import Foundation
import CommonCrypto
import CryptoKit

// RAR 5.0 reader (decompression only). Written from the public RAR 5.0 format description.
// ArchiveX never creates RAR files: RARLAB's license reserves the compression algorithm.


// MARK: - Bit reader (MSB first)

final class RBits {
    private let src: ByteSource
    private var buf = [UInt8]()
    private var ip = 0
    private var bits: UInt64 = 0
    private var n = 0
    private var eof = false
    private(set) var consumed: UInt64 = 0

    init(_ s: ByteSource) { src = s }
    /// Bits left in the register (used to hand the stream back to byte-wise readers).
    var bitsInRegister: Int { n }

    @inline(__always) func refill() throws {
        while n <= 56 {
            if ip == buf.count {
                if eof { return }
                let d = try src.read(1 << 16)
                if d.isEmpty { eof = true; return }
                buf = [UInt8](d); ip = 0
            }
            bits |= UInt64(buf[ip]) << UInt64(56 - n); ip += 1; n += 8
        }
    }
    @inline(__always) func peek(_ k: Int) -> Int { Int(bits >> UInt64(64 - k)) }
    @inline(__always) func skip(_ k: Int) { bits <<= UInt64(k); n -= k; consumed &+= UInt64(k) }
    @inline(__always) func take(_ k: Int) throws -> Int {
        if k == 0 { return 0 }
        try refill()
        let v = peek(k); skip(k); return v
    }
    /// True once more bits were consumed than the input could supply.
    var overrun: Bool { n < 0 }
}

struct RHuff {
    var table = [UInt16](repeating: 0, count: 1 << 15)
    var used = false

    init() {}
    init(lengths: ArraySlice<UInt8>) throws {
        var counts = [Int](repeating: 0, count: 16)
        for l in lengths { counts[Int(l)] += 1 }
        counts[0] = 0
        var next = [Int](repeating: 0, count: 17)
        var code = 0
        for l in 1...15 { code = (code + counts[l - 1]) << 1; next[l] = code }
        for (sym, l) in lengths.enumerated() where l > 0 {
            let len = Int(l)
            let c = next[len]; next[len] += 1
            guard c < (1 << len) else { throw AXError.corrupt("invalid RAR Huffman table") }
            let start = c << (15 - len), end = (c + 1) << (15 - len)
            let entry = UInt16(sym << 4 | len)
            for i in start..<end { table[i] = entry }
        }
        used = true
    }
}

// MARK: - Decoder

final class Rar5Decoder {
    private var win: UnsafeMutablePointer<UInt8>
    private let winSize: Int
    private let mask: Int
    private var wpos = 0
    private var valid: UInt64 = 0
    private var old = [0, 0, 0, 0]
    private var lastLen = 0
    private var main = RHuff(), dist = RHuff(), low = RHuff(), len = RHuff()
    private var haveTables = false

    private var br: RBits!
    private var out = [UInt8]()
    private var outHead = 0
    private var outBase: UInt64 = 0
    private var produced: UInt64 = 0
    private var sink: ByteSink!
    private var progress: ProgressTracker?
    private struct Filter { var type: Int; var start: UInt64; var length: Int; var channels: Int }
    private var filters = [Filter]()

    init(windowSize requested: Int) {
        var w = 1 << 17
        while w < requested && w < 1 << 31 { w <<= 1 }
        winSize = w; mask = w - 1
        win = UnsafeMutablePointer<UInt8>.allocate(capacity: w)
        win.initialize(repeating: 0, count: 1)
    }
    deinit { win.deallocate() }

    // MARK: file entry point

    /// Decodes one file's data. `size` is the unpacked size (nil when unknown).
    func decode(input: ByteSource, size: UInt64?, solid: Bool, sink: ByteSink, progress: ProgressTracker?) throws {
        if !solid { wpos = 0; valid = 0; old = [0, 0, 0, 0]; lastLen = 0; haveTables = false }
        br = RBits(input); self.sink = sink; self.progress = progress
        out.removeAll(keepingCapacity: true); outHead = 0; outBase = 0; produced = 0; filters = []
        var last = false
        while !last {
            try br.refill()
            let flags = try br.take(8), check = try br.take(8)
            let bc = ((flags >> 3) & 3) + 1
            guard bc <= 3 else { throw AXError.corrupt("bad RAR block header") }
            var bs = 0
            for i in 0..<bc { bs |= try br.take(8) << (8 * i) }
            guard check == (0x5a ^ flags ^ (bs & 0xff) ^ ((bs >> 8) & 0xff) ^ ((bs >> 16) & 0xff)), bs >= 1 else {
                throw AXError.corrupt("RAR block header checksum mismatch")
            }
            let bitSize = (flags & 7) + 1
            last = flags & 0x40 != 0
            let end = br.consumed + UInt64((bs - 1) * 8 + bitSize)
            if flags & 0x80 != 0 { try readTables() } else { guard haveTables else { throw AXError.corrupt("RAR data without Huffman tables") } }
            try decodeBlock(until: end)
            guard br.consumed == end, !br.overrun else { throw AXError.corrupt("RAR block overran its size") }
            try br.refill(); br.skip(8 - bitSize)
            try flush(final: false)
            if let s = size, produced > s { throw AXError.corrupt("RAR data longer than the file") }
        }
        try flush(final: true)
        if let s = size, produced != s { throw AXError.corrupt("RAR data shorter than the file") }
        br = nil
    }

    // MARK: tables

    private func readTables() throws {
        var bl = [UInt8](repeating: 0, count: 20)
        var i = 0
        while i < 20 {
            let l = try br.take(4)
            if l == 15 {
                var z = try br.take(4)
                if z == 0 { bl[i] = 15; i += 1 }
                else { z += 2; while z > 0 && i < 20 { bl[i] = 0; i += 1; z -= 1 } }
            } else { bl[i] = UInt8(l); i += 1 }
        }
        let bd = try RHuff(lengths: bl[...])
        let total = 306 + 64 + 16 + 44
        var lens = [UInt8](repeating: 0, count: total)
        i = 0
        while i < total {
            try br.refill()
            let sym = try decode(bd)
            if sym < 16 { lens[i] = UInt8(sym); i += 1; continue }
            var count: Int
            if sym < 18 {
                guard i > 0 else { throw AXError.corrupt("bad RAR table repeat") }
                count = sym == 16 ? try br.take(3) + 3 : try br.take(7) + 11
                let v = lens[i - 1]
                while count > 0 && i < total { lens[i] = v; i += 1; count -= 1 }
            } else {
                count = sym == 18 ? try br.take(3) + 3 : try br.take(7) + 11
                while count > 0 && i < total { lens[i] = 0; i += 1; count -= 1 }
            }
        }
        main = try RHuff(lengths: lens[0..<306])
        dist = try RHuff(lengths: lens[306..<370])
        low = try RHuff(lengths: lens[370..<386])
        len = try RHuff(lengths: lens[386..<430])
        haveTables = true
    }

    @inline(__always) private func decode(_ t: RHuff) throws -> Int {
        try br.refill()
        let e = t.table[br.peek(15)]
        let l = Int(e & 15)
        guard l > 0 else { throw AXError.corrupt("invalid RAR Huffman code") }
        br.skip(l)
        return Int(e >> 4)
    }

    // MARK: symbols

    @inline(__always) private func put(_ b: UInt8) {
        win[wpos] = b; wpos = (wpos + 1) & mask; valid &+= 1
        out.append(b); produced &+= 1
    }

    private func copy(_ length: Int, _ d: Int) throws {
        guard d >= 1, UInt64(d) <= valid, d <= winSize else { throw AXError.corrupt("RAR distance out of range") }
        var s = (wpos - d) & mask
        for _ in 0..<length { let b = win[s]; s = (s + 1) & mask; put(b) }
    }

    private func slotToLength(_ slot: Int) throws -> Int {
        var lbits = 0, length: Int
        if slot < 8 { length = 2 + slot } else { lbits = slot / 4 - 1; length = 2 + ((4 | (slot & 3)) << lbits) }
        if lbits > 0 { length += try br.take(lbits) }
        return length
    }

    private func readFilterData() throws -> Int {
        let byteCount = try br.take(2) + 1
        var v = 0
        for i in 0..<byteCount { v += try br.take(8) << (8 * i) }
        return v
    }

    private func decodeBlock(until end: UInt64) throws {
        while br.consumed < end {
            let sym = try decode(main)
            if sym < 256 { put(UInt8(sym)) }
            else if sym >= 262 {
                var length = try slotToLength(sym - 262)
                let slot = try decode(dist)
                var d: Int
                if slot < 4 { d = 1 + slot }
                else {
                    let dbits = slot / 2 - 1
                    d = 1 + ((2 | (slot & 1)) << dbits)
                    if dbits >= 4 {
                        if dbits > 4 { d += try br.take(dbits - 4) << 4 }
                        d += try decode(low)
                    } else { d += try br.take(dbits) }
                }
                if d > 0x100 { length += 1; if d > 0x2000 { length += 1; if d > 0x40000 { length += 1 } } }
                old[3] = old[2]; old[2] = old[1]; old[1] = old[0]; old[0] = d
                lastLen = length
                try copy(length, d)
            } else if sym == 256 {
                let start = try readFilterData()
                var length = try readFilterData()
                if length > 0x40_0000 { length = 0 }
                let type = try br.take(3)
                var channels = 0
                if type == 0 { channels = try br.take(5) + 1 }
                if length > 0 { filters.append(Filter(type: type, start: produced + UInt64(start), length: length, channels: channels)) }
            } else if sym == 257 {
                if lastLen != 0 { try copy(lastLen, old[0]) }
            } else {
                let idx = sym - 258
                let d = old[idx]
                var k = idx; while k > 0 { old[k] = old[k - 1]; k -= 1 }
                old[0] = d
                let length = try slotToLength(try decode(len))
                lastLen = length
                try copy(length, d)
            }
            if out.count - outHead >= 1 << 20 { try flush(final: false) }
        }
    }

    // MARK: output and filters

    private func emit(_ n: Int) throws {
        guard n > 0 else { return }
        try sink.write(Data(out[outHead..<outHead + n]))
        try progress?.add(n)
        outHead += n; outBase &+= UInt64(n)
        if outHead > 1 << 22 { out.removeFirst(outHead); outHead = 0 }
    }

    private func flush(final: Bool) throws {
        while true {
            let pending = out.count - outHead
            guard let f = filters.first else { try emit(pending); return }
            guard f.start >= outBase else { throw AXError.corrupt("RAR filter out of order") }
            let ahead = Int(f.start - outBase)
            if ahead > 0 {
                try emit(min(ahead, pending))
                if ahead > pending { return }
                continue
            }
            if f.length <= pending {
                apply(f, at: outHead)
                try emit(f.length)
                filters.removeFirst()
                continue
            }
            if final { throw AXError.corrupt("RAR filter extends past the end of the data") }
            return
        }
    }

    private func apply(_ f: Filter, at base: Int) {
        let n = f.length
        switch f.type {
        case 0:                                                       // delta
            let ch = max(1, f.channels)
            let src = Array(out[base..<base + n])
            var s = 0
            for c in 0..<ch {
                var prev: UInt8 = 0
                var d = c
                while d < n { prev = prev &- src[s]; s += 1; out[base + d] = prev; d += ch }
            }
        case 1, 2:                                                    // x86 CALL (and JMP) address conversion
            let cmp: UInt8 = f.type == 2 ? 0xe9 : 0xe8
            let fileSize: UInt32 = 0x100_0000
            var cur = 0
            while cur + 4 < n {
                let b = out[base + cur]; cur += 1
                if b == 0xe8 || b == cmp {
                    let offset = UInt32(truncatingIfNeeded: (UInt64(cur) &+ f.start) % UInt64(fileSize))
                    let p = base + cur
                    let addr = UInt32(out[p]) | UInt32(out[p + 1]) << 8 | UInt32(out[p + 2]) << 16 | UInt32(out[p + 3]) << 24
                    var nv: UInt32?
                    if addr & 0x8000_0000 != 0 { if (addr &+ offset) & 0x8000_0000 == 0 { nv = addr &+ fileSize } }
                    else if (addr &- fileSize) & 0x8000_0000 != 0 { nv = addr &- offset }
                    if let v = nv { out[p] = UInt8(truncatingIfNeeded: v); out[p + 1] = UInt8(truncatingIfNeeded: v >> 8); out[p + 2] = UInt8(truncatingIfNeeded: v >> 16); out[p + 3] = UInt8(truncatingIfNeeded: v >> 24) }
                    cur += 4
                }
            }
        case 3:                                                       // ARM branch
            var cur = 0
            while cur + 3 < n {
                if out[base + cur + 3] == 0xeb {
                    var off = UInt32(out[base + cur]) | UInt32(out[base + cur + 1]) << 8 | UInt32(out[base + cur + 2]) << 16
                    off = off &- UInt32(truncatingIfNeeded: (f.start &+ UInt64(cur)) / 4)
                    out[base + cur] = UInt8(truncatingIfNeeded: off); out[base + cur + 1] = UInt8(truncatingIfNeeded: off >> 8); out[base + cur + 2] = UInt8(truncatingIfNeeded: off >> 16)
                }
                cur += 4
            }
        default: break
        }
    }
}

// MARK: - AES-256-CBC for RAR

final class RarAESSource: ByteSource {
    private let input: ByteSource
    private var cryptor: CCCryptorRef?
    private var carry = Data()
    private var out = Data(); private var outPos = 0
    private var done = false

    init(input: ByteSource, key: Data, iv: Data, keyLength: Int = 32) throws {
        self.input = input
        let st = key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
            CCCryptorCreate(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, keyLength, v.baseAddress, &cryptor)
        } }
        guard st == kCCSuccess else { throw AXError.io("Could not start AES.") }
    }
    deinit { if let c = cryptor { CCCryptorRelease(c) } }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && !done {
            let fresh = try input.read(1 << 16)
            if fresh.isEmpty { done = true; break }
            var chunk = carry + fresh
            let usable = chunk.count - chunk.count % 16
            carry = chunk.suffix(chunk.count - usable); chunk = chunk.prefix(usable)
            guard usable > 0 else { continue }
            var plain = Data(count: usable); var moved = 0
            let st = chunk.withUnsafeBytes { i in plain.withUnsafeMutableBytes { o in CCCryptorUpdate(cryptor, i.baseAddress, usable, o.baseAddress, usable, &moved) } }
            guard st == kCCSuccess else { throw AXError.io("AES failure.") }
            out.append(plain)
        }
        let take = min(n, out.count - outPos)
        let d = out.subdata(in: out.startIndex + outPos..<out.startIndex + outPos + take); outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

/// Reads at most `limit` bytes of a source (the unpacked size of a stored, padded, encrypted file).
final class LimitSource: ByteSource {
    private let input: ByteSource
    private var left: UInt64
    init(_ i: ByteSource, limit: UInt64) { input = i; left = limit }
    func read(_ n: Int) throws -> Data {
        guard left > 0 else { return Data() }
        let d = try input.read(Int(min(UInt64(n), left))); left -= UInt64(d.count); return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

// MARK: - Archive

struct RarEnc {
    var log2: Int
    var salt: Data
    var iv: Data
    var check: Data?
    var useMAC: Bool
    var v3 = false                // RAR 3/4: AES-128, SHA-1 key derivation, no password check value
}

struct RarPart {
    var file: FileIn
    var offset: UInt64
    var length: UInt64
}

struct RarEntry {
    var name = ""
    var isDir = false
    var size: UInt64?
    var packSize: UInt64 = 0
    var crc: UInt32?
    var mtime: Date?
    var attrib: UInt64 = 0
    var hostOS = 0
    var method = 0
    var dictShift = 0
    var solid = false
    var dataOffset: UInt64 = 0
    var enc: RarEnc?
    var link: (type: Int, target: String)?
    var unpVer = 50               // 50 = RAR 5; otherwise the RAR 1.x–4.x "unpack version" (29 = RAR 3/4)
    var parts: [RarPart] = []     // RAR 3/4: where the packed data lives (several parts for multi-volume archives)
    var dataLink = false          // RAR 3/4 symbolic link: the target is the (packed) file data
    var incomplete = false        // a following volume is missing
    var unixMode: UInt32? { hostOS == 1 ? UInt32(truncatingIfNeeded: attrib) : nil }
}

final class RarArchive {
    static let signature5: [UInt8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]
    static let signature4: [UInt8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]

    var file: FileIn
    var entries: [RarEntry] = []
    var isSolid = false
    var headersEncrypted = false
    var generation = 5            // 5 = RAR 5 format, 4 = RAR 1.5–4.x format
    var volumeCount = 1
    var newNumbering = false
    let password: String?
    private var keyCache: [String: (key: Data, hashKey: Data, check: Data)] = [:]
    var keyCache3: [String: (key: Data, iv: Data)] = [:]

    static func isRar5(_ url: URL) -> Bool {
        guard let f = try? FileIn(url), let h = try? f.read(at: 0, 8) else { return false }
        return Array(h) == signature5
    }

    init(url: URL, password: String?) throws {
        file = try FileIn(url)
        self.password = password
        try parse()
    }

    // MARK: key derivation

    private func derive(salt: Data, log2: Int) throws -> (key: Data, hashKey: Data, check: Data) {
        let id = salt.base64EncodedString() + "/\(log2)"
        if let c = keyCache[id] { return c }
        guard let pw = password, !pw.isEmpty else { throw AXError.passwordRequired }
        guard log2 <= 24 else { throw AXError.unsupported("RAR key derivation strength \(log2)") }
        let pwb = Array(pw.utf8)
        func pbkdf(_ rounds: UInt32) throws -> Data {
            var out = [UInt8](repeating: 0, count: 32)
            let st = salt.withUnsafeBytes { s in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pwb.map { Int8(bitPattern: $0) }, pwb.count,
                                     s.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds, &out, 32)
            }
            guard st == kCCSuccess else { throw AXError.io("Key derivation failed.") }
            return Data(out)
        }
        let n = UInt32(1) << UInt32(log2)
        let r = (try pbkdf(n), try pbkdf(n + 16), try pbkdf(n + 32))
        keyCache[id] = r
        return r
    }

    private func verifyPassword(_ e: RarEnc, _ keys: (key: Data, hashKey: Data, check: Data)) throws {
        guard let stored = e.check, stored.count >= 8 else { return }
        var fold = [UInt8](repeating: 0, count: 8)
        for (i, b) in keys.check.enumerated() { fold[i % 8] ^= b }
        guard Data(fold) == stored.prefix(8) else { throw AXError.wrongPassword }
    }

    private func parseEnc(_ r: inout RarVint, extra: Bool) throws -> RarEnc {
        _ = try r.vint()                                  // version
        let flags = Int(try r.vint())
        let log2 = Int(try r.byte())
        let salt = try r.bytes(16)
        let iv = extra ? try r.bytes(16) : Data(count: 16)
        let check = flags & 1 != 0 ? try r.bytes(12) : nil
        return RarEnc(log2: log2, salt: salt, iv: iv, check: check, useMAC: flags & 2 != 0)
    }

    // MARK: parsing

    private func parse() throws {
        let head = try file.read(at: 0, 8)
        if Array(head.prefix(7)) == RarArchive.signature4 { generation = 4; try parse4(); return }
        guard Array(head) == RarArchive.signature5 else { throw AXError.corrupt("not a RAR 5 archive") }
        var pos: UInt64 = 8
        var headerKey: Data?
        while pos + 7 <= file.size {
            var h: Data
            var next: UInt64
            if let key = headerKey {
                let iv = try file.readExactly(at: pos, 16)
                let first = try file.readExactly(at: pos + 16, 16)
                // decrypt the first block to learn the size, then the rest, all in one CBC chain
                var cryptor: CCCryptorRef?
                let st = key.withUnsafeBytes { k in iv.withUnsafeBytes { v in CCCryptorCreate(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, 32, v.baseAddress, &cryptor) } }
                guard st == kCCSuccess else { throw AXError.io("Could not start AES.") }
                defer { CCCryptorRelease(cryptor) }
                func dec(_ d: Data) throws -> Data {
                    var o = Data(count: d.count); var m = 0
                    let s = d.withUnsafeBytes { i in o.withUnsafeMutableBytes { p in CCCryptorUpdate(cryptor, i.baseAddress, d.count, p.baseAddress, d.count, &m) } }
                    guard s == kCCSuccess else { throw AXError.io("AES failure.") }
                    return o
                }
                var plain = try dec(first)
                var r = RarVint(plain); r.p = 4
                let hs = Int(try r.vint())
                let total = r.p + hs
                let enc = (total + 15) / 16 * 16
                guard hs < 1 << 21, pos + 16 + UInt64(enc) <= file.size else { throw AXError.wrongPassword }
                if enc > 16 { plain.append(try dec(try file.readExactly(at: pos + 32, enc - 16))) }
                h = plain.prefix(total)
                next = pos + 16 + UInt64(enc)
                guard CRC32.update(0, h.suffix(from: h.startIndex + 4)) == h.le32(0) else { throw AXError.wrongPassword }
            } else {
                let probe = try file.read(at: pos, 16)
                guard probe.count >= 8 else { break }
                var r = RarVint(probe); r.p = 4
                let hs = Int(try r.vint())
                let total = r.p + hs
                guard hs > 0, hs < 1 << 21, pos + UInt64(total) <= file.size else { throw AXError.corrupt("truncated RAR header") }
                h = try file.readExactly(at: pos, total)
                next = pos + UInt64(total)
                guard CRC32.update(0, h.suffix(from: h.startIndex + 4)) == h.le32(0) else { throw AXError.corrupt("RAR header CRC mismatch") }
            }

            var r = RarVint(h); r.p = 4
            let hsize = Int(try r.vint())
            let bodyEnd = r.p + hsize
            let type = Int(try r.vint())
            let flags = try r.vint()
            let extraSize = flags & 1 != 0 ? Int(try r.vint()) : 0
            let dataSize = flags & 2 != 0 ? try r.vint() : 0
            let dataOffset = next

            switch type {
            case 1:                                                    // main header
                let af = try r.vint()
                isSolid = af & 4 != 0
                if af & 1 != 0 { throw AXError.unsupported("multi-volume RAR archives") }
            case 4:                                                    // archive encryption header
                let e = try parseEnc(&r, extra: false)
                let keys = try derive(salt: e.salt, log2: e.log2)
                try verifyPassword(e, keys)
                headerKey = keys.key; headersEncrypted = true
            case 2, 3:
                var ent = RarEntry()
                let ff = try r.vint()
                ent.isDir = ff & 1 != 0
                let unp = try r.vint()
                ent.size = ff & 8 != 0 ? nil : unp
                ent.attrib = try r.vint()
                if ff & 2 != 0 { ent.mtime = Date(timeIntervalSince1970: TimeInterval(try r.u32())) }
                if ff & 4 != 0 { ent.crc = try r.u32() }
                let ci = try r.vint()
                guard ci & 0x3f <= 1 else { throw AXError.unsupported("RAR compression version \(ci & 0x3f)") }
                ent.solid = ci & 0x40 != 0
                ent.method = Int((ci >> 7) & 7)
                ent.dictShift = Int((ci >> 10) & 0x1f)
                ent.hostOS = Int(try r.vint())
                let nl = Int(try r.vint())
                ent.name = String(decoding: try r.bytes(nl), as: UTF8.self)
                ent.packSize = dataSize
                ent.dataOffset = dataOffset
                guard dataOffset + dataSize <= file.size else { throw AXError.corrupt("RAR archive is truncated (data of “\(ent.name)” is incomplete)") }
                // extra records
                var ex = RarVint(h); ex.p = bodyEnd - extraSize
                while ex.p < bodyEnd {
                    let sz = Int(try ex.vint()); let start = ex.p
                    let t = Int(try ex.vint())
                    switch t {
                    case 1: ent.enc = try parseEnc(&ex, extra: true)
                    case 3:
                        let tf = try ex.vint()
                        if tf & 2 != 0 {
                            if tf & 1 != 0 { ent.mtime = Date(timeIntervalSince1970: TimeInterval(try ex.u32())) }
                            else { ent.mtime = Date(timeIntervalSince1970: Double(try ex.u64()) / 10_000_000 - 11_644_473_600) }
                        }
                    case 5:
                        let rt = Int(try ex.vint()); _ = try ex.vint()
                        let ln = Int(try ex.vint())
                        ent.link = (rt, String(decoding: try ex.bytes(ln), as: UTF8.self))
                    default: break
                    }
                    ex.p = start + sz
                }
                if type == 2 { entries.append(ent) }
            case 5:
                pos = file.size; continue
            default: break
            }
            pos = next + dataSize
            if flags & 4 == 0 && type > 5 { /* unknown required block: ignore */ }
        }
    }

    // MARK: public API

    var listing: Listing {
        var l = Listing()
        l.solid = isSolid
        l.headerEncrypted = headersEncrypted
        l.details = (["RAR \(generation)"] + (isSolid ? ["solid"] : []) + (volumeCount > 1 ? ["\(volumeCount) volumes"] : []) + (entries.contains { $0.enc != nil } || headersEncrypted ? [generation == 4 ? "AES-128" : "AES-256"] : []) + (headersEncrypted ? ["encrypted names"] : [])).joined(separator: " · ")
        l.entries = entries.map { e in
            let size = Int64(e.size ?? 0)
            let clean = SafePath.clean(e.name) ?? e.name
            return ArchiveEntry(path: clean, isDir: e.isDir, size: size, packed: Int64(e.packSize),
                                ratio: (!e.isDir && size > 0) ? "\(min(100, Int(Double(e.packSize) / Double(size) * 100)))%" : "",
                                mtime: Dates.text(e.mtime), crc: e.crc.map { String(format: "%08X", $0) } ?? "", attrs: "", encrypted: e.enc != nil)
        }
        return l
    }

    private var decoder: Rar5Decoder?
    private var decoder4: Rar4Decoder?

    private func decoder4For() -> Rar4Decoder {
        if let d = decoder4 { return d }
        let d = Rar4Decoder(); decoder4 = d; return d
    }

    private func decoderFor() -> Rar5Decoder {
        if let d = decoder { return d }
        let maxShift = entries.map { $0.dictShift }.max() ?? 0
        let dict = 1 << (17 + min(maxShift, 14))
        let total = entries.reduce(UInt64(0)) { $0 + ($1.size ?? 0) }
        let unknown = entries.contains { $0.size == nil && !$0.isDir }
        let biggest = entries.compactMap { $0.size }.max() ?? 0
        let want = unknown ? dict : (isSolid ? Int(min(UInt64(dict), max(total, 1 << 17))) : Int(min(UInt64(dict), max(biggest, 1 << 17))))
        let d = Rar5Decoder(windowSize: want)
        decoder = d
        return d
    }

    private func source(for e: RarEntry) throws -> (ByteSource, Data?) {
        var s: ByteSource
        if e.parts.isEmpty { s = RangeSource(file: file, offset: e.dataOffset, length: e.packSize) }
        else {
            if e.incomplete { throw AXError.corrupt("The next volume of this archive is missing, so “\(e.name)” can’t be read.") }
            s = ConcatSource(e.parts.map { RangeSource(file: $0.file, offset: $0.offset, length: $0.length) })
        }
        var hashKey: Data?
        if let enc = e.enc, enc.v3 {
            let k = try derive3(salt: enc.salt)
            s = try RarAESSource(input: s, key: k.key, iv: k.iv, keyLength: 16)
        } else if let enc = e.enc {
            let keys = try derive(salt: enc.salt, log2: enc.log2)
            try verifyPassword(enc, keys)
            s = try RarAESSource(input: s, key: keys.key, iv: enc.iv)
            if enc.useMAC { hashKey = keys.hashKey }
        }
        return (s, hashKey)
    }

    private func macCRC(_ crc: UInt32, key: Data) -> UInt32 {
        var raw = Data(); raw.put32(crc)
        let d = Array(HMAC<SHA256>.authenticationCode(for: raw, using: SymmetricKey(data: key)))
        var v: UInt32 = 0
        for (i, b) in d.enumerated() { v ^= UInt32(b) << UInt32((i & 3) * 8) }
        return v
    }

    /// Decodes one entry's data into `sink`, verifying its checksum.
    private func extractData(_ e: RarEntry, to sink: ByteSink, progress: ProgressTracker?) throws {
        if e.size == 0 {
            // Nothing to write or checksum. But an empty file inside a solid RAR 3/4 stream still carries the stream's
            // end-of-block marker, which tells the decoder whether the next file starts with new tables.
            guard e.unpVer < 50, e.unpVer >= 29, e.method != 0, e.packSize > 0, e.solid, !e.incomplete else { return }
            let (src, _) = try source(for: e)
            try decoder4For().decode(input: src, size: 0, solid: true, sink: NullSink(), progress: nil)
            return
        }
        let (src, hashKey) = try source(for: e)
        let crcSink = CRCSink(out: sink)
        do {
            if e.method == 0 {
                let s: ByteSource = e.enc != nil ? LimitSource(src, limit: e.size ?? e.packSize) : src
                var left = e.size ?? e.packSize
                while left > 0 {
                    let d = try s.read(Int(min(left, 1 << 20)))
                    if d.isEmpty { throw AXError.corrupt("“\(e.name)” ended unexpectedly") }
                    left -= UInt64(d.count); try crcSink.write(d); try progress?.add(d.count)
                }
            } else if e.unpVer < 50 {
                try decoder4For().decode(input: src, size: e.size, solid: e.solid, sink: crcSink, progress: progress)
            } else {
                try decoderFor().decode(input: src, size: e.size, solid: e.solid, sink: crcSink, progress: progress)
            }
        } catch let err as AXError {
            if e.enc != nil { switch err { case .corrupt, .unsupported: throw AXError.wrongPassword; default: break } }
            throw err
        }
        if let want = e.crc {
            let got = hashKey.map { macCRC(crcSink.crc, key: $0) } ?? crcSink.crc
            guard got == want else { throw e.enc != nil ? AXError.wrongPassword : AXError.corrupt("CRC mismatch in “\(e.name)”") }
        }
    }

    func extract(to ex: Extractor, progress: ProgressTracker?) throws {
        var written: [String: URL] = [:]
        for e in entries {
            try Task.checkCancellation()
            guard let clean = SafePath.clean(e.name) else { if !e.name.isEmpty { _ = try ex.destination(for: e.name, isDir: e.isDir) }; continue }
            let wanted = ex.isSelected(clean)
            if e.isDir {
                if wanted, ex.keepPaths, let u = try ex.destination(for: e.name, isDir: true) {
                    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true); ex.finalize(u, mode: e.unixMode, mtime: e.mtime)
                }
                continue
            }
            if e.dataLink {
                if wanted {
                    let mem = MemorySink()
                    try extractData(e, to: mem, progress: nil)
                    if let u = try ex.destination(for: e.name, isDir: false) { ex.makeSymlink(at: u, target: String(decoding: mem.data, as: UTF8.self)) }
                } else if e.solid || isSolid { try extractData(e, to: NullSink(), progress: nil) }
                continue
            }
            if let l = e.link {
                if wanted, l.type == 1 || l.type == 2, let u = try ex.destination(for: e.name, isDir: false) { ex.makeSymlink(at: u, target: l.target) }
                else if wanted, l.type >= 4, let src = SafePath.clean(l.target).flatMap({ written[$0] }), let u = try ex.destination(for: e.name, isDir: false) {
                    try? FileManager.default.copyItem(at: src, to: u)
                }
                continue
            }
            if !wanted {
                if e.solid || isSolid { try extractData(e, to: NullSink(), progress: nil) }      // must keep the dictionary in step
                continue
            }
            guard let u = try ex.destination(for: e.name, isDir: false) else {
                if e.solid || isSolid { try extractData(e, to: NullSink(), progress: nil) }
                continue
            }
            let out = try FileOut(u)
            do { try extractData(e, to: out, progress: progress) } catch { try? FileManager.default.removeItem(at: u); throw error }
            ex.finalize(u, mode: e.unixMode, mtime: e.mtime)
            written[clean] = u
        }
    }

    func test(progress: ProgressTracker?) throws {
        for e in entries where !e.isDir && e.link == nil && !e.dataLink {
            try Task.checkCancellation()
            try extractData(e, to: NullSink(), progress: progress)
        }
    }
}

// MARK: - RAR variable-length integers

struct RarVint {
    let d: Data
    var p = 0
    init(_ d: Data) { self.d = d }
    mutating func byte() throws -> UInt8 {
        guard p < d.count else { throw AXError.corrupt("truncated RAR header") }
        defer { p += 1 }
        return d[d.startIndex + p]
    }
    mutating func vint() throws -> UInt64 {
        var v: UInt64 = 0, shift: UInt64 = 0
        while true {
            let b = try byte()
            v |= UInt64(b & 0x7f) << shift
            if b & 0x80 == 0 { return v }
            shift += 7
            guard shift < 64 else { throw AXError.corrupt("bad RAR number") }
        }
    }
    mutating func bytes(_ n: Int) throws -> Data {
        guard n >= 0, p + n <= d.count else { throw AXError.corrupt("truncated RAR header") }
        defer { p += n }
        return d.subdata(in: d.startIndex + p..<d.startIndex + p + n)
    }
    mutating func u32() throws -> UInt32 { try bytes(4).le32(0) }
    mutating func u64() throws -> UInt64 { try bytes(8).le64(0) }
}
