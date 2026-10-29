import Foundation
import CommonCrypto

// RAR 1.5–4.x ("RAR 3") reader: block headers, multi-volume sets, AES-128 and the version 29 decompressor
// (Huffman/LZ, PPMd variant H, and the six standard filters). Written from the public format descriptions.
// ArchiveX never creates RAR files: RARLAB's license reserves the compression algorithm.

// MARK: - Helpers

/// Reads several sources one after the other (the packed data of a file that spans volumes).
final class ConcatSource: ByteSource {
    private let parts: [ByteSource]
    private var i = 0
    init(_ p: [ByteSource]) { parts = p }
    func read(_ n: Int) throws -> Data {
        while i < parts.count {
            let d = try parts[i].read(n)
            if !d.isEmpty { return d }
            i += 1
        }
        return Data()
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

/// SHA-1 with access to the internal state words (RAR 3 derives its key from them).
struct RarSha1 {
    private(set) var h: [UInt32] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0]
    private var buf = [UInt8]()
    private var total: UInt64 = 0
    private var w = [UInt32](repeating: 0, count: 80)

    mutating func update(_ bytes: [UInt8]) {
        total &+= UInt64(bytes.count)
        absorb(bytes)
    }

    private mutating func absorb(_ bytes: [UInt8]) {
        buf.append(contentsOf: bytes)
        guard buf.count >= 64 else { return }
        let full = buf.count / 64 * 64
        let chunk = Array(buf[0..<full])
        buf.removeFirst(full)
        chunk.withUnsafeBufferPointer { p in
            var o = 0
            while o < full { block(p.baseAddress! + o); o += 64 }
        }
    }

    /// State words after padding, without disturbing this hash (it can keep being updated).
    func finalState() -> [UInt32] {
        var c = self
        var pad: [UInt8] = [0x80]
        while (c.buf.count + pad.count) % 64 != 56 { pad.append(0) }
        let bits = total &* 8
        for i in (0..<8).reversed() { pad.append(UInt8(truncatingIfNeeded: bits >> UInt64(8 * i))) }
        c.absorb(pad)
        return c.h
    }

    private mutating func block(_ p: UnsafePointer<UInt8>) {
        for t in 0..<16 { w[t] = UInt32(p[4 * t]) << 24 | UInt32(p[4 * t + 1]) << 16 | UInt32(p[4 * t + 2]) << 8 | UInt32(p[4 * t + 3]) }
        for t in 16..<80 { let x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]; w[t] = (x << 1) | (x >> 31) }
        var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4]
        for t in 0..<80 {
            let f: UInt32, k: UInt32
            switch t {
            case 0..<20: f = (b & c) | (~b & d); k = 0x5A82_7999
            case 20..<40: f = b ^ c ^ d; k = 0x6ED9_EBA1
            case 40..<60: f = (b & c) | (b & d) | (c & d); k = 0x8F1B_BCDC
            default: f = b ^ c ^ d; k = 0xCA62_C1D6
            }
            let tmp = ((a << 5) | (a >> 27)) &+ f &+ e &+ k &+ w[t]
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = tmp
        }
        h[0] &+= a; h[1] &+= b; h[2] &+= c; h[3] &+= d; h[4] &+= e
    }
}

/// AES-CBC decryption of a whole buffer (no padding handling; RAR pads with zeros).
private func aesCBCDecrypt(key: Data, iv: Data, _ data: [UInt8]) throws -> [UInt8] {
    var out = [UInt8](repeating: 0, count: data.count)
    var moved = 0
    let st = key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, key.count, v.baseAddress, data, data.count, &out, out.count, &moved)
    } }
    guard st == kCCSuccess else { throw AXError.io("AES failure.") }
    return out
}

@inline(__always) private func u16(_ d: [UInt8], _ o: Int) -> Int { Int(d[o]) | Int(d[o + 1]) << 8 }
@inline(__always) private func u32(_ d: [UInt8], _ o: Int) -> UInt32 {
    UInt32(d[o]) | UInt32(d[o + 1]) << 8 | UInt32(d[o + 2]) << 16 | UInt32(d[o + 3]) << 24
}

// MARK: - Archive parsing (RAR 1.5–4.x)

extension RarArchive {
    /// Key and IV from the password and an 8-byte salt: SHA-1 over password (UTF-16LE), salt and a counter, 0x40000 times.
    func derive3(salt: Data) throws -> (key: Data, iv: Data) {
        let id = salt.base64EncodedString()
        if let c = keyCache3[id] { return c }
        guard let pw = password, !pw.isEmpty else { throw AXError.passwordRequired }
        var raw = [UInt8]()
        for u in pw.utf16.prefix(128) { raw.append(UInt8(u & 0xff)); raw.append(UInt8(u >> 8)) }
        raw.append(contentsOf: salt)
        var sha = RarSha1()
        var iv = [UInt8](repeating: 0, count: 16)
        for i in 0..<0x40000 {
            sha.update(raw)
            sha.update([UInt8(i & 0xff), UInt8((i >> 8) & 0xff), UInt8((i >> 16) & 0xff)])
            if i % 0x4000 == 0 { iv[i / 0x4000] = UInt8(truncatingIfNeeded: sha.finalState()[4]) }
        }
        let st = sha.finalState()
        var key = [UInt8](repeating: 0, count: 16)
        for i in 0..<4 { for j in 0..<4 { key[i * 4 + j] = UInt8(truncatingIfNeeded: st[i] >> UInt32(8 * j)) } }
        let r = (key: Data(key), iv: Data(iv))
        keyCache3[id] = r
        return r
    }

    // MARK: volume names

    private static func volumeMatch(_ name: String) -> (prefix: String, number: Int, width: Int, suffix: String)? {
        guard let re = try? NSRegularExpression(pattern: #"^(.*\.part)(\d+)(\.rar)$"#, options: [.caseInsensitive]) else { return nil }
        let ns = name as NSString
        guard let m = re.firstMatch(in: name, range: NSRange(location: 0, length: ns.length)) else { return nil }
        let digits = ns.substring(with: m.range(at: 2))
        return (ns.substring(with: m.range(at: 1)), Int(digits) ?? 0, digits.count, ns.substring(with: m.range(at: 3)))
    }

    static func nextVolumeURL(_ url: URL, newNumbering: Bool) -> URL? {
        let name = url.lastPathComponent
        let dir = url.deletingLastPathComponent()
        if let v = volumeMatch(name) {
            return dir.appendingPathComponent(v.prefix + String(format: "%0*d", v.width, v.number + 1) + v.suffix)
        }
        let ext = url.pathExtension
        let base = (name as NSString).deletingPathExtension
        if ext.lowercased() == "rar" { return dir.appendingPathComponent(base + "." + (ext == "RAR" ? "R00" : "r00")) }
        let chars = Array(ext)
        if chars.count == 3, chars[0].isLetter, let n = Int(String(chars[1...])) {
            if n < 99 { return dir.appendingPathComponent(base + "." + String(chars[0]) + String(format: "%02d", n + 1)) }
            guard let a = chars[0].asciiValue, a < UInt8(ascii: "z") || (a >= 65 && a < 90) else { return nil }
            return dir.appendingPathComponent(base + "." + String(UnicodeScalar(a + 1)) + "00")
        }
        return nil
    }

    static func firstVolumeURL(_ url: URL) -> URL? {
        let name = url.lastPathComponent
        let dir = url.deletingLastPathComponent()
        if let v = volumeMatch(name) {
            guard v.number > 1 else { return nil }
            return dir.appendingPathComponent(v.prefix + String(format: "%0*d", v.width, 1) + v.suffix)
        }
        let ext = url.pathExtension
        let chars = Array(ext)
        if chars.count == 3, chars[0].isLetter, chars[0] != "r" || ext.lowercased() != "rar", Int(String(chars[1...])) != nil {
            return dir.appendingPathComponent((name as NSString).deletingPathExtension + (chars[0].isUppercase ? ".RAR" : ".rar"))
        }
        return nil
    }

    // MARK: names and times

    /// File names are 8-bit, optionally followed by a compact Unicode encoding.
    static func decodeName4(_ raw: [UInt8], unicode: Bool, windows: Bool) -> String {
        var name: String
        if unicode, let z = raw.firstIndex(of: 0) {
            let std = Array(raw[0..<z]), enc = Array(raw[(z + 1)...])
            var out = [UInt16]()
            if !enc.isEmpty {
                let high = UInt16(enc[0]) << 8
                var ep = 1, flags = 0, bits = 0
                while ep < enc.count {
                    if bits == 0 { flags = Int(enc[ep]); ep += 1; bits = 8; if ep >= enc.count { break } }
                    switch (flags >> 6) & 3 {
                    case 0: out.append(UInt16(enc[ep])); ep += 1
                    case 1: out.append(UInt16(enc[ep]) | high); ep += 1
                    case 2:
                        guard ep + 1 < enc.count else { ep = enc.count; break }
                        out.append(UInt16(enc[ep]) | UInt16(enc[ep + 1]) << 8); ep += 2
                    default:
                        var len = Int(enc[ep]); ep += 1
                        if len & 0x80 != 0 {
                            guard ep < enc.count else { break }
                            let corr = enc[ep]; ep += 1
                            len = (len & 0x7f) + 2
                            while len > 0, out.count < std.count { out.append(UInt16((std[out.count] &+ corr) & 0xff) | high); len -= 1 }
                        } else {
                            len += 2
                            while len > 0, out.count < std.count { out.append(UInt16(std[out.count])); len -= 1 }
                        }
                    }
                    flags = (flags << 2) & 0xff; bits -= 2
                }
            }
            name = String(decoding: out, as: UTF16.self)
        } else {
            let bytes = unicode ? Array(raw.prefix { $0 != 0 }) : raw
            name = String(data: Data(bytes), encoding: .utf8) ?? String(data: Data(bytes), encoding: .isoLatin1) ?? ""
        }
        if windows { name = name.replacingOccurrences(of: "\\", with: "/") }
        return name
    }

    // MARK: parsing

    func parse4() throws {
        let first = try file.read(at: 7, 13)
        if first.count >= 5 {
            let f = [UInt8](first)
            let flags = u16(f, 3)
            if flags & 1 != 0, flags & 0x100 == 0, let url = RarArchive.firstVolumeURL(file.url),
               FileManager.default.fileExists(atPath: url.path) { file = try FileIn(url) }
        }
        var vol = file
        var cont = try parseVolume4(vol)
        while cont {
            guard let next = RarArchive.nextVolumeURL(vol.url, newNumbering: newNumbering), FileManager.default.fileExists(atPath: next.path) else { break }
            vol = try FileIn(next)
            volumeCount += 1
            cont = try parseVolume4(vol)
        }
    }

    private func parseVolume4(_ f: FileIn) throws -> Bool {
        guard f.size >= 7, [UInt8](try f.read(at: 0, 7)) == RarArchive.signature4 else { throw AXError.corrupt("“\(f.url.lastPathComponent)” is not a RAR volume") }
        var pos: UInt64 = 7
        var encrypted = false
        var continues = false
        while pos + 7 <= f.size {
            var h: [UInt8]
            var next: UInt64
            if encrypted {
                let salt = try f.readExactly(at: pos, 8)
                let k = try derive3(salt: salt)
                guard pos + 8 + 16 <= f.size else { throw AXError.wrongPassword }
                let head = try aesCBCDecrypt(key: k.key, iv: k.iv, [UInt8](try f.readExactly(at: pos + 8, 16)))
                let size = u16(head, 5)
                guard size >= 7 else { throw AXError.wrongPassword }
                let padded = (size + 15) / 16 * 16
                guard pos + 8 + UInt64(padded) <= f.size else { throw AXError.wrongPassword }
                let all = padded == 16 ? head : try aesCBCDecrypt(key: k.key, iv: k.iv, [UInt8](try f.readExactly(at: pos + 8, padded)))
                h = Array(all[0..<size])
                next = pos + 8 + UInt64(padded)
                guard Int(CRC32.update(0, Data(h[2...])) & 0xffff) == u16(h, 0) else { throw AXError.wrongPassword }
            } else {
                let probe = [UInt8](try f.read(at: pos, 7))
                guard probe.count == 7 else { break }
                let size = u16(probe, 5)
                guard size >= 7, pos + UInt64(size) <= f.size else { throw AXError.corrupt("truncated RAR header") }
                h = [UInt8](try f.readExactly(at: pos, size))
                next = pos + UInt64(size)
                let type = h[2]
                if type == 0x73 || type == 0x74 || type == 0x7a || type == 0x7b {
                    guard Int(CRC32.update(0, Data(h[2...])) & 0xffff) == u16(h, 0) else { throw AXError.corrupt("RAR header CRC mismatch") }
                }
            }
            let type = h[2]
            let flags = u16(h, 3)
            switch type {
            case 0x73:
                if volumeCount == 1 || entries.isEmpty { isSolid = isSolid || flags & 0x08 != 0 }
                newNumbering = flags & 0x10 != 0
                if flags & 0x80 != 0 { encrypted = true; headersEncrypted = true }
                pos = next
            case 0x74, 0x7a:
                guard h.count >= 32 else { throw AXError.corrupt("truncated RAR file header") }
                var pack = UInt64(u32(h, 7)), unp = UInt64(u32(h, 11))
                var p = 32
                var unknownSize = false
                if flags & 0x100 != 0 {
                    guard h.count >= p + 8 else { throw AXError.corrupt("truncated RAR file header") }
                    let hp = UInt64(u32(h, p)), hu = UInt64(u32(h, p + 4)); p += 8
                    pack |= hp << 32
                    if unp == 0xffff_ffff && hu == 0xffff_ffff { unknownSize = true } else { unp |= hu << 32 }
                }
                let nameLen = u16(h, 26)
                guard h.count >= p + nameLen else { throw AXError.corrupt("truncated RAR file name") }
                let host = Int(h[15])
                let rawName = Array(h[p..<p + nameLen]); p += nameLen
                var salt: Data?
                if flags & 0x400 != 0 {
                    guard h.count >= p + 8 else { throw AXError.corrupt("truncated RAR file header") }
                    salt = Data(h[p..<p + 8]); p += 8
                }
                let dataStart = next
                let dataEnd = dataStart + pack
                guard dataEnd <= f.size else { throw AXError.corrupt("RAR archive is truncated (a file’s data is incomplete)") }
                pos = dataEnd
                if type == 0x7a {                                            // service block (comment, recovery record, …)
                    continue
                }
                let part = RarPart(file: f, offset: dataStart, length: pack)
                let splitBefore = flags & 0x01 != 0, splitAfter = flags & 0x02 != 0
                continues = splitAfter
                let name = RarArchive.decodeName4(rawName, unicode: flags & 0x200 != 0, windows: host <= 2)
                if splitBefore, let li = entries.indices.last, entries[li].name == name, entries[li].incomplete {
                    entries[li].parts.append(part)
                    entries[li].packSize += pack
                    entries[li].incomplete = splitAfter
                    if !splitAfter { entries[li].crc = u32(h, 16) }
                    continue
                }
                var e = RarEntry()
                e.name = name
                e.unpVer = Int(h[24])
                e.method = max(0, Int(h[25]) - 0x30)
                e.isDir = flags & 0xe0 == 0xe0
                e.size = unknownSize ? nil : unp
                e.packSize = pack
                e.crc = splitAfter ? nil : u32(h, 16)
                e.mtime = DOSTime.date(time: UInt16(truncatingIfNeeded: u32(h, 20)), date: UInt16(truncatingIfNeeded: u32(h, 20) >> 16))
                let attr = u32(h, 28)
                e.attrib = UInt64(attr)
                e.hostOS = host == 3 ? 1 : 0
                e.solid = flags & 0x10 != 0
                e.parts = [part]
                e.incomplete = splitAfter
                if host == 3, attr & 0xF000 == 0xA000, !e.isDir { e.dataLink = true }
                if flags & 0x04 != 0 {
                    guard let s = salt else { throw AXError.unsupported("this RAR version’s encryption (RAR 2.x)") }
                    guard e.unpVer >= 29 else { throw AXError.unsupported("this RAR version’s encryption (RAR 2.x)") }
                    e.enc = RarEnc(log2: 0, salt: s, iv: Data(), check: nil, useMAC: false, v3: true)
                }
                entries.append(e)
            case 0x7b:
                if flags & 0x01 != 0 { continues = true }
                return continues
            default:
                if flags & 0x8000 != 0, h.count >= 11 { pos = next + UInt64(u32(h, 7)) } else { pos = next }
            }
        }
        return continues
    }
}

// MARK: - Decompressor (unpack version 29/36)

private struct VMBits {
    let d: [UInt8]
    var pos = 0                                   // bit position
    var overflow: Bool { pos > d.count * 8 }
    mutating func bits(_ n: Int) -> Int {
        var v = 0
        for _ in 0..<n {
            let byte = pos >> 3
            let bit = byte < d.count ? Int(d[byte] >> UInt8(7 - (pos & 7))) & 1 : 0
            v = v << 1 | bit; pos += 1
        }
        return v
    }
    /// The variable-length number format of RAR programs.
    mutating func data() -> UInt32 {
        switch bits(2) {
        case 0: return UInt32(bits(4))
        case 1:
            let v = bits(8)
            if v >= 16 { return UInt32(v) }
            return 0xffff_ff00 | UInt32(v << 4 | bits(4))
        case 2: return UInt32(bits(16))
        default: return UInt32(bits(16)) << 16 | UInt32(bits(16))
        }
    }
}

final class Rar4Decoder {
    private static let lDecode = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
    private static let lBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
    private static let sdDecode = [0, 4, 8, 16, 32, 64, 128, 192]
    private static let sdBits = [2, 2, 3, 4, 5, 6, 6, 6]
    private static let dTables: (base: [Int], bits: [Int]) = {
        var base = [Int](), bits = [Int](), next = 0
        for (b, n) in [(0, 4)] + (1...15).map({ ($0, 2) }) + [(16, 14), (18, 12)] {
            for _ in 0..<n { base.append(next); bits.append(b); next += 1 << b }
        }
        return (base, bits)
    }()

    private enum Kind { case e8, e8e9, itanium, delta, rgb, audio }
    private struct Pending { var kind: Kind; var start: UInt64; var length: Int; var regs: [UInt32] }

    private let winSize = 1 << 22
    private let mask = (1 << 22) - 1
    private let win: UnsafeMutablePointer<UInt8>
    private var wpos = 0
    private var valid: UInt64 = 0
    private var oldDist = [0, 0, 0, 0]
    private var lastLen = 0
    private var prevLowDist = 0, lowDistRepCount = 0
    private var oldTable = [UInt8](repeating: 0, count: 404)
    private var ld = RHuff(), dd = RHuff(), ldd = RHuff(), rd = RHuff()
    private var tablesRead = false
    private var ppmBlock = false
    private var escChar = 2
    private let ppm = Ppmd7()

    private var filterKinds = [Kind]()
    private var oldFilterLengths = [Int]()
    private var lastFilter = 0
    private var pending = [Pending]()

    private var br: RBits!
    private var out = [UInt8]()
    private var outHead = 0
    private var outBase: UInt64 = 0
    private var produced: UInt64 = 0
    private var sink: ByteSink!
    private var progress: ProgressTracker?

    init() {
        win = UnsafeMutablePointer<UInt8>.allocate(capacity: winSize)
        win.initialize(repeating: 0, count: winSize)
    }
    deinit { win.deallocate() }

    // MARK: entry point

    func decode(input: ByteSource, size: UInt64?, solid: Bool, sink: ByteSink, progress: ProgressTracker?) throws {
        if !solid {
            wpos = 0; valid = 0; oldDist = [0, 0, 0, 0]; lastLen = 0; prevLowDist = 0; lowDistRepCount = 0
            oldTable = [UInt8](repeating: 0, count: 404); tablesRead = false; ppmBlock = false; escChar = 2
            filterKinds = []; oldFilterLengths = []; lastFilter = 0
        }
        pending = []
        br = RBits(input); self.sink = sink; self.progress = progress
        ppm.input = br
        out.removeAll(keepingCapacity: true); outHead = 0; outBase = 0; produced = 0
        if !solid || !tablesRead { try readTables() }
        try run(size: size)
        try flush(final: true)
        if let s = size, produced != s { throw AXError.corrupt("RAR data shorter than the file") }
        br = nil; ppm.input = nil
    }

    // MARK: tables

    @inline(__always) private func decode(_ t: RHuff) throws -> Int {
        try br.refill()
        let e = t.table[br.peek(15)]
        let l = Int(e & 15)
        guard l > 0 else { throw AXError.corrupt("invalid RAR Huffman code") }
        br.skip(l)
        return Int(e >> 4)
    }

    private func readTables() throws {
        let pad = (8 - Int(br.consumed & 7)) & 7
        if pad > 0 { _ = try br.take(pad) }
        try br.refill()
        if br.peek(1) == 1 {                                       // PPMd block: the flag lives in its first byte
            try startPPM()
            ppmBlock = true
            return
        }
        ppmBlock = false
        prevLowDist = 0; lowDistRepCount = 0
        _ = try br.take(1)
        if try br.take(1) == 0 { oldTable = [UInt8](repeating: 0, count: 404) }
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
        var table = [UInt8](repeating: 0, count: 404)
        i = 0
        while i < 404 {
            let sym = try decode(bd)
            if sym < 16 { table[i] = UInt8((sym + Int(oldTable[i])) & 15); i += 1; continue }
            var count: Int
            if sym < 18 {
                guard i > 0 else { throw AXError.corrupt("bad RAR table repeat") }
                count = sym == 16 ? try br.take(3) + 3 : try br.take(7) + 11
                let v = table[i - 1]
                while count > 0 && i < 404 { table[i] = v; i += 1; count -= 1 }
            } else {
                count = sym == 18 ? try br.take(3) + 3 : try br.take(7) + 11
                while count > 0 && i < 404 { table[i] = 0; i += 1; count -= 1 }
            }
        }
        guard !br.overrun else { throw AXError.corrupt("truncated RAR data") }
        ld = try RHuff(lengths: table[0..<299])
        dd = try RHuff(lengths: table[299..<359])
        ldd = try RHuff(lengths: table[359..<376])
        rd = try RHuff(lengths: table[376..<404])
        oldTable = table
        tablesRead = true
    }

    private func startPPM() throws {
        let flags = try br.take(8)
        var reset = false
        var mem = 0
        if flags & 0x20 != 0 { reset = true; mem = try br.take(8) }
        if flags & 0x40 != 0 { escChar = try br.take(8) }
        try ppm.initRange()
        if reset {
            var order = (flags & 0x1f) + 1
            if order > 16 { order = 16 + (order - 16) * 3 }
            guard order > 1 else { throw AXError.corrupt("bad PPMd parameters") }
            try ppm.start(order: order, memory: (mem + 1) << 20)
        } else if !ppm.ready { throw AXError.corrupt("PPMd data without a model") }
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

    private func run(size: UInt64?) throws {
        var finished = false
        while !finished {
            if let s = size, produced > s { throw AXError.corrupt("RAR data longer than the file") }
            if out.count - outHead >= 1 << 20 { try flush(final: false) }
            if ppmBlock {
                finished = try ppmStep()
                continue
            }
            guard !br.overrun else { throw AXError.corrupt("truncated RAR data") }
            let sym = try decode(ld)
            if sym < 256 { put(UInt8(sym)); continue }
            if sym >= 271 {
                let k = sym - 271
                var length = Rar4Decoder.lDecode[k] + 3
                if Rar4Decoder.lBits[k] > 0 { length += try br.take(Rar4Decoder.lBits[k]) }
                let ds = try decode(dd)
                var d = Rar4Decoder.dTables.base[ds] + 1
                let bits = Rar4Decoder.dTables.bits[ds]
                if bits > 0 {
                    if ds > 9 {
                        if bits > 4 { d += try br.take(bits - 4) << 4 }
                        if lowDistRepCount > 0 { lowDistRepCount -= 1; d += prevLowDist }
                        else {
                            let low = try decode(ldd)
                            if low == 16 { lowDistRepCount = 15; d += prevLowDist }
                            else { d += low; prevLowDist = low }
                        }
                    } else { d += try br.take(bits) }
                }
                if d >= 0x2000 { length += 1; if d >= 0x40000 { length += 1 } }
                oldDist[3] = oldDist[2]; oldDist[2] = oldDist[1]; oldDist[1] = oldDist[0]; oldDist[0] = d
                lastLen = length
                try copy(length, d)
            } else if sym == 256 {
                try br.refill()
                if br.peek(1) == 1 {                              // another table follows, same file
                    _ = try br.take(1)
                    tablesRead = false
                    try readTables()
                } else {
                    let newTable = br.peek(2) & 1 != 0
                    _ = try br.take(2)
                    tablesRead = !newTable
                    finished = true
                }
            } else if sym == 257 {
                try readFilter { try self.br.take(8) }
            } else if sym == 258 {
                if lastLen != 0 { try copy(lastLen, oldDist[0]) }
            } else if sym < 263 {
                let idx = sym - 259
                let d = oldDist[idx]
                var k = idx; while k > 0 { oldDist[k] = oldDist[k - 1]; k -= 1 }
                oldDist[0] = d
                let ln = try decode(rd)
                var length = Rar4Decoder.lDecode[ln] + 2
                if Rar4Decoder.lBits[ln] > 0 { length += try br.take(Rar4Decoder.lBits[ln]) }
                lastLen = length
                try copy(length, d)
            } else {
                let k = sym - 263
                var d = Rar4Decoder.sdDecode[k] + 1
                if Rar4Decoder.sdBits[k] > 0 { d += try br.take(Rar4Decoder.sdBits[k]) }
                oldDist[3] = oldDist[2]; oldDist[2] = oldDist[1]; oldDist[1] = oldDist[0]; oldDist[0] = d
                lastLen = 2
                try copy(2, d)
            }
        }
    }

    /// One PPMd symbol (which may be an escape sequence). Returns true at the end of the file's data.
    private func ppmStep() throws -> Bool {
        let ch = try ppm.decodeChar()
        guard ch >= 0 else { throw AXError.corrupt("damaged PPMd data") }
        if ch != escChar { put(UInt8(ch)); return false }
        let next = try ppm.decodeChar()
        switch next {
        case 0:
            try readTables()
            return false
        case 2: return true
        case -1: throw AXError.corrupt("damaged PPMd data")
        case 3:
            try readFilter { let c = try self.ppm.decodeChar(); if c < 0 { throw AXError.corrupt("damaged PPMd data") }; return c }
            return false
        case 4:
            var dist = 0, len = 0
            for i in 0..<4 {
                let c = try ppm.decodeChar()
                guard c >= 0 else { throw AXError.corrupt("damaged PPMd data") }
                if i == 3 { len = c } else { dist = dist << 8 + c }
            }
            try copy(len + 32, dist + 2)
            return false
        case 5:
            let len = try ppm.decodeChar()
            guard len >= 0 else { throw AXError.corrupt("damaged PPMd data") }
            try copy(len + 4, 1)
            return false
        default:
            put(UInt8(ch))
            return false
        }
    }

    // MARK: filters

    private static let known: [(length: Int, crc: UInt32, kind: Kind)] = [
        (53, 0xad57_6887, .e8), (57, 0x3cd7_e57e, .e8e9), (120, 0x3769_893f, .itanium),
        (29, 0x0e06_077d, .delta), (149, 0x1c2c_5dc8, .rgb), (216, 0xbc85_e701, .audio),
    ]

    private func readFilter(_ next: () throws -> Int) throws {
        let first = try next()
        var length = (first & 7) + 1
        if length == 7 { length = try next() + 7 }
        else if length == 8 { let hi = try next(); let lo = try next(); length = hi << 8 | lo }
        guard length > 0 else { throw AXError.corrupt("bad RAR filter") }
        var code = [UInt8]()
        code.reserveCapacity(length)
        for _ in 0..<length { code.append(UInt8(try next())) }
        try addFilter(first, code)
    }

    private func addFilter(_ first: Int, _ code: [UInt8]) throws {
        var v = VMBits(d: code)
        var pos: Int
        if first & 0x80 != 0 {
            pos = Int(v.data())
            if pos == 0 { filterKinds = []; oldFilterLengths = []; lastFilter = 0; pending = [] } else { pos -= 1 }
        } else { pos = lastFilter }
        guard pos <= filterKinds.count, pos <= oldFilterLengths.count else { throw AXError.corrupt("bad RAR filter number") }
        lastFilter = pos
        let isNew = pos == filterKinds.count
        guard !isNew || pos < 1024 else { throw AXError.corrupt("too many RAR filters") }
        var blockStart = Int(v.data())
        if first & 0x40 != 0 { blockStart += 258 }
        var blockLength: Int
        if first & 0x20 != 0 { blockLength = Int(v.data()) } else { blockLength = pos < oldFilterLengths.count ? oldFilterLengths[pos] : 0 }
        var regs = [UInt32](repeating: 0, count: 7)
        regs[3] = 0x3c000; regs[4] = UInt32(truncatingIfNeeded: blockLength)
        if first & 0x10 != 0 {
            let m = v.bits(7)
            for i in 0..<7 where m & (1 << i) != 0 { regs[i] = v.data() }
        }
        if isNew {
            let n = Int(v.data())
            guard n > 0, n < 0x10000 else { throw AXError.corrupt("bad RAR filter program") }
            var prog = [UInt8]()
            for _ in 0..<n { guard !v.overflow else { throw AXError.corrupt("bad RAR filter program") }; prog.append(UInt8(v.bits(8))) }
            var x: UInt8 = 0
            for b in prog.dropFirst() { x ^= b }
            guard x == prog[0] else { throw AXError.corrupt("RAR filter program checksum mismatch") }
            let crc = CRC32.update(0, Data(prog))
            guard let k = Rar4Decoder.known.first(where: { $0.length == n && $0.crc == crc }) else {
                throw AXError.unsupported("a custom RAR filter program")
            }
            filterKinds.append(k.kind); oldFilterLengths.append(blockLength)
        }
        guard !v.overflow else { throw AXError.corrupt("bad RAR filter") }
        oldFilterLengths[pos] = blockLength
        guard blockLength > 0, blockLength <= 0x3c000 else { throw AXError.corrupt("bad RAR filter size") }
        regs[4] = UInt32(blockLength)
        pending.append(Pending(kind: filterKinds[pos], start: produced + UInt64(blockStart), length: blockLength, regs: regs))
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
            let have = out.count - outHead
            guard let f = pending.first else { try emit(have); return }
            guard f.start >= outBase else { throw AXError.corrupt("RAR filter out of order") }
            let ahead = Int(f.start - outBase)
            if ahead > 0 {
                try emit(min(ahead, have))
                if ahead > have { return }
                continue
            }
            if f.length <= have {
                apply(f, at: outHead)
                pending.removeFirst()
                while let g = pending.first, g.start == f.start, g.length == f.length { apply(g, at: outHead); pending.removeFirst() }
                try emit(f.length)
                continue
            }
            if final { throw AXError.corrupt("RAR filter extends past the end of the data") }
            return
        }
    }

    private func apply(_ f: Pending, at base: Int) {
        let n = f.length
        switch f.kind {
        case .e8, .e8e9:
            guard n >= 4 else { return }
            let cmp: UInt8 = f.kind == .e8e9 ? 0xe9 : 0xe8
            let fileSize: UInt32 = 0x100_0000
            let fileOffset = UInt32(truncatingIfNeeded: f.start)
            var cur = 0
            while cur < n - 4 {
                let b = out[base + cur]; cur += 1
                if b == 0xe8 || b == cmp {
                    let offset = UInt32(truncatingIfNeeded: cur) &+ fileOffset
                    let off = offset % fileSize
                    let p = base + cur
                    let addr = UInt32(out[p]) | UInt32(out[p + 1]) << 8 | UInt32(out[p + 2]) << 16 | UInt32(out[p + 3]) << 24
                    var nv: UInt32?
                    if addr & 0x8000_0000 != 0 { if (addr &+ off) & 0x8000_0000 == 0 { nv = addr &+ fileSize } }
                    else if (addr &- fileSize) & 0x8000_0000 != 0 { nv = addr &- off }
                    if let v = nv {
                        out[p] = UInt8(truncatingIfNeeded: v); out[p + 1] = UInt8(truncatingIfNeeded: v >> 8)
                        out[p + 2] = UInt8(truncatingIfNeeded: v >> 16); out[p + 3] = UInt8(truncatingIfNeeded: v >> 24)
                    }
                    cur += 4
                }
            }
        case .itanium:
            guard n >= 21 else { return }
            let masks: [UInt8] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0]
            var fileOffset = UInt32(truncatingIfNeeded: f.start) >> 4
            var cur = 0
            while cur < n - 21 {
                let byte = Int(out[base + cur] & 0x1f) - 0x10
                if byte >= 0 {
                    let cmd = masks[byte]
                    if cmd != 0 {
                        for i in 0...2 where cmd & (1 << UInt8(i)) != 0 {
                            let start = i * 41 + 5
                            if getBits(base + cur, start + 37, 4) == 5 {
                                let offset = getBits(base + cur, start + 13, 20)
                                setBits(base + cur, (offset &- fileOffset) & 0xfffff, start + 13, 20)
                            }
                        }
                    }
                }
                cur += 16; fileOffset &+= 1
            }
        case .delta:
            let ch = Int(f.regs[0])
            guard ch > 0 else { return }
            let src = Array(out[base..<base + n])
            var s = 0
            for c in 0..<min(ch, n) {
                var prev: UInt8 = 0
                var d = c
                while d < n { prev = prev &- src[s]; s += 1; out[base + d] = prev; d += ch }
            }
        case .rgb:
            let width = Int(f.regs[0]) - 3, posR = Int(f.regs[1])
            guard posR <= 2 else { return }
            let src = Array(out[base..<base + n])
            var dst = [UInt8](repeating: 0, count: n)
            func at(_ idx: Int) -> Int { Int(dst[idx]) }
            var s = 0
            for c in 0..<3 {
                var prev = 0
                var i = c
                while i < n {
                    var predicted: Int
                    if width >= 0 && i >= width + 3 {
                        let upper = at(i - width), upperLeft = at(i - width - 3)
                        predicted = prev + upper - upperLeft
                        let pa = abs(predicted - prev), pb = abs(predicted - upper), pc = abs(predicted - upperLeft)
                        if pa <= pb && pa <= pc { predicted = prev } else if pb <= pc { predicted = upper } else { predicted = upperLeft }
                    } else { predicted = prev }
                    prev = Int(UInt8(truncatingIfNeeded: predicted &- Int(src[s]))); s += 1
                    dst[i] = UInt8(prev)
                    i += 3
                }
            }
            var i = posR
            while i < n - 2 {
                let g = dst[i + 1]
                dst[i] = dst[i] &+ g
                dst[i + 2] = dst[i + 2] &+ g
                i += 3
            }
            for k in 0..<n { out[base + k] = dst[k] }
        case .audio:
            let ch = Int(f.regs[0])
            guard ch > 0 else { return }
            let src = Array(out[base..<base + n])
            var dst = [UInt8](repeating: 0, count: n)
            var s = 0
            for c in 0..<min(ch, n) {
                var prevByte = 0, prevDelta = 0
                var dif = [Int](repeating: 0, count: 7)
                var d1 = 0, d2 = 0, d3 = 0, k1 = 0, k2 = 0, k3 = 0
                var i = c, count = 0
                while i < n {
                    d3 = d2; d2 = prevDelta - d1; d1 = prevDelta
                    var predicted = 8 * prevByte + k1 * d1 + k2 * d2 + k3 * d3
                    predicted = (predicted >> 3) & 0xff
                    let cur = Int(src[s]); s += 1
                    predicted = (predicted - cur) & 0xff
                    dst[i] = UInt8(predicted)
                    prevDelta = Int(Int8(truncatingIfNeeded: predicted - prevByte))
                    prevByte = predicted
                    let d = Int(Int8(truncatingIfNeeded: cur)) << 3
                    dif[0] += abs(d); dif[1] += abs(d - d1); dif[2] += abs(d + d1)
                    dif[3] += abs(d - d2); dif[4] += abs(d + d2); dif[5] += abs(d - d3); dif[6] += abs(d + d3)
                    if count & 0x1f == 0 {
                        var minDif = dif[0], num = 0
                        dif[0] = 0
                        for j in 1..<7 { if dif[j] < minDif { minDif = dif[j]; num = j }; dif[j] = 0 }
                        switch num {
                        case 1: if k1 >= -16 { k1 -= 1 }
                        case 2: if k1 < 16 { k1 += 1 }
                        case 3: if k2 >= -16 { k2 -= 1 }
                        case 4: if k2 < 16 { k2 += 1 }
                        case 5: if k3 >= -16 { k3 -= 1 }
                        case 6: if k3 < 16 { k3 += 1 }
                        default: break
                        }
                    }
                    i += ch; count += 1
                }
            }
            for k in 0..<n { out[base + k] = dst[k] }
        }
    }

    private func getBits(_ at: Int, _ bitPos: Int, _ count: Int) -> UInt32 {
        let a = at + bitPos / 8, b = bitPos & 7
        var v = UInt32(out[a]) | UInt32(out[a + 1]) << 8 | UInt32(out[a + 2]) << 16 | UInt32(out[a + 3]) << 24
        v >>= UInt32(b)
        return v & (0xffff_ffff >> UInt32(32 - count))
    }

    private func setBits(_ at: Int, _ value: UInt32, _ bitPos: Int, _ count: Int) {
        let a = at + bitPos / 8, b = UInt32(bitPos & 7)
        var andMask = ~((0xffff_ffff >> UInt32(32 - count)) << b)
        var v = value << b
        for i in 0..<4 {
            out[a + i] = (out[a + i] & UInt8(truncatingIfNeeded: andMask)) | UInt8(truncatingIfNeeded: v)
            andMask = (andMask >> 8) | 0xff00_0000
            v >>= 8
        }
    }
}
