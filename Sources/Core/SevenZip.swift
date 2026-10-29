import Foundation
import CommonCrypto
import CryptoKit

// 7z archives: reader (LZMA, LZMA2, BZip2, Deflate, Copy, BCJ/ARM/ARM64/Delta, AES-256, encoded and
// encrypted headers) and writer (LZMA2 or stored, solid or per-file, AES-256, encrypted headers).

private enum ID {
    static let end = 0, header = 1, archiveProps = 2, additionalStreams = 3, mainStreams = 4, filesInfo = 5
    static let packInfo = 6, unpackInfo = 7, subStreams = 8, size = 9, crc = 0x0a, folder = 0x0b, codersUnpackSize = 0x0c
    static let numUnpackStream = 0x0d, emptyStream = 0x0e, emptyFile = 0x0f, anti = 0x10, names = 0x11
    static let mtime = 0x14, attributes = 0x15, encodedHeader = 0x17
}

private enum Method {
    static let copy: UInt64 = 0x00, delta: UInt64 = 0x03, bcjx86: UInt64 = 0x04, arm64: UInt64 = 0x0a
    static let lzma2: UInt64 = 0x21, lzma: UInt64 = 0x030101, ppmd: UInt64 = 0x030401
    static let ppc: UInt64 = 0x05, ia64: UInt64 = 0x06, arm: UInt64 = 0x07, armt: UInt64 = 0x08, sparc: UInt64 = 0x09
    static let ppcOld: UInt64 = 0x03030205, ia64Old: UInt64 = 0x03030401, armtOld: UInt64 = 0x03030701, sparcOld: UInt64 = 0x03030805
    static let bcj2: UInt64 = 0x0303011b, bcjx86Old: UInt64 = 0x03030103, armOld: UInt64 = 0x03030501
    static let deflate: UInt64 = 0x040108, bzip2: UInt64 = 0x040202, aes: UInt64 = 0x06f10701

    static func name(_ id: UInt64) -> String {
        switch id {
        case copy: return "Store"; case bcj2: return "BCJ2"; case delta: return "Delta"; case bcjx86, bcjx86Old: return "BCJ"; case arm64: return "ARM64"
        case armOld, arm: return "ARM"; case ppc, ppcOld: return "PPC"; case ia64, ia64Old: return "IA64"; case armt, armtOld: return "ARMT"; case sparc, sparcOld: return "SPARC"; case lzma2: return "LZMA2"; case lzma: return "LZMA"; case ppmd: return "PPMd"
        case deflate: return "Deflate"; case bzip2: return "BZip2"; case aes: return "AES-256"
        default: return "method " + String(id, radix: 16)
        }
    }
}

// MARK: - helpers

private struct HReader {
    let d: Data
    var p = 0
    init(_ d: Data) { self.d = d }

    mutating func byte() throws -> Int {
        guard p < d.count else { throw AXError.corrupt("truncated 7z header") }
        defer { p += 1 }
        return Int(d[d.startIndex + p])
    }
    mutating func number() throws -> UInt64 {
        let first = try byte()
        var mask = 0x80, value: UInt64 = 0
        for i in 0..<8 {
            if first & mask == 0 { return value | (UInt64(first & (mask - 1)) << UInt64(8 * i)) }
            value |= UInt64(try byte()) << UInt64(8 * i)
            mask >>= 1
        }
        return value
    }
    mutating func bytes(_ n: Int) throws -> Data {
        guard n >= 0, p + n <= d.count else { throw AXError.corrupt("truncated 7z header") }
        defer { p += n }
        return d.subdata(in: d.startIndex + p..<d.startIndex + p + n)
    }
    mutating func u32() throws -> UInt32 { try bytes(4).le32(0) }
    mutating func u64() throws -> UInt64 { try bytes(8).le64(0) }
    mutating func bitVector(_ n: Int) throws -> [Bool] {
        var out = [Bool](); var cur = 0, mask = 0
        for _ in 0..<n { if mask == 0 { cur = try byte(); mask = 0x80 }; out.append(cur & mask != 0); mask >>= 1 }
        return out
    }
    mutating func optionalBits(_ n: Int) throws -> [Bool] {
        let all = try byte()
        return all != 0 ? [Bool](repeating: true, count: n) : try bitVector(n)
    }
    mutating func digests(_ n: Int) throws -> [UInt32?] {
        let defined = try optionalBits(n)
        return try defined.map { $0 ? try u32() : nil }
    }
}

private func put7z(_ v: UInt64, _ d: inout Data) {
    var first: UInt8 = 0, mask: UInt8 = 0x80
    var i = 0
    while i < 8 {
        if v < (UInt64(1) << UInt64(7 * (i + 1))) { first |= UInt8(truncatingIfNeeded: v >> UInt64(8 * i)); break }
        first |= mask; mask >>= 1; i += 1
    }
    d.append(first)
    var x = v
    for _ in 0..<i { d.append(UInt8(x & 0xff)); x >>= 8 }
}

private func putBits(_ bits: [Bool], _ d: inout Data) {
    var cur: UInt8 = 0, mask: UInt8 = 0x80
    for b in bits { if b { cur |= mask }; mask >>= 1; if mask == 0 { d.append(cur); cur = 0; mask = 0x80 } }
    if mask != 0x80 { d.append(cur) }
}

final class RangeSource: ByteSource {
    private let file: FileIn
    private var pos: UInt64
    private var left: UInt64
    init(file: FileIn, offset: UInt64, length: UInt64) { self.file = file; pos = offset; left = length }
    func read(_ n: Int) throws -> Data {
        let take = Int(min(UInt64(n), left, 1 << 20))
        guard take > 0 else { return Data() }
        let d = try file.read(at: pos, take)
        pos += UInt64(d.count); left -= UInt64(d.count)
        return d
    }
    func skip(_ n: UInt64) throws { pos += n; left -= min(left, n) }
}

/// Deflate (7z coder 040108) over any byte source.
final class InflateSource: ByteSource {
    private let input: ByteSource
    private let inf = Inflater()
    private var out = [UInt8](); private var outPos = 0
    private var ended = false
    private var pending = Data()
    init(input: ByteSource) { self.input = input }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && !ended {
            let next = try input.read(1 << 16)
            let chunk = pending; pending = next
            if chunk.isEmpty && next.isEmpty { throw AXError.corrupt("unexpected end of deflate data") }
            let r = try inf.process(chunk, final: next.isEmpty) { self.out.append(contentsOf: $0) }
            if r.ended { ended = true }
        }
        let take = min(n, out.count - outPos)
        let d = Data(out[outPos..<outPos + take]); outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

// MARK: - AES (7zAES)

enum SevenAES {
    static func key(password: String, salt: Data, power: Int) -> Data {
        let pw = Data(password.utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] })
        if power == 0x3f {
            var k = salt + pw
            if k.count < 32 { k.append(Data(count: 32 - k.count)) }
            return k.prefix(32)
        }
        var sha = SHA256()
        let rounds: UInt64 = 1 << UInt64(power)
        var i: UInt64 = 0
        let batch: UInt64 = 2048
        while i < rounds {
            var buf = Data()
            let end = min(rounds, i + batch)
            for k in i..<end { buf.append(salt); buf.append(pw); var c = k.littleEndian; withUnsafeBytes(of: &c) { buf.append(contentsOf: $0) } }
            sha.update(data: buf)
            i = end
        }
        return Data(sha.finalize())
    }

    struct Props { var power: Int; var salt: Data; var iv: Data }

    static func parse(_ p: Data) throws -> Props {
        guard p.count >= 1 else { throw AXError.corrupt("bad 7z AES properties") }
        let b0 = Int(p[p.startIndex])
        let power = b0 & 0x3f
        if b0 & 0xc0 == 0 { return Props(power: power, salt: Data(), iv: Data(count: 16)) }
        guard p.count >= 2 else { throw AXError.corrupt("bad 7z AES properties") }
        let b1 = Int(p[p.startIndex + 1])
        let ivSize = ((b0 >> 6) & 1) + (b1 & 0x0f), saltSize = ((b0 >> 7) & 1) + (b1 >> 4)
        guard p.count >= 2 + saltSize + ivSize, ivSize <= 16 else { throw AXError.corrupt("bad 7z AES properties") }
        let salt = p.subdata(in: p.startIndex + 2..<p.startIndex + 2 + saltSize)
        var iv = p.subdata(in: p.startIndex + 2 + saltSize..<p.startIndex + 2 + saltSize + ivSize)
        iv.append(Data(count: 16 - iv.count))
        return Props(power: power, salt: salt, iv: iv)
    }
}

final class SevenAESSource: ByteSource {
    private let input: ByteSource
    private var cryptor: CCCryptorRef?
    private var remaining: UInt64
    private var carry = Data()
    private var out = Data(); private var outPos = 0

    init(input: ByteSource, props: Data, password: String?, unpackSize: UInt64) throws {
        guard let pw = password, !pw.isEmpty else { throw AXError.passwordRequired }
        let p = try SevenAES.parse(props)
        let key = SevenAES.key(password: pw, salt: p.salt, power: p.power)
        self.input = input; remaining = unpackSize
        let status = key.withUnsafeBytes { k in p.iv.withUnsafeBytes { iv in
            CCCryptorCreate(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, 32, iv.baseAddress, &cryptor)
        } }
        guard status == kCCSuccess else { throw AXError.io("Could not start AES.") }
    }
    deinit { if let c = cryptor { CCCryptorRelease(c) } }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && remaining > 0 {
            var chunk = carry + (try input.read(1 << 16))
            if chunk.count == carry.count { throw AXError.corrupt("encrypted data ended early") }
            let usable = chunk.count - chunk.count % 16
            carry = chunk.suffix(chunk.count - usable); chunk = chunk.prefix(usable)
            guard usable > 0 else { continue }
            var plain = Data(count: usable); var moved = 0
            let st = chunk.withUnsafeBytes { i in plain.withUnsafeMutableBytes { o in CCCryptorUpdate(cryptor, i.baseAddress, usable, o.baseAddress, usable, &moved) } }
            guard st == kCCSuccess else { throw AXError.io("AES failure.") }
            let take = Int(min(UInt64(moved), remaining)); remaining -= UInt64(take)
            out.append(plain.prefix(take))
        }
        let take = min(n, out.count - outPos)
        let d = out.subdata(in: out.startIndex + outPos..<out.startIndex + outPos + take); outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

final class SevenAESSink: ByteSink {
    private let out: ByteSink
    private var cryptor: CCCryptorRef?
    private var carry = Data()
    let props: Data

    init(out: ByteSink, password: String) throws {
        self.out = out
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let power = 19
        props = Data([UInt8(power) | 0x40, 0x0f]) + iv
        let key = SevenAES.key(password: password, salt: Data(), power: power)
        let status = key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
            CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, 32, v.baseAddress, &cryptor)
        } }
        guard status == kCCSuccess else { throw AXError.io("Could not start AES.") }
    }
    deinit { if let c = cryptor { CCCryptorRelease(c) } }

    private func encrypt(_ d: Data) throws -> Data {
        var o = Data(count: d.count); var moved = 0
        let st = d.withUnsafeBytes { i in o.withUnsafeMutableBytes { p in CCCryptorUpdate(cryptor, i.baseAddress, d.count, p.baseAddress, d.count, &moved) } }
        guard st == kCCSuccess else { throw AXError.io("AES failure.") }
        return o
    }
    func write(_ data: Data) throws {
        carry.append(data)
        let usable = carry.count - carry.count % 16
        if usable > 0 { try out.write(try encrypt(carry.prefix(usable))); carry = carry.suffix(carry.count - usable) }
    }
    func finish() throws {
        if !carry.isEmpty { carry.append(Data(count: 16 - carry.count)); try out.write(try encrypt(carry)); carry = Data() }
    }
}

// MARK: - Archive model

struct SZCoder { var id: UInt64; var numIn: Int; var numOut: Int; var props: Data }

struct SZFolder {
    var coders: [SZCoder] = []
    var bind: [(inIdx: Int, outIdx: Int)] = []
    var packed: [Int] = []
    var unpack: [UInt64] = []
    var crc: UInt32?
    var numSub = 1
    var firstPack = 0
    var mainOut: Int { (0..<unpack.count).first { o in !bind.contains { $0.outIdx == o } } ?? 0 }
    var size: UInt64 { unpack.isEmpty ? 0 : unpack[mainOut] }
    var encrypted: Bool { coders.contains { $0.id == Method.aes } }
}

struct SZFile {
    var name = ""
    var hasStream = true
    var isDir = false
    var size: UInt64 = 0
    var crc: UInt32?
    var mtime: Date?
    var attrib: UInt32?
    var folder = -1
    var unixMode: UInt32? { attrib.flatMap { $0 & 0x8000 != 0 ? $0 >> 16 : nil } }
    var isSymlink: Bool { unixMode.map { $0 & 0xf000 == 0xa000 } ?? false }
}

private struct StreamsInfo {
    var packPos: UInt64 = 0
    var packSizes: [UInt64] = []
    var folders: [SZFolder] = []
    var subSizes: [[UInt64]] = []
    var subCRCs: [[UInt32?]] = []
}

final class SevenZipArchive {
    let file: FileIn
    private var streams = StreamsInfo()
    private(set) var files: [SZFile] = []
    private(set) var headerEncrypted = false
    private let password: String?

    var folders: [SZFolder] { streams.folders }

    init(url: URL, password: String?) throws {
        file = try FileIn.openArchive(url)
        self.password = password
        try parse()
    }

    // MARK: parsing

    private func parse() throws {
        guard file.size >= 32 else { throw AXError.corrupt("not a 7z archive") }
        let sh = try file.readExactly(at: 0, 32)
        guard Array(sh.prefix(6)) == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] else { throw AXError.corrupt("not a 7z archive") }
        guard sh[sh.startIndex + 6] == 0 else { throw AXError.unsupported("7z format version \(sh[sh.startIndex + 6])") }
        guard CRC32.update(0, sh.subdata(in: sh.startIndex + 12..<sh.startIndex + 32)) == sh.le32(8) else { throw AXError.corrupt("7z start header CRC mismatch") }
        let off = sh.le64(12), size = sh.le64(20), crc = sh.le32(28)
        guard size > 0 else { return }                                       // empty archive
        guard size < 1 << 31, 32 + off + size <= file.size else { throw AXError.corrupt("7z header out of range (truncated archive?)") }
        var data = try file.readExactly(at: 32 + off, Int(size))
        guard CRC32.update(0, data) == crc else { throw AXError.corrupt("7z header CRC mismatch") }

        while true {
            var r = HReader(data)
            let id = try r.byte()
            if id == ID.encodedHeader {
                let si = try readStreams(&r)
                guard let f = si.folders.first else { throw AXError.corrupt("bad encoded 7z header") }
                headerEncrypted = headerEncrypted || f.encrypted
                do {
                    let src = try chain(folder: f, info: si)
                    var out = Data()
                    while out.count < Int(f.size) { let d = try src.read(1 << 20); if d.isEmpty { break }; out.append(d) }
                    guard out.count == Int(f.size) else { throw AXError.corrupt("7z header decoding failed") }
                    if let c = f.crc, CRC32.update(0, out) != c { throw AXError.corrupt("7z header CRC mismatch") }
                    data = out
                } catch let e as AXError {
                    if f.encrypted, case .corrupt = e { throw AXError.wrongPassword }
                    throw e
                }
                continue
            }
            guard id == ID.header else { throw AXError.corrupt("unexpected 7z header type") }
            try readHeader(&r)
            return
        }
    }

    private func readHeader(_ r: inout HReader) throws {
        while true {
            let id = Int(try r.number())
            switch id {
            case ID.end: return
            case ID.archiveProps:
                while true { let t = Int(try r.number()); if t == 0 { break }; _ = try r.bytes(Int(try r.number())) }
            case ID.additionalStreams: _ = try readStreams(&r)
            case ID.mainStreams: streams = try readStreams(&r)
            case ID.filesInfo: try readFiles(&r)
            default: throw AXError.corrupt("unknown 7z header item \(id)")
            }
        }
    }

    private func readStreams(_ r: inout HReader) throws -> StreamsInfo {
        var si = StreamsInfo()
        var folderCRCs: [UInt32?] = []
        while true {
            let id = Int(try r.number())
            switch id {
            case ID.end:
                // assign pack stream indexes
                var next = 0
                for i in 0..<si.folders.count { si.folders[i].firstPack = next; next += si.folders[i].packed.count }
                if si.subSizes.isEmpty {
                    si.subSizes = si.folders.map { [$0.size] }
                    si.subCRCs = si.folders.map { [$0.crc] }
                }
                return si
            case ID.packInfo:
                si.packPos = try r.number()
                let n = Int(try r.number())
                while true {
                    let t = Int(try r.number())
                    if t == ID.end { break }
                    if t == ID.size { si.packSizes = try (0..<n).map { _ in try r.number() } }
                    else if t == ID.crc { _ = try r.digests(n) }
                    else { throw AXError.corrupt("bad 7z pack info") }
                }
            case ID.unpackInfo:
                guard Int(try r.number()) == ID.folder else { throw AXError.corrupt("bad 7z unpack info") }
                let nf = Int(try r.number())
                guard try r.byte() == 0 else { throw AXError.unsupported("external 7z folder data") }
                si.folders = try (0..<nf).map { _ in try readFolder(&r) }
                guard Int(try r.number()) == ID.codersUnpackSize else { throw AXError.corrupt("bad 7z unpack info") }
                for i in 0..<nf {
                    si.folders[i].unpack = try (0..<si.folders[i].coders.reduce(0) { $0 + $1.numOut }).map { _ in try r.number() }
                }
                while true {
                    let t = Int(try r.number())
                    if t == ID.end { break }
                    if t == ID.crc { folderCRCs = try r.digests(nf); for i in 0..<nf { si.folders[i].crc = folderCRCs[i] } }
                    else { throw AXError.corrupt("bad 7z unpack info") }
                }
            case ID.subStreams:
                var counts = si.folders.map { _ in 1 }
                var t = Int(try r.number())
                if t == ID.numUnpackStream { counts = try si.folders.map { _ in Int(try r.number()) }; t = Int(try r.number()) }
                for i in 0..<si.folders.count { si.folders[i].numSub = counts[i] }
                si.subSizes = []
                for (i, f) in si.folders.enumerated() {
                    guard counts[i] > 0 else { si.subSizes.append([]); continue }
                    var sizes: [UInt64] = []
                    if t == ID.size {
                        var sum: UInt64 = 0
                        for _ in 0..<(counts[i] - 1) { let s = try r.number(); sizes.append(s); sum += s }
                        guard sum <= f.size else { throw AXError.corrupt("bad 7z substream sizes") }
                        sizes.append(f.size - sum)
                    } else { sizes = counts[i] == 1 ? [f.size] : [] }
                    si.subSizes.append(sizes)
                }
                if t == ID.size { t = Int(try r.number()) }
                // CRCs: streams whose folder already carries a CRC and has one stream are implicit
                var needCRC = 0
                for (i, f) in si.folders.enumerated() where !(f.numSub == 1 && f.crc != nil) { needCRC += counts[i] }
                var read: [UInt32?] = []
                while true {
                    if t == ID.end { break }
                    if t == ID.crc { read = try r.digests(needCRC) } else { _ = try r.bytes(Int(try r.number())) }
                    t = Int(try r.number())
                }
                var k = 0
                si.subCRCs = []
                for (i, f) in si.folders.enumerated() {
                    if f.numSub == 1 && f.crc != nil { si.subCRCs.append([f.crc]); continue }
                    var row: [UInt32?] = []
                    for _ in 0..<counts[i] { row.append(k < read.count ? read[k] : nil); k += 1 }
                    si.subCRCs.append(row)
                }
            default:
                throw AXError.corrupt("unknown 7z streams item \(id)")
            }
        }
    }

    private func readFolder(_ r: inout HReader) throws -> SZFolder {
        var f = SZFolder()
        let nc = Int(try r.number())
        guard nc > 0 && nc <= 32 else { throw AXError.corrupt("bad 7z coder count") }
        for _ in 0..<nc {
            let b = try r.byte()
            guard b & 0x80 == 0 else { throw AXError.unsupported("alternative 7z coder methods") }
            let idBytes = try r.bytes(b & 0x0f)
            var id: UInt64 = 0
            for x in idBytes { id = id << 8 | UInt64(x) }
            var nIn = 1, nOut = 1
            if b & 0x10 != 0 { nIn = Int(try r.number()); nOut = Int(try r.number()) }
            var props = Data()
            if b & 0x20 != 0 { props = try r.bytes(Int(try r.number())) }
            f.coders.append(SZCoder(id: id, numIn: nIn, numOut: nOut, props: props))
        }
        let totalIn = f.coders.reduce(0) { $0 + $1.numIn }, totalOut = f.coders.reduce(0) { $0 + $1.numOut }
        guard totalOut >= 1 else { throw AXError.corrupt("bad 7z folder") }
        for _ in 0..<(totalOut - 1) { f.bind.append((Int(try r.number()), Int(try r.number()))) }
        let numPacked = totalIn - f.bind.count
        guard numPacked >= 1 else { throw AXError.corrupt("bad 7z folder") }
        if numPacked == 1 {
            guard let i = (0..<totalIn).first(where: { i in !f.bind.contains { $0.inIdx == i } }) else { throw AXError.corrupt("bad 7z folder") }
            f.packed = [i]
        } else { f.packed = try (0..<numPacked).map { _ in Int(try r.number()) } }
        return f
    }

    private func readFiles(_ r: inout HReader) throws {
        let n = Int(try r.number())
        var list = [SZFile](repeating: SZFile(), count: n)
        var emptyStream = [Bool](repeating: false, count: n), emptyFile: [Bool] = []
        while true {
            let t = Int(try r.number())
            if t == ID.end { break }
            let size = Int(try r.number())
            let body = try r.bytes(size)
            var b = HReader(body)
            switch t {
            case ID.emptyStream: emptyStream = try b.bitVector(n)
            case ID.emptyFile: emptyFile = try b.bitVector(emptyStream.filter { $0 }.count)
            case ID.anti: _ = try b.bitVector(emptyStream.filter { $0 }.count)
            case ID.names:
                guard try b.byte() == 0 else { throw AXError.unsupported("external 7z names") }
                let raw = b.d.subdata(in: b.d.startIndex + b.p..<b.d.endIndex)
                var units = [UInt16](); var idx = 0
                for i in stride(from: 0, to: raw.count - 1, by: 2) {
                    let u = raw.le16(i)
                    if u == 0 { if idx < n { list[idx].name = String(decoding: units, as: UTF16.self) }; idx += 1; units = [] } else { units.append(u) }
                }
            case ID.mtime:
                let defined = try b.optionalBits(n)
                guard try b.byte() == 0 else { break }
                for i in 0..<n where defined[i] {
                    let ft = try b.u64()
                    list[i].mtime = Date(timeIntervalSince1970: Double(ft) / 10_000_000 - 11_644_473_600)
                }
            case ID.attributes:
                let defined = try b.optionalBits(n)
                guard try b.byte() == 0 else { break }
                for i in 0..<n where defined[i] { list[i].attrib = try b.u32() }
            default: break
            }
        }
        var si = 0, folder = 0, inFolder = 0
        var ei = 0
        for i in 0..<n {
            list[i].name = list[i].name.replacingOccurrences(of: "\\", with: "/")
            if emptyStream[i] {
                list[i].hasStream = false
                let isEmptyFile = ei < emptyFile.count ? emptyFile[ei] : false
                list[i].isDir = !isEmptyFile
                if let a = list[i].attrib, a & 0x10 != 0 { list[i].isDir = true }
                ei += 1
                continue
            }
            while folder < streams.folders.count && inFolder >= streams.folders[folder].numSub { folder += 1; inFolder = 0 }
            guard folder < streams.folders.count else { throw AXError.corrupt("7z file list does not match its streams") }
            list[i].folder = folder
            list[i].size = streams.subSizes[folder][inFolder]
            list[i].crc = streams.subCRCs[folder][inFolder]
            inFolder += 1; si += 1
        }
        files = list
    }

    // MARK: decoding

    private func packOffset(_ info: StreamsInfo, _ index: Int) -> UInt64 {
        32 + info.packPos + info.packSizes.prefix(index).reduce(0, +)
    }

    private func chain(folder f: SZFolder, info: StreamsInfo) throws -> ByteSource {
        var inBase = [Int](), outBase = [Int]()
        var ai = 0, ao = 0
        for c in f.coders { inBase.append(ai); outBase.append(ao); ai += c.numIn; ao += c.numOut }

        func inputFor(_ inStream: Int) throws -> ByteSource {
            if let bp = f.bind.first(where: { $0.inIdx == inStream }) { return try build(out: bp.outIdx) }
            guard let pi = f.packed.firstIndex(of: inStream), f.firstPack + pi < info.packSizes.count else { throw AXError.corrupt("bad 7z pack stream") }
            let idx = f.firstPack + pi
            guard packOffset(info, idx) + info.packSizes[idx] <= file.size else { throw AXError.corrupt("7z data out of range (truncated archive?)") }
            return RangeSource(file: file, offset: packOffset(info, idx), length: info.packSizes[idx])
        }

        func build(out: Int) throws -> ByteSource {
            guard let ci = (0..<f.coders.count).last(where: { outBase[$0] <= out }) else { throw AXError.corrupt("bad 7z folder graph") }
            let c = f.coders[ci]
            if c.id == Method.bcj2 {
                guard c.numIn == 4, c.numOut == 1 else { throw AXError.corrupt("bad BCJ2 coder") }
                return Bcj2Source(main: try inputFor(inBase[ci]), call: try inputFor(inBase[ci] + 1), jump: try inputFor(inBase[ci] + 2),
                                  rc: try inputFor(inBase[ci] + 3), outSize: f.unpack[out])
            }
            guard c.numIn == 1, c.numOut == 1 else { throw AXError.unsupported("7z method \(Method.name(c.id)) (multi-stream)") }
            let input = try inputFor(inBase[ci])
            let size = f.unpack[out]
            switch c.id {
            case Method.copy: return input
            case Method.lzma2:
                guard let p = c.props.first else { throw AXError.corrupt("missing LZMA2 properties") }
                return try Lzma2Source(input: input, dictProp: p, sizeHint: size)
            case Method.lzma: return try LzmaSource(input: input, props: c.props, unpackSize: size)
            case Method.bzip2: return try Bzip2Source(source: input)
            case Method.ppmd: return try PpmdSource(input: input, props: c.props, unpackSize: size)
            case Method.deflate: return InflateSource(input: input)
            case Method.bcjx86, Method.bcjx86Old: return FilterSource(input: input, filter: BCJx86())
            case Method.arm64: return FilterSource(input: input, filter: BCJARM64())
            case Method.armOld, Method.arm: return FilterSource(input: input, filter: BCJARM())
            case Method.ppc, Method.ppcOld: return FilterSource(input: input, filter: BCJPPC())
            case Method.ia64, Method.ia64Old: return FilterSource(input: input, filter: BCJIA64())
            case Method.armt, Method.armtOld: return FilterSource(input: input, filter: BCJARMT())
            case Method.sparc, Method.sparcOld: return FilterSource(input: input, filter: BCJSPARC())
            case Method.delta: return FilterSource(input: input, filter: DeltaFilter(distance: Int(c.props.first ?? 0) + 1))
            case Method.aes: return try SevenAESSource(input: input, props: c.props, password: password, unpackSize: size)
            default: throw AXError.unsupported("7z compression method “\(Method.name(c.id))”")
            }
        }
        return try build(out: f.mainOut)
    }

    // MARK: public API

    var listing: Listing {
        var l = Listing()
        var methods: [String] = []
        for f in streams.folders { for c in f.coders where c.id != Method.aes { let n = Method.name(c.id); if !methods.contains(n) { methods.append(n) } } }
        l.solid = streams.folders.contains { $0.numSub > 1 }
        l.totalPacked = Int64(streams.packSizes.reduce(0, +))
        l.headerEncrypted = headerEncrypted
        l.details = (["7Z"] + methods + (streams.folders.contains { $0.encrypted } ? ["AES-256"] : []) + (l.solid ? ["solid"] : []) + (headerEncrypted ? ["encrypted names"] : [])).joined(separator: " · ")
        l.entries = files.map { f in
            var packed: Int64 = 0
            if f.folder >= 0, streams.folders[f.folder].numSub == 1 {
                let fo = streams.folders[f.folder]
                packed = Int64(fo.packed.indices.reduce(UInt64(0)) { $0 + (fo.firstPack + $1 < streams.packSizes.count ? streams.packSizes[fo.firstPack + $1] : 0) })
            }
            let clean = SafePath.clean(f.name) ?? f.name
            return ArchiveEntry(path: clean, isDir: f.isDir, size: Int64(f.size), packed: packed,
                                ratio: (!f.isDir && f.size > 0 && packed > 0) ? "\(min(100, Int(Double(packed) / Double(f.size) * 100)))%" : "",
                                mtime: Dates.text(f.mtime), crc: f.crc.map { String(format: "%08X", $0) } ?? "",
                                attrs: "", encrypted: f.folder >= 0 && streams.folders[f.folder].encrypted)
        }
        return l
    }

    /// Runs through the archive. `visit` is called per file with the decoded bytes' source (nil for entries without data).
    private func walk(_ wanted: (SZFile) -> Bool, _ visit: (SZFile, ByteSource?) throws -> Void) throws {
        for f in files where !f.hasStream { if wanted(f) { try visit(f, nil) } }
        for (fi, folder) in streams.folders.enumerated() {
            try Task.checkCancellation()
            let members = files.filter { $0.folder == fi }
            guard members.contains(where: wanted) else { continue }
            let src = try chain(folder: folder, info: streams)
            for f in members {
                if wanted(f) { try visit(f, src) } else { try src.discard(f.size) }
            }
        }
    }

    private func copy(_ f: SZFile, from src: ByteSource, to sink: ByteSink, progress: ProgressTracker?) throws {
        var left = f.size
        var crc: UInt32 = 0
        do {
            while left > 0 {
                let d = try src.read(Int(min(left, 1 << 20)))
                if d.isEmpty { throw AXError.corrupt("“\(f.name)” ended unexpectedly") }
                left -= UInt64(d.count)
                crc = CRC32.update(crc, d)
                try sink.write(d)
                try progress?.add(d.count)
            }
        } catch let e as AXError {
            if streams.folders[f.folder].encrypted, case .corrupt = e { throw AXError.wrongPassword }
            throw e
        }
        if let want = f.crc, want != crc {
            throw streams.folders[f.folder].encrypted ? AXError.wrongPassword : AXError.corrupt("CRC mismatch in “\(f.name)”")
        }
    }

    func extract(to ex: Extractor, progress: ProgressTracker?) throws {
        try walk({ f in
            guard let clean = SafePath.clean(f.name) else { _ = try? ex.destination(for: f.name, isDir: f.isDir); return false }
            return ex.isSelected(clean)
        }) { f, src in
            if f.isDir {
                if ex.keepPaths, let u = try ex.destination(for: f.name, isDir: true) {
                    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
                    ex.finalize(u, mode: f.unixMode, mtime: f.mtime)
                }
                return
            }
            guard let src else {                                           // empty file
                if let u = try ex.destination(for: f.name, isDir: false) { _ = try FileOut(u); ex.finalize(u, mode: f.unixMode, mtime: f.mtime) }
                return
            }
            if f.isSymlink {
                let sink = MemorySink(); try copy(f, from: src, to: sink, progress: nil)
                if let u = try ex.destination(for: f.name, isDir: false), let t = String(data: sink.data, encoding: .utf8) { ex.makeSymlink(at: u, target: t) }
                return
            }
            guard let u = try ex.destination(for: f.name, isDir: false) else { try src.discard(f.size); return }
            let out = try FileOut(u)
            do { try copy(f, from: src, to: out, progress: progress) } catch { try? FileManager.default.removeItem(at: u); throw error }
            ex.finalize(u, mode: f.unixMode, mtime: f.mtime)
        }
    }

    func test(progress: ProgressTracker?) throws {
        try walk({ _ in true }) { f, src in
            guard let src, !f.isDir else { return }
            try copy(f, from: src, to: NullSink(), progress: progress)
        }
    }

    /// Streams every kept file through `emit` (used to rebuild an archive when editing).
    func rebuild(keep: (SZFile) -> Bool, emit: (SZFile, ByteSource?) throws -> Void) throws {
        try walk({ keep($0) }, emit)
    }
}

// MARK: - Writer

final class SevenZipWriter {
    struct Options { var level = 5; var solid = true; var password: String?; var encryptHeader = false; var totalHint: UInt64? }

    private struct Entry { var name: String; var mtime: Date; var attrib: UInt32; var hasStream: Bool; var isEmptyFile: Bool; var size: UInt64; var crc: UInt32 }
    private struct FolderInfo { var coders: Data; var numCoders: Int; var unpackSizes: [UInt64]; var packSize: UInt64; var bind: Data; var numSub: Int; var subSizes: [UInt64] }

    private let out: FileOut
    private let opt: Options
    private var entries: [Entry] = []
    private var folders: [FolderInfo] = []
    private var packSizes: [UInt64] = []

    // open folder state
    private var lzma: ByteSink?
    private var lzmaCount: CountingSink?
    private var packCount: CountingSink?
    private var aes: SevenAESSink?
    private var folderUnpack: UInt64 = 0
    private var folderSubSizes: [UInt64] = []
    private var folderHasLzma = false

    init(url: URL, options: Options) throws {
        out = try FileOut(url)
        opt = options
        try out.write(Data(count: 32))
    }

    private func attrib(mode: UInt32, dir: Bool) -> UInt32 { (dir ? 0x10 : 0x20) | 0x8000 | ((mode & 0o7777 | (dir ? 0o040000 : 0o100000)) << 16) }

    func addDirectory(name: String, mtime: Date, mode: UInt32) {
        entries.append(Entry(name: name, mtime: mtime, attrib: attrib(mode: mode, dir: true), hasStream: false, isEmptyFile: false, size: 0, crc: 0))
    }

    private func openFolder() throws {
        packCount = CountingSink(out)
        var tail: ByteSink = packCount!
        if let pw = opt.password, !pw.isEmpty { let a = try SevenAESSink(out: tail, password: pw); aes = a; tail = a }
        lzmaCount = CountingSink(tail)
        if opt.level == 0 { lzma = lzmaCount; folderHasLzma = false }
        else {
            let lv = min(max(opt.level, 1), 5)
            let dict = [0, 1 << 18, 1 << 20, 1 << 22, 1 << 24, 1 << 25][lv]
            lzma = Lzma2Sink(out: lzmaCount!, dictSize: dict, level: lv, totalHint: opt.totalHint)
            folderHasLzma = true
        }
        folderUnpack = 0; folderSubSizes = []
    }

    private func closeFolder() throws {
        guard let l = lzma else { return }
        try l.finish()
        try aes?.finish()
        let packSize = packCount!.count
        let compSize = lzmaCount!.count
        var coders = Data(); var n = 0
        var bind = Data(); var unpack: [UInt64] = []
        func coder(id: [UInt8], props: Data) {
            coders.append(UInt8(id.count) | (props.isEmpty ? 0 : 0x20)); coders.append(contentsOf: id)
            if !props.isEmpty { put7z(UInt64(props.count), &coders); coders.append(props) }
            n += 1
        }
        if folderHasLzma {
            coder(id: [0x21], props: Data([(l as! Lzma2Sink).dictProp])); unpack.append(folderUnpack)
            if let a = aes { coder(id: [0x06, 0xf1, 0x07, 0x01], props: a.props); unpack.append(compSize); put7z(0, &bind); put7z(1, &bind) }
        } else if let a = aes {
            coder(id: [0x00], props: Data()); unpack.append(folderUnpack)
            coder(id: [0x06, 0xf1, 0x07, 0x01], props: a.props); unpack.append(compSize); put7z(0, &bind); put7z(1, &bind)
        } else { coder(id: [0x00], props: Data()); unpack.append(folderUnpack) }
        folders.append(FolderInfo(coders: coders, numCoders: n, unpackSizes: unpack, packSize: packSize, bind: bind,
                                  numSub: folderSubSizes.count, subSizes: folderSubSizes))
        packSizes.append(packSize)
        lzma = nil; lzmaCount = nil; packCount = nil; aes = nil
    }

    /// Adds a file; `feed` must push exactly `size` bytes into the sink it is given.
    func addFile(name: String, size: UInt64, mtime: Date, mode: UInt32, symlink: Bool = false, feed: (ByteSink) throws -> Void) throws {
        let at = (symlink ? 0o120000 : 0o100000) | (mode & 0o7777)
        let attr: UInt32 = 0x20 | 0x8000 | (at << 16)
        guard size > 0 else {
            entries.append(Entry(name: name, mtime: mtime, attrib: attr, hasStream: false, isEmptyFile: true, size: 0, crc: 0)); return
        }
        if lzma == nil { try openFolder() }
        let crcSink = CRCSink(out: lzma!)
        try feed(crcSink)
        guard crcSink.count == size else { throw AXError.io("“\(name)” changed while it was being archived.") }
        folderUnpack += size; folderSubSizes.append(size)
        entries.append(Entry(name: name, mtime: mtime, attrib: attr, hasStream: true, isEmptyFile: false, size: size, crc: crcSink.crc))
        if !opt.solid { try closeFolder() }
    }

    func finish() throws {
        try closeFolder()
        var h = Data([UInt8(ID.header)])
        if !folders.isEmpty {
            h.append(UInt8(ID.mainStreams))
            h.append(UInt8(ID.packInfo)); put7z(0, &h); put7z(UInt64(folders.count), &h)
            h.append(UInt8(ID.size)); for s in packSizes { put7z(s, &h) }; h.append(0)
            h.append(UInt8(ID.unpackInfo)); h.append(UInt8(ID.folder)); put7z(UInt64(folders.count), &h); h.append(0)
            for f in folders { put7z(UInt64(f.numCoders), &h); h.append(f.coders); h.append(f.bind) }
            h.append(UInt8(ID.codersUnpackSize)); for f in folders { for u in f.unpackSizes { put7z(u, &h) } }
            h.append(0)
            h.append(UInt8(ID.subStreams))
            if folders.contains(where: { $0.numSub != 1 }) { h.append(UInt8(ID.numUnpackStream)); for f in folders { put7z(UInt64(f.numSub), &h) } }
            if folders.contains(where: { $0.numSub > 1 }) {
                h.append(UInt8(ID.size)); for f in folders where f.numSub > 1 { for s in f.subSizes.dropLast() { put7z(s, &h) } }
            }
            h.append(UInt8(ID.crc)); h.append(1)
            for e in entries where e.hasStream { h.put32(e.crc) }
            h.append(0); h.append(0)
        }
        if !entries.isEmpty {
            h.append(UInt8(ID.filesInfo)); put7z(UInt64(entries.count), &h)
            let emptyStream = entries.map { !$0.hasStream }
            if emptyStream.contains(true) {
                var b = Data(); putBits(emptyStream, &b)
                h.append(UInt8(ID.emptyStream)); put7z(UInt64(b.count), &h); h.append(b)
                let ef = entries.filter { !$0.hasStream }.map { $0.isEmptyFile }
                if ef.contains(true) { var e = Data(); putBits(ef, &e); h.append(UInt8(ID.emptyFile)); put7z(UInt64(e.count), &h); h.append(e) }
            }
            var names = Data([0])
            for e in entries { for u in e.name.utf16 { names.put16(u) }; names.put16(0) }
            h.append(UInt8(ID.names)); put7z(UInt64(names.count), &h); h.append(names)
            var times = Data([1, 0])
            for e in entries { times.put64(UInt64((e.mtime.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)) }
            h.append(UInt8(ID.mtime)); put7z(UInt64(times.count), &h); h.append(times)
            var attrs = Data([1, 0])
            for e in entries { attrs.put32(e.attrib) }
            h.append(UInt8(ID.attributes)); put7z(UInt64(attrs.count), &h); h.append(attrs)
            h.append(0)
        }
        h.append(0)

        // compress (and optionally encrypt) the header itself
        let headerStart = out.position
        var next = h
        if !entries.isEmpty {
            let packCount = CountingSink(out)
            var tail: ByteSink = packCount
            var aesProps: Data?
            if opt.encryptHeader, let pw = opt.password, !pw.isEmpty { let a = try SevenAESSink(out: tail, password: pw); aesProps = a.props; tail = a }
            let lc = CountingSink(tail)
            let l = Lzma2Sink(out: lc, dictSize: 1 << 20, level: 3, totalHint: UInt64(h.count))
            try l.write(h); try l.finish()
            if let a = tail as? SevenAESSink { try a.finish() }
            var e = Data([UInt8(ID.encodedHeader)])
            e.append(UInt8(ID.packInfo)); put7z(headerStart - 32, &e); put7z(1, &e)
            e.append(UInt8(ID.size)); put7z(packCount.count, &e); e.append(0)
            e.append(UInt8(ID.unpackInfo)); e.append(UInt8(ID.folder)); put7z(1, &e); e.append(0)
            if let ap = aesProps {
                put7z(2, &e)                                                     // two coders: LZMA2, then AES
                e.append(0x21); e.append(0x21); put7z(1, &e); e.append(l.dictProp)
                e.append(0x24); e.append(contentsOf: [0x06, 0xf1, 0x07, 0x01]); put7z(UInt64(ap.count), &e); e.append(ap)
                put7z(0, &e); put7z(1, &e)                                        // bind: LZMA2 input <- AES output
                e.append(UInt8(ID.codersUnpackSize)); put7z(UInt64(h.count), &e); put7z(lc.count, &e)
            } else {
                put7z(1, &e)
                e.append(0x21); e.append(0x21); put7z(1, &e); e.append(l.dictProp)
                e.append(UInt8(ID.codersUnpackSize)); put7z(UInt64(h.count), &e)
            }
            e.append(UInt8(ID.crc)); e.append(1); e.put32(CRC32.update(0, h))
            e.append(0); e.append(0)
            next = e
        }
        let nextOffset = out.position - 32
        try out.write(next)

        var sh = Data([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4])
        var start = Data()
        start.put64(nextOffset); start.put64(UInt64(next.count)); start.put32(CRC32.update(0, next))
        sh.put32(CRC32.update(0, start)); sh.append(start)
        try out.write(at: 0, sh)
    }
}

final class CRCSink: ByteSink {
    private let out: ByteSink
    private(set) var crc: UInt32 = 0
    private(set) var count: UInt64 = 0
    init(out: ByteSink) { self.out = out }
    func write(_ data: Data) throws { crc = CRC32.update(crc, data); count += UInt64(data.count); try out.write(data) }
    func finish() throws {}
}
