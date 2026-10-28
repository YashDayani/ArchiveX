import Foundation
import CryptoKit

// .xz container (spec: tukaani.org/xz/xz-file-format): LZMA2 blocks, optional BCJ/Delta filters,
// CRC32 / CRC64 / SHA-256 integrity checks, multiple blocks and concatenated streams.

enum CRC64 {
    private static let table: [UInt64] = (0..<256).map { i -> UInt64 in
        var c = UInt64(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xC96C_5795_D787_0F42 ^ (c >> 1) : c >> 1 }
        return c
    }
    static func update(_ crc: UInt64, _ data: Data) -> UInt64 {
        var c = ~crc
        data.withUnsafeBytes { raw in
            table.withUnsafeBufferPointer { t in
                for b in raw.bindMemory(to: UInt8.self) { c = t[Int((c ^ UInt64(b)) & 0xff)] ^ (c >> 8) }
            }
        }
        return ~c
    }
}

private func varint(_ data: Data, _ pos: inout Int) throws -> UInt64 {
    var v: UInt64 = 0, shift: UInt64 = 0
    while true {
        guard pos < data.count, shift < 63 else { throw AXError.corrupt("bad xz number") }
        let b = data[data.startIndex + pos]; pos += 1
        v |= UInt64(b & 0x7f) << shift
        if b & 0x80 == 0 { return v }
        shift += 7
    }
}

private func putVarint(_ v: UInt64, _ d: inout Data) {
    var x = v
    while x >= 0x80 { d.append(UInt8(x & 0x7f) | 0x80); x >>= 7 }
    d.append(UInt8(x))
}

/// Counts bytes passing through to another sink.
final class CountingSink: ByteSink {
    let out: ByteSink
    private(set) var count: UInt64 = 0
    init(_ out: ByteSink) { self.out = out }
    func write(_ data: Data) throws { count += UInt64(data.count); try out.write(data) }
    func finish() throws {}
}

// MARK: - Reader

final class XzSource: ByteSource {
    private let src: FileSource
    private let file: FileIn
    private var checkType = 0
    private var block: ByteSource?
    private var blockIsLzma2: Lzma2Source?
    private var crc32: UInt32 = 0
    private var crc64: UInt64 = 0
    private var sha = SHA256()
    private var produced: UInt64 = 0
    private var blockHeaderSize = 0
    private var expectedUnpadded: UInt64?
    private var eof = false
    private var records: [(unpadded: UInt64, size: UInt64)] = []

    init(file: FileIn) throws {
        self.file = file
        src = FileSource(file)
        try startStream(first: true)
    }

    private func startStream(first: Bool) throws {
        // optional stream padding between streams: zero bytes in multiples of 4
        var h = try src.readUpTo(12)
        if !first {
            if h.isEmpty { eof = true; return }
            while h.count >= 4 && h.prefix(4).allSatisfy({ $0 == 0 }) {
                h = h.dropFirst(4) + (try src.readUpTo(4))
                if h.isEmpty { eof = true; return }
            }
        }
        guard h.count == 12, Array(h.prefix(6)) == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] else {
            if first { throw AXError.corrupt("not an xz file") }
            eof = true; return
        }
        guard CRC32.update(0, h.subdata(in: h.startIndex + 6..<h.startIndex + 8)) == h.le32(8) else { throw AXError.corrupt("xz header CRC mismatch") }
        checkType = Int(h[h.startIndex + 7] & 0x0f)
        records = []
        try openNextBlock()
    }

    private func checkSize() -> Int { switch checkType { case 0: return 0; case 1: return 4; case 4: return 8; case 10: return 32; default: return [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64][checkType] } }

    private func makeFilter(_ id: UInt64, _ props: Data) throws -> StreamFilter {
        switch id {
        case 0x04: return BCJx86()
        case 0x07: return BCJARM()
        case 0x0a: return BCJARM64()
        case 0x03: return DeltaFilter(distance: Int(props.first ?? 0) + 1)
        default: throw AXError.unsupported("xz filter \(String(id, radix: 16))")
        }
    }

    private func openNextBlock() throws {
        let first = try src.readExactly(1)[0]
        if first == 0 { try finishStream(); return }                     // index indicator
        let headerSize = (Int(first) + 1) * 4
        var h = Data([first]); h.append(try src.readExactly(headerSize - 1))
        guard CRC32.update(0, h.prefix(headerSize - 4)) == h.le32(headerSize - 4) else { throw AXError.corrupt("xz block header CRC mismatch") }
        var p = 1
        let flags = h[1]; p = 2
        let nFilters = Int(flags & 3) + 1
        var compSize: UInt64?, uncSize: UInt64?
        if flags & 0x40 != 0 { compSize = try varint(h, &p) }
        if flags & 0x80 != 0 { uncSize = try varint(h, &p) }
        var filters: [(UInt64, Data)] = []
        for _ in 0..<nFilters {
            let id = try varint(h, &p), ps = Int(try varint(h, &p))
            guard p + ps <= headerSize - 4 else { throw AXError.corrupt("bad xz filter") }
            filters.append((id, h.subdata(in: h.startIndex + p..<h.startIndex + p + ps))); p += ps
        }
        guard let last = filters.last, last.0 == 0x21, last.1.count == 1 else { throw AXError.unsupported("xz block without LZMA2") }
        blockHeaderSize = headerSize
        blockStartPos = src.position - UInt64(headerSize)
        let lz = try Lzma2Source(input: src, dictProp: last.1[last.1.startIndex], sizeHint: uncSize)
        var chain: ByteSource = lz
        for f in filters.dropLast().reversed() { chain = FilterSource(input: chain, filter: try makeFilter(f.0, f.1)) }
        block = chain; blockIsLzma2 = lz
        crc32 = 0; crc64 = 0; sha = SHA256(); produced = 0
        _ = compSize
    }
    private var blockStartPos: UInt64 = 0

    private func closeBlock() throws {
        // LZMA2 consumed its end marker; align to 4 then verify the check
        let used = src.position - blockStartPos
        let pad = Int((4 - used % 4) % 4)
        if pad > 0 { let z = try src.readExactly(pad); guard z.allSatisfy({ $0 == 0 }) else { throw AXError.corrupt("bad xz block padding") } }
        let cs = checkSize()
        let check = cs > 0 ? try src.readExactly(cs) : Data()
        switch checkType {
        case 1: guard check.le32(0) == crc32 else { throw AXError.corrupt("xz CRC32 mismatch") }
        case 4: guard check.le64(0) == crc64 else { throw AXError.corrupt("xz CRC64 mismatch") }
        case 10: guard Data(sha.finalize()) == check else { throw AXError.corrupt("xz SHA-256 mismatch") }
        default: break
        }
        records.append((used + UInt64(cs), produced))
        block = nil; blockIsLzma2 = nil
        try openNextBlock()
    }

    private func finishStream() throws {
        // index (indicator already read): count, records, padding, CRC32; then 12-byte footer
        var idx = Data([0])
        func readVar() throws -> UInt64 {
            var v: UInt64 = 0, shift: UInt64 = 0
            while true {
                let b = try src.readExactly(1)[0]; idx.append(b)
                v |= UInt64(b & 0x7f) << shift
                if b & 0x80 == 0 { return v }
                shift += 7
                guard shift < 63 else { throw AXError.corrupt("bad xz index") }
            }
        }
        let n = try readVar()
        for _ in 0..<n { _ = try readVar(); _ = try readVar() }
        let pad = (4 - idx.count % 4) % 4
        if pad > 0 { idx.append(try src.readExactly(pad)) }
        let crc = try src.readExactly(4)
        guard crc.le32(0) == CRC32.update(0, idx) else { throw AXError.corrupt("xz index CRC mismatch") }
        guard n == UInt64(records.count) else { throw AXError.corrupt("xz index does not match the blocks") }
        let footer = try src.readExactly(12)
        guard footer[footer.startIndex + 10] == 0x59, footer[footer.startIndex + 11] == 0x5a else { throw AXError.corrupt("bad xz footer") }
        try startStream(first: false)
    }

    func read(_ n: Int) throws -> Data {
        while !eof {
            guard let b = block else { return Data() }
            let d = try b.read(n)
            if !d.isEmpty {
                produced += UInt64(d.count)
                switch checkType {
                case 1: crc32 = CRC32.update(crc32, d)
                case 4: crc64 = CRC64.update(crc64, d)
                case 10: sha.update(data: d)
                default: break
                }
                return d
            }
            try closeBlock()
        }
        return Data()
    }
    func skip(_ n: UInt64) throws { try discard(n) }

    /// Total uncompressed size from the stream index (single-stream files).
    static func recordedSize(of file: FileIn) -> UInt64? {
        guard file.size >= 32, let f = try? file.readExactly(at: file.size - 12, 12), f[f.startIndex + 10] == 0x59 else { return nil }
        let back = (UInt64(f.le32(4)) + 1) * 4
        guard back + 12 < file.size, let idx = try? file.readExactly(at: file.size - 12 - back, Int(back)), idx.first == 0 else { return nil }
        var p = 1
        guard let n = try? varint(idx, &p) else { return nil }
        var total: UInt64 = 0
        for _ in 0..<n { guard (try? varint(idx, &p)) != nil, let u = try? varint(idx, &p) else { return nil }; total += u }
        return total
    }
}

extension FileSource {
    /// Bytes consumed so far from the start of the file.
    var position: UInt64 { pos }
}

// MARK: - Writer

final class XzSink: ByteSink {
    private let out: ByteSink
    private let level: Int
    private let totalHint: UInt64?
    private var counting: CountingSink
    private var lzma: Lzma2Sink?
    private var crc: UInt64 = 0
    private var size: UInt64 = 0
    private let dict: Int

    init(out: ByteSink, level: Int, totalHint: UInt64?) throws {
        self.out = out; self.level = level; self.totalHint = totalHint
        counting = CountingSink(out)
        dict = [1 << 18, 1 << 20, 1 << 22, 1 << 23, 1 << 24, 1 << 25][min(max(level, 0), 5)]
        var h = Data([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04])
        h.put32(CRC32.update(0, Data([0x00, 0x04])))
        try out.write(h)
    }

    private func startBlock() throws {
        let l = Lzma2Sink(out: counting, dictSize: dict, level: level, totalHint: totalHint)
        lzma = l
        var hdr = Data([0x02, 0x00, 0x21, 0x01, l.dictProp, 0, 0, 0])
        hdr.put32(CRC32.update(0, hdr))
        try out.write(hdr)
    }

    func write(_ data: Data) throws {
        if lzma == nil { try startBlock() }
        crc = CRC64.update(crc, data); size += UInt64(data.count)
        try lzma!.write(data)
    }

    func finish() throws {
        var records = Data()
        var unpadded: UInt64 = 0
        if let l = lzma {
            try l.finish()
            let comp = counting.count
            let pad = Int((4 - comp % 4) % 4)
            if pad > 0 { try out.write(Data(count: pad)) }
            var c = Data(); c.put64(crc); try out.write(c)
            unpadded = 12 + comp + 8
            putVarint(unpadded, &records); putVarint(size, &records)
        }
        var idx = Data([0])
        putVarint(lzma == nil ? 0 : 1, &idx); idx.append(records)
        while idx.count % 4 != 0 { idx.append(0) }
        idx.put32(CRC32.update(0, idx))
        try out.write(idx)
        var f = Data()
        var tail = Data(); tail.put32(UInt32(idx.count / 4 - 1)); tail.append(contentsOf: [0x00, 0x04])
        f.put32(CRC32.update(0, tail)); f.append(tail); f.append(contentsOf: [0x59, 0x5a])
        try out.write(f)
    }
}
