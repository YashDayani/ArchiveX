import Foundation

// Zstandard (RFC 8878) decoder, written from the format specification: frames, raw/RLE/compressed blocks, Huffman-coded
// literals (1 or 4 streams), FSE-coded sequences, repeat offsets and the optional xxHash64 content checksum.
// Dictionaries are not supported.

// MARK: - xxHash64 (only for the frame checksum)

struct XXH64 {
    private static let p1: UInt64 = 11400714785074694791, p2: UInt64 = 14029467366897019727, p3: UInt64 = 1609587929392839161
    private static let p4: UInt64 = 9650029242287828579, p5: UInt64 = 2870177450012600261
    private var v1: UInt64 = 0 &+ p1 &+ p2, v2: UInt64 = p2, v3: UInt64 = 0, v4: UInt64 = 0 &- p1
    private var total: UInt64 = 0
    private var buf = [UInt8]()

    @inline(__always) private static func rotl(_ x: UInt64, _ r: UInt64) -> UInt64 { (x << r) | (x >> (64 - r)) }
    @inline(__always) private static func round(_ acc: UInt64, _ input: UInt64) -> UInt64 { rotl(acc &+ input &* p2, 31) &* p1 }
    @inline(__always) private static func merge(_ acc: UInt64, _ v: UInt64) -> UInt64 { (acc ^ round(0, v)) &* p1 &+ p4 }
    @inline(__always) private static func le64(_ b: [UInt8], _ o: Int) -> UInt64 { (0..<8).reduce(UInt64(0)) { $0 | UInt64(b[o + $1]) << UInt64(8 * $1) } }
    @inline(__always) private static func le32(_ b: [UInt8], _ o: Int) -> UInt64 { (0..<4).reduce(UInt64(0)) { $0 | UInt64(b[o + $1]) << UInt64(8 * $1) } }

    mutating func update(_ data: Data) {
        total &+= UInt64(data.count)
        buf.append(contentsOf: data)
        var o = 0
        while buf.count - o >= 32 {
            v1 = XXH64.round(v1, XXH64.le64(buf, o)); v2 = XXH64.round(v2, XXH64.le64(buf, o + 8))
            v3 = XXH64.round(v3, XXH64.le64(buf, o + 16)); v4 = XXH64.round(v4, XXH64.le64(buf, o + 24))
            o += 32
        }
        if o > 0 { buf.removeFirst(o) }
    }

    func digest() -> UInt64 {
        var h: UInt64
        if total >= 32 {
            h = XXH64.rotl(v1, 1) &+ XXH64.rotl(v2, 7) &+ XXH64.rotl(v3, 12) &+ XXH64.rotl(v4, 18)
            h = XXH64.merge(h, v1); h = XXH64.merge(h, v2); h = XXH64.merge(h, v3); h = XXH64.merge(h, v4)
        } else { h = XXH64.p5 }
        h &+= total
        var o = 0
        while buf.count - o >= 8 { h ^= XXH64.round(0, XXH64.le64(buf, o)); h = XXH64.rotl(h, 27) &* XXH64.p1 &+ XXH64.p4; o += 8 }
        if buf.count - o >= 4 { h ^= XXH64.le32(buf, o) &* XXH64.p1; h = XXH64.rotl(h, 23) &* XXH64.p2 &+ XXH64.p3; o += 4 }
        while o < buf.count { h ^= UInt64(buf[o]) &* XXH64.p5; h = XXH64.rotl(h, 11) &* XXH64.p1; o += 1 }
        h ^= h >> 33; h = h &* XXH64.p2; h ^= h >> 29; h = h &* XXH64.p3; h ^= h >> 32
        return h
    }
}

// MARK: - bit readers

/// Reads a buffer from its end towards its start (the way Huffman and sequence data are stored).
private struct BackBits {
    let d: [UInt8]
    var pos: Int                 // index of the next bit to read; -1 once everything has been read

    init(_ bytes: [UInt8]) throws {
        d = bytes
        guard let last = bytes.last, last != 0 else { throw AXError.corrupt("bad Zstandard bitstream") }
        pos = (bytes.count - 1) * 8 + (7 - last.leadingZeroBitCount) - 1
    }
    var overflow: Bool { pos < -1 }

    @inline(__always) private func load64(_ b: Int) -> UInt64 {
        var r: UInt64 = 0
        for i in 0..<8 where b + i < d.count && b + i >= 0 { r |= UInt64(d[b + i]) << UInt64(8 * i) }
        return r
    }
    /// Bits [lo, lo+n) as a number (bits below the start read as zero).
    @inline(__always) func peek(at lo: Int, _ n: Int) -> Int {
        let r: UInt64 = lo >= 0 ? load64(lo >> 3) >> UInt64(lo & 7) : load64(0) << UInt64(-lo)
        return Int(r & ((UInt64(1) << UInt64(n)) - 1))
    }
    @inline(__always) mutating func read(_ n: Int) -> Int {
        if n == 0 { return 0 }
        pos -= n
        return peek(at: pos + 1, n)
    }
}

/// Reads forward, least significant bit first (used for FSE table descriptions).
private struct FwdBits {
    let d: [UInt8]
    var bit = 0
    func peek(_ n: Int) -> Int {
        var r: UInt64 = 0
        let b = bit >> 3
        for i in 0..<8 where b + i < d.count { r |= UInt64(d[b + i]) << UInt64(8 * i) }
        return Int((r >> UInt64(bit & 7)) & ((UInt64(1) << UInt64(n)) - 1))
    }
    mutating func skip(_ n: Int) { bit += n }
    var bytesUsed: Int { (bit + 7) >> 3 }
    var overrun: Bool { (bit + 7) >> 3 > d.count }
}

// MARK: - FSE

private struct FSETable {
    var accLog = 0
    var symbol = [UInt8]()
    var nbBits = [UInt8]()
    var newState = [UInt16]()

    static func rle(_ s: UInt8) -> FSETable { FSETable(accLog: 0, symbol: [s], nbBits: [0], newState: [0]) }

    init(accLog: Int, symbol: [UInt8], nbBits: [UInt8], newState: [UInt16]) { self.accLog = accLog; self.symbol = symbol; self.nbBits = nbBits; self.newState = newState }

    init(counts: [Int], accLog: Int) throws {
        self.accLog = accLog
        let size = 1 << accLog
        var sym = [UInt8](repeating: 0, count: size)
        var next = [Int](repeating: 0, count: counts.count)
        var high = size - 1
        for (s, c) in counts.enumerated() where c == -1 { sym[high] = UInt8(s); high -= 1; next[s] = 1 }
        let step = (size >> 1) + (size >> 3) + 3
        var pos = 0
        for (s, c) in counts.enumerated() where c > 0 {
            next[s] = c
            for _ in 0..<c {
                sym[pos] = UInt8(s)
                repeat { pos = (pos + step) & (size - 1) } while pos > high
            }
        }
        guard pos == 0 else { throw AXError.corrupt("bad Zstandard FSE table") }
        var nb = [UInt8](repeating: 0, count: size), ns = [UInt16](repeating: 0, count: size)
        for u in 0..<size {
            let s = Int(sym[u])
            let n = next[s]; next[s] += 1
            let bits = accLog - (Int.bitWidth - 1 - n.leadingZeroBitCount)
            nb[u] = UInt8(bits); ns[u] = UInt16((n << bits) - size)
        }
        symbol = sym; nbBits = nb; newState = ns
    }

    /// Reads a table description; returns the table and the number of bytes used.
    static func read(_ data: [UInt8], maxSymbol: Int, maxLog: Int) throws -> (FSETable, Int) {
        var r = FwdBits(d: data)
        let accLog = r.peek(4) + 5
        r.skip(4)
        guard accLog <= maxLog else { throw AXError.corrupt("Zstandard FSE accuracy too large") }
        var remaining = (1 << accLog) + 1
        var threshold = 1 << accLog
        var nb = accLog + 1
        var counts = [Int]()
        var previousZero = false
        while remaining > 1 && counts.count <= maxSymbol {
            if previousZero {
                var n = 0
                while true { let v = r.peek(2); r.skip(2); n += v; if v != 3 { break }; if r.overrun { throw AXError.corrupt("bad Zstandard FSE table") } }
                counts.append(contentsOf: [Int](repeating: 0, count: n))
                if counts.count > maxSymbol + 1 { throw AXError.corrupt("bad Zstandard FSE table") }
                previousZero = false
                continue
            }
            let max = (2 * threshold - 1) - remaining
            var count: Int
            let low = r.peek(nb - 1)
            if low < max { count = low; r.skip(nb - 1) }
            else {
                count = r.peek(nb); r.skip(nb)
                if count >= threshold { count -= max }
            }
            count -= 1
            remaining -= count < 0 ? -count : count
            counts.append(count)
            previousZero = count == 0
            while remaining < threshold && threshold > 1 { nb -= 1; threshold >>= 1 }
            if r.overrun { throw AXError.corrupt("bad Zstandard FSE table") }
        }
        guard remaining == 1, counts.count <= maxSymbol + 1 else { throw AXError.corrupt("bad Zstandard FSE table") }
        return (try FSETable(counts: counts, accLog: accLog), r.bytesUsed)
    }
}

// MARK: - Huffman

private struct HuffTable {
    var maxBits = 0
    var symbol = [UInt8]()
    var bits = [UInt8]()

    init() {}
    init(weights w: [Int]) throws {
        // the last weight is implied: the total must become a power of two
        var sum = 0
        for x in w where x > 0 { sum += 1 << (x - 1) }
        guard sum > 0 else { throw AXError.corrupt("bad Zstandard Huffman table") }
        let top = Int.bitWidth - 1 - sum.leadingZeroBitCount
        let total = 1 << (top + 1)
        let left = total - sum
        guard left > 0, left & (left - 1) == 0 else { throw AXError.corrupt("bad Zstandard Huffman table") }
        var weights = w
        weights.append(Int.bitWidth - 1 - left.leadingZeroBitCount + 1)
        maxBits = Int.bitWidth - 1 - total.leadingZeroBitCount
        guard maxBits <= 11, weights.count <= 256 else { throw AXError.corrupt("bad Zstandard Huffman table") }
        symbol = [UInt8](repeating: 0, count: 1 << maxBits)
        bits = [UInt8](repeating: 0, count: 1 << maxBits)
        var pos = 0
        for wt in 1...maxBits {
            for (s, x) in weights.enumerated() where x == wt {
                let span = 1 << (wt - 1)
                for k in 0..<span { symbol[pos + k] = UInt8(s); bits[pos + k] = UInt8(maxBits + 1 - wt) }
                pos += span
            }
        }
        guard pos == 1 << maxBits else { throw AXError.corrupt("bad Zstandard Huffman table") }
    }

    func decode(_ stream: [UInt8], count: Int, into out: inout [UInt8]) throws {
        var r = try BackBits(stream)
        for _ in 0..<count {
            let i = r.peek(at: r.pos - maxBits + 1, maxBits)
            out.append(symbol[i])
            r.pos -= Int(bits[i])
            if r.overflow { throw AXError.corrupt("damaged Zstandard literals") }
        }
        guard r.pos == -1 else { throw AXError.corrupt("damaged Zstandard literals") }
    }
}

// MARK: - the decoder

final class ZstdSource: ByteSource {
    private static let llDefault = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1]
    private static let mlDefault = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1]
    private static let ofDefault = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]
    private static let llBase = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    private static let llBits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    private static let mlBase = (0..<32).map { $0 + 3 } + [35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539]
    private static let mlBits = [Int](repeating: 0, count: 32) + [1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    private static let llTable = try! FSETable(counts: llDefault, accLog: 6)
    private static let mlTable = try! FSETable(counts: mlDefault, accLog: 6)
    private static let ofTable = try! FSETable(counts: ofDefault, accLog: 5)

    private let input: ByteSource
    private var inBuf = [UInt8]()
    private var inPos = 0
    private var eof = false

    private var out = [UInt8]()              // decoded data not yet returned, preceded by the window of history
    private var outHead = 0                  // start of the not-yet-returned data
    private var finished = false
    private var inFrame = false
    private var lastBlock = false
    private var windowSize = 0
    private var contentSize: UInt64?
    private var frameProduced: UInt64 = 0
    private var frameBase = 0                // where this frame's own history starts in `out`
    private var checksum: XXH64?
    private var wantChecksum = false

    private var huff: HuffTable?
    private var llT = ZstdSource.llTable, mlT = ZstdSource.mlTable, ofT = ZstdSource.ofTable
    private var rep = [1, 4, 8]

    init(input: ByteSource) { self.input = input }
    convenience init(file: FileIn) throws { self.init(input: FileSource(file)) }

    // MARK: input

    private func need(_ n: Int) throws -> Bool {
        while inBuf.count - inPos < n && !eof {
            let d = try input.read(1 << 18)
            if d.isEmpty { eof = true; break }
            if inPos > 1 << 20 { inBuf.removeFirst(inPos); inPos = 0 }
            inBuf.append(contentsOf: d)
        }
        return inBuf.count - inPos >= n
    }
    private func take(_ n: Int) throws -> [UInt8] {
        guard try need(n) else { throw AXError.corrupt("truncated Zstandard data") }
        defer { inPos += n }
        return Array(inBuf[inPos..<inPos + n])
    }
    private func le(_ b: [UInt8]) -> UInt64 { b.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << UInt64(8 * $1.offset) } }

    // MARK: frames

    private func startFrame() throws -> Bool {
        guard try need(4) else {
            if inBuf.count - inPos == 0 { return false }
            throw AXError.corrupt("truncated Zstandard data")
        }
        let magic = le(try take(4))
        if magic & 0xffff_fff0 == 0x184d_2a50 {                             // skippable frame
            let n = Int(le(try take(4)))
            var left = n
            while left > 0 { let k = min(left, 1 << 16); _ = try take(k); left -= k }
            return try startFrame()
        }
        guard magic == 0xfd2f_b528 else { throw AXError.corrupt("not Zstandard data") }
        let fd = Int(try take(1)[0])
        let fcsFlag = fd >> 6, single = fd & 0x20 != 0
        wantChecksum = fd & 4 != 0
        let dictFlag = fd & 3
        guard fd & 8 == 0 else { throw AXError.corrupt("bad Zstandard frame header") }
        var window = 0
        if !single {
            let wd = Int(try take(1)[0])
            let base = 1 << (10 + (wd >> 3))
            window = base + (base >> 3) * (wd & 7)
        }
        if dictFlag != 0 {
            let id = le(try take([0, 1, 2, 4][dictFlag]))
            if id != 0 { throw AXError.unsupported("Zstandard data that needs a dictionary") }
        }
        let fcsBytes = [single ? 1 : 0, 2, 4, 8][fcsFlag]
        contentSize = nil
        if fcsBytes > 0 {
            var v = le(try take(fcsBytes))
            if fcsBytes == 2 { v += 256 }
            contentSize = v
            if single { window = Int(min(v, UInt64(1 << 30))) }
        }
        guard window <= 1 << 30 else { throw AXError.unsupported("Zstandard windows larger than 1 GB") }
        windowSize = max(window, 1 << 10)
        frameProduced = 0
        checksum = wantChecksum ? XXH64() : nil
        huff = nil; llT = ZstdSource.llTable; mlT = ZstdSource.mlTable; ofT = ZstdSource.ofTable; rep = [1, 4, 8]
        inFrame = true; lastBlock = false
        frameBase = out.count
        return true
    }

    private func endFrame() throws {
        if wantChecksum {
            let want = le(try take(4))
            if let c = checksum, c.digest() & 0xffff_ffff != want { throw AXError.corrupt("Zstandard checksum mismatch") }
        }
        if let s = contentSize, s != frameProduced { throw AXError.corrupt("Zstandard frame has the wrong length") }
        inFrame = false
    }

    // MARK: blocks

    private func appendOutput(_ bytes: [UInt8]) {
        out.append(contentsOf: bytes)
        frameProduced &+= UInt64(bytes.count)
        checksum?.update(Data(bytes))
    }

    private func nextBlock() throws {
        let h = Int(le(try take(3)))
        lastBlock = h & 1 != 0
        let type = (h >> 1) & 3, size = h >> 3
        guard size <= 1 << 17 + 1 << 10 || type != 2 else { throw AXError.corrupt("bad Zstandard block size") }
        switch type {
        case 0:
            guard size <= 1 << 17 else { throw AXError.corrupt("bad Zstandard block size") }
            appendOutput(try take(size))
        case 1:
            guard size <= 1 << 17 else { throw AXError.corrupt("bad Zstandard block size") }
            appendOutput([UInt8](repeating: try take(1)[0], count: size))
        case 2: try compressedBlock(try take(size))
        default: throw AXError.corrupt("bad Zstandard block type")
        }
        trimHistory()
        if lastBlock { try endFrame() }
    }

    private func trimHistory() {
        let keep = windowSize + (1 << 17)
        if outHead > keep && outHead > 1 << 20 {
            let drop = outHead - windowSize
            out.removeFirst(drop); outHead -= drop; frameBase = max(0, frameBase - drop)
        }
    }

    private func literals(_ b: [UInt8], _ p: inout Int) throws -> [UInt8] {
        guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }
        let b0 = Int(b[p])
        let type = b0 & 3, fmt = (b0 >> 2) & 3
        switch type {
        case 0, 1:
            var size: Int
            switch fmt {
            case 0, 2: size = b0 >> 3; p += 1
            case 1: guard p + 2 <= b.count else { throw AXError.corrupt("bad Zstandard block") }; size = (b0 >> 4) | Int(b[p + 1]) << 4; p += 2
            default: guard p + 3 <= b.count else { throw AXError.corrupt("bad Zstandard block") }; size = (b0 >> 4) | Int(b[p + 1]) << 4 | Int(b[p + 2]) << 12; p += 3
            }
            if type == 0 {
                guard p + size <= b.count else { throw AXError.corrupt("bad Zstandard block") }
                defer { p += size }
                return Array(b[p..<p + size])
            }
            guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }
            defer { p += 1 }
            return [UInt8](repeating: b[p], count: size)
        default:
            var regen: Int, comp: Int, streams: Int
            let hdrLen: Int
            switch fmt {
            case 0, 1: hdrLen = 3; streams = fmt == 0 ? 1 : 4
            case 2: hdrLen = 4; streams = 4
            default: hdrLen = 5; streams = 4
            }
            guard p + hdrLen <= b.count else { throw AXError.corrupt("bad Zstandard block") }
            var v: UInt64 = 0
            for i in 0..<hdrLen { v |= UInt64(b[p + i]) << UInt64(8 * i) }
            v >>= 4
            switch fmt {
            case 0, 1: regen = Int(v & 0x3ff); comp = Int((v >> 10) & 0x3ff)
            case 2: regen = Int(v & 0x3fff); comp = Int((v >> 14) & 0x3fff)
            default: regen = Int(v & 0x3ffff); comp = Int((v >> 18) & 0x3ffff)
            }
            p += hdrLen
            guard p + comp <= b.count, regen <= 1 << 17 else { throw AXError.corrupt("bad Zstandard block") }
            var body = Array(b[p..<p + comp])
            p += comp
            if type == 2 {
                let (t, used) = try readHuffman(body)
                huff = t
                body.removeFirst(used)
            }
            guard let table = huff else { throw AXError.corrupt("Zstandard literals without a Huffman table") }
            var result = [UInt8]()
            result.reserveCapacity(regen)
            if streams == 1 { try table.decode(body, count: regen, into: &result) }
            else {
                guard body.count >= 6 else { throw AXError.corrupt("bad Zstandard literals") }
                let s1 = Int(body[0]) | Int(body[1]) << 8, s2 = Int(body[2]) | Int(body[3]) << 8, s3 = Int(body[4]) | Int(body[5]) << 8
                guard 6 + s1 + s2 + s3 <= body.count else { throw AXError.corrupt("bad Zstandard literals") }
                let per = (regen + 3) / 4
                let bounds = [(6, s1, per), (6 + s1, s2, per), (6 + s1 + s2, s3, per), (6 + s1 + s2 + s3, body.count - 6 - s1 - s2 - s3, regen - 3 * per)]
                for (o, n, c) in bounds {
                    guard c >= 0 else { throw AXError.corrupt("bad Zstandard literals") }
                    try table.decode(Array(body[o..<o + n]), count: c, into: &result)
                }
            }
            return result
        }
    }

    private func readHuffman(_ b: [UInt8]) throws -> (HuffTable, Int) {
        guard let hb = b.first.map(Int.init) else { throw AXError.corrupt("bad Zstandard Huffman table") }
        var weights = [Int]()
        var used: Int
        if hb >= 128 {
            let n = hb - 127
            used = 1 + (n + 1) / 2
            guard b.count >= used else { throw AXError.corrupt("bad Zstandard Huffman table") }
            for i in 0..<n { let byte = Int(b[1 + i / 2]); weights.append(i % 2 == 0 ? byte >> 4 : byte & 15) }
        } else {
            used = 1 + hb
            guard b.count >= used, hb > 0 else { throw AXError.corrupt("bad Zstandard Huffman table") }
            let comp = Array(b[1..<used])
            let (t, n) = try FSETable.read(comp, maxSymbol: 12, maxLog: 6)
            var r = try BackBits(Array(comp[n...]))
            var s1 = r.read(t.accLog), s2 = r.read(t.accLog)
            while true {
                weights.append(Int(t.symbol[s1])); s1 = Int(t.newState[s1]) + r.read(Int(t.nbBits[s1]))
                if r.overflow { weights.append(Int(t.symbol[s2])); break }
                weights.append(Int(t.symbol[s2])); s2 = Int(t.newState[s2]) + r.read(Int(t.nbBits[s2]))
                if r.overflow { weights.append(Int(t.symbol[s1])); break }
                if weights.count > 255 { throw AXError.corrupt("bad Zstandard Huffman table") }
            }
        }
        guard weights.count <= 255, weights.allSatisfy({ $0 <= 11 }) else { throw AXError.corrupt("bad Zstandard Huffman table") }
        return (try HuffTable(weights: weights), used)
    }

    private func table(mode: Int, _ b: [UInt8], _ p: inout Int, current: FSETable, def: FSETable, maxSymbol: Int, maxLog: Int) throws -> FSETable {
        switch mode {
        case 0: return def
        case 1: guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }; defer { p += 1 }; return FSETable.rle(b[p])
        case 2:
            guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }
            let (t, n) = try FSETable.read(Array(b[p...]), maxSymbol: maxSymbol, maxLog: maxLog)
            p += n
            return t
        default: return current
        }
    }

    private func compressedBlock(_ b: [UInt8]) throws {
        var p = 0
        let lits = try literals(b, &p)
        guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }
        var nSeq = Int(b[p]); p += 1
        if nSeq == 0 { appendOutput(lits); return }
        if nSeq >= 128 {
            guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }
            if nSeq < 255 { nSeq = ((nSeq - 128) << 8) + Int(b[p]); p += 1 }
            else { guard p + 2 <= b.count else { throw AXError.corrupt("bad Zstandard block") }; nSeq = Int(b[p]) + Int(b[p + 1]) << 8 + 0x7f00; p += 2 }
        }
        guard p < b.count else { throw AXError.corrupt("bad Zstandard block") }
        let modes = Int(b[p]); p += 1
        llT = try table(mode: modes >> 6, b, &p, current: llT, def: ZstdSource.llTable, maxSymbol: 35, maxLog: 9)
        ofT = try table(mode: (modes >> 4) & 3, b, &p, current: ofT, def: ZstdSource.ofTable, maxSymbol: 31, maxLog: 8)
        mlT = try table(mode: (modes >> 2) & 3, b, &p, current: mlT, def: ZstdSource.mlTable, maxSymbol: 52, maxLog: 9)
        var r = try BackBits(Array(b[p...]))
        var sl = r.read(llT.accLog), so = r.read(ofT.accLog), sm = r.read(mlT.accLog)
        var litPos = 0
        var produced = [UInt8]()
        produced.reserveCapacity(lits.count + nSeq * 8)
        let base = out.count                                       // `produced` goes after the existing history
        for i in 0..<nSeq {
            let ofCode = Int(ofT.symbol[so]), mlCode = Int(mlT.symbol[sm]), llCode = Int(llT.symbol[sl])
            guard ofCode <= 31, mlCode <= 52, llCode <= 35 else { throw AXError.corrupt("bad Zstandard sequence") }
            let ofv = (1 << ofCode) + r.read(ofCode)
            let ml = ZstdSource.mlBase[mlCode] + r.read(ZstdSource.mlBits[mlCode])
            let ll = ZstdSource.llBase[llCode] + r.read(ZstdSource.llBits[llCode])
            if i + 1 < nSeq {
                sl = Int(llT.newState[sl]) + r.read(Int(llT.nbBits[sl]))
                sm = Int(mlT.newState[sm]) + r.read(Int(mlT.nbBits[sm]))
                so = Int(ofT.newState[so]) + r.read(Int(ofT.nbBits[so]))
            }
            if r.overflow { throw AXError.corrupt("damaged Zstandard sequences") }
            var offset: Int
            if ofv > 3 { offset = ofv - 3; rep = [offset, rep[0], rep[1]] }
            else {
                let idx = ofv - 1 + (ll == 0 ? 1 : 0)
                switch idx {
                case 0: offset = rep[0]
                case 1: offset = rep[1]; rep = [offset, rep[0], rep[2]]
                case 2: offset = rep[2]; rep = [offset, rep[0], rep[1]]
                default: offset = rep[0] - 1; guard offset > 0 else { throw AXError.corrupt("bad Zstandard offset") }; rep = [offset, rep[0], rep[1]]
                }
            }
            guard litPos + ll <= lits.count else { throw AXError.corrupt("bad Zstandard literal length") }
            produced.append(contentsOf: lits[litPos..<litPos + ll]); litPos += ll
            guard offset > 0, offset <= (out.count - frameBase) + produced.count, offset <= max(windowSize, 1 << 17) else { throw AXError.corrupt("Zstandard match reaches too far back") }
            guard ml <= 1 << 17 + 1 << 16 else { throw AXError.corrupt("bad Zstandard match length") }
            // copy byte by byte: the source may overlap the bytes being written
            for _ in 0..<ml {
                let pos = produced.count - offset
                if pos >= 0 { produced.append(produced[pos]) } else { produced.append(out[base + pos]) }
            }
        }
        guard r.pos == -1 else { throw AXError.corrupt("damaged Zstandard sequences") }
        produced.append(contentsOf: lits[litPos...])
        guard produced.count <= 1 << 17 else { throw AXError.corrupt("bad Zstandard block") }
        appendOutput(produced)
    }

    // MARK: ByteSource

    func read(_ n: Int) throws -> Data {
        while out.count - outHead < n && !finished {
            if !inFrame {
                if try !startFrame() { finished = true; break }
            }
            try nextBlock()
        }
        let take = min(n, out.count - outHead)
        let d = Data(out[outHead..<outHead + take])
        outHead += take
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}
