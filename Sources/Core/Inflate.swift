import Foundation

// Our own streaming DEFLATE decoder (RFC 1951). Unlike Apple's codec it reports exactly how
// many input bytes it used, which gzip members, ZIP and later formats rely on.

private struct HuffTable {
    var table: [UInt16] = []      // (symbol << 4) | length, indexed by the next `maxBits` input bits
    var maxBits = 0

    init() {}

    init(lengths: [UInt8]) throws {
        var counts = [Int](repeating: 0, count: 16)
        for l in lengths { counts[Int(l)] += 1 }
        counts[0] = 0
        maxBits = (1...15).last(where: { counts[$0] > 0 }) ?? 0
        guard maxBits > 0 else { table = [0]; return }                // empty code (only valid if never used)
        var next = [Int](repeating: 0, count: 17)
        var code = 0
        for b in 1...15 {
            code = (code + counts[b - 1]) << 1
            next[b] = code
        }
        table = [UInt16](repeating: 0, count: 1 << maxBits)
        for (sym, l) in lengths.enumerated() where l > 0 {
            let len = Int(l)
            let c = next[len]; next[len] += 1
            guard c < (1 << len) else { throw AXError.corrupt("invalid Huffman code") }
            var rev = 0
            for i in 0..<len where c & (1 << i) != 0 { rev |= 1 << (len - 1 - i) }
            var i = rev
            while i < table.count { table[i] = UInt16(sym << 4 | len); i += 1 << len }
        }
    }
}

final class Inflater {
    private var buf = [UInt8]()
    private var ip = 0
    private var bits: UInt64 = 0
    private var nbits = 0
    private enum State { case blockHeader, stored(Int), huffman, finished }
    private var state = State.blockHeader
    private var lastBlock = false
    private var lit = HuffTable()
    private var dist = HuffTable()
    private let deflate64: Bool
    private var window: [UInt8]
    private let wmask: Int
    private var wpos = 0
    private var total: UInt64 = 0
    private var chunk = [UInt8]()

    private static let lenBase: [Int] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
    private static let lenExtra: [Int] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
    private static let distBase: [Int] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
    private static let distExtra: [Int] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
    private static let clOrder: [Int] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
    private static let fixed: (HuffTable, HuffTable) = {
        var l = [UInt8](repeating: 8, count: 288)
        for i in 144..<256 { l[i] = 9 }
        for i in 256..<280 { l[i] = 7 }
        return (try! HuffTable(lengths: l), try! HuffTable(lengths: [UInt8](repeating: 5, count: 30)))
    }()

    /// `deflate64`: the Deflate64 variant (64 KB window, 16 extra bits on length code 285, distance codes 30 and 31).
    private static let fixed64: HuffTable = try! HuffTable(lengths: [UInt8](repeating: 5, count: 32))

    init(deflate64: Bool = false) {
        self.deflate64 = deflate64
        window = [UInt8](repeating: 0, count: deflate64 ? 65536 : 32768)
        wmask = deflate64 ? 65535 : 32767
        chunk.reserveCapacity(1 << 17)
    }

    @inline(__always) private func refill() {
        while nbits <= 56 && ip < buf.count { bits |= UInt64(buf[ip]) << UInt64(nbits); nbits += 8; ip += 1 }
    }
    @inline(__always) private func take(_ n: Int) -> Int {
        let v = Int(bits & ((1 << UInt64(n)) - 1)); bits >>= UInt64(n); nbits -= n; return v
    }
    @inline(__always) private func put(_ b: UInt8) {
        window[wpos] = b; wpos = (wpos + 1) & wmask; chunk.append(b)
    }
    private func flush(_ sink: (Data) throws -> Void) throws {
        if !chunk.isEmpty { total &+= UInt64(chunk.count); try sink(Data(chunk)); chunk.removeAll(keepingCapacity: true) }
    }

    private func decode(_ t: HuffTable) throws -> Int {
        guard t.maxBits > 0 else { throw AXError.corrupt("use of an empty Huffman code") }
        let e = t.table[Int(bits & UInt64((1 << t.maxBits) - 1))]
        let len = Int(e & 15)
        guard len > 0, len <= nbits else { throw len == 0 ? AXError.corrupt("invalid Huffman code") : AXError.corrupt("truncated deflate data") }
        bits >>= UInt64(len); nbits -= len
        return Int(e >> 4)
    }

    private func readDynamicTables() throws {
        let hlit = take(5) + 257, hdist = take(5) + 1, hclen = take(4) + 4
        var cl = [UInt8](repeating: 0, count: 19)
        for i in 0..<hclen { refill(); cl[Inflater.clOrder[i]] = UInt8(take(3)) }
        let clTable = try HuffTable(lengths: cl)
        var lengths = [UInt8](repeating: 0, count: hlit + hdist)
        var i = 0
        while i < hlit + hdist {
            refill()
            let sym = try decode(clTable)
            if sym < 16 { lengths[i] = UInt8(sym); i += 1; continue }
            var rep = 0, val: UInt8 = 0
            switch sym {
            case 16:
                guard i > 0 else { throw AXError.corrupt("bad repeat in deflate header") }
                val = lengths[i - 1]; rep = 3 + take(2)
            case 17: rep = 3 + take(3)
            default: rep = 11 + take(7)
            }
            guard i + rep <= hlit + hdist else { throw AXError.corrupt("bad repeat in deflate header") }
            for _ in 0..<rep { lengths[i] = val; i += 1 }
        }
        lit = try HuffTable(lengths: Array(lengths[0..<hlit]))
        dist = try HuffTable(lengths: Array(lengths[hlit...]))
    }

    /// Starts a new deflate stream but keeps the last 32 KB of output as its dictionary (CAB "MSZIP" blocks work this way).
    func restartKeepingWindow() {
        buf.removeAll(); ip = 0; bits = 0; nbits = 0
        state = .blockHeader; lastBlock = false; chunk.removeAll(keepingCapacity: true)
    }

    /// Feeds more compressed bytes. `final` promises that no more input will follow.
    /// Returns whether the final block was completed and how many of `data`'s bytes were not used.
    @discardableResult
    func process(_ data: Data, final: Bool, _ sink: (Data) throws -> Void) throws -> (ended: Bool, unused: Int) {
        if ip > 0 { buf.removeSubrange(0..<ip); ip = 0 }
        buf.append(contentsOf: data)
        defer { }

        while true {
            switch state {
            case .finished:
                try flush(sink)
                // give back whole bytes still held in the bit buffer
                let back = nbits / 8
                ip -= back; bits = 0; nbits = 0
                let unused = buf.count - ip
                return (true, min(unused, data.count))

            case .blockHeader:
                refill()
                if !final && nbits + 8 * (buf.count - ip) < 2600 { try flush(sink); return (false, 0) }
                guard nbits >= 3 else { throw AXError.corrupt("truncated deflate data") }
                lastBlock = take(1) == 1
                switch take(2) {
                case 0:
                    _ = take(nbits % 8)
                    refill()
                    guard nbits >= 32 else { throw AXError.corrupt("truncated stored block") }
                    let len = take(16), nlen = take(16)
                    guard len == (~nlen & 0xffff) else { throw AXError.corrupt("stored block length mismatch") }
                    state = .stored(len)
                case 1:
                    lit = Inflater.fixed.0; dist = deflate64 ? Inflater.fixed64 : Inflater.fixed.1; state = .huffman
                case 2:
                    try readDynamicTables(); state = .huffman
                default:
                    throw AXError.corrupt("invalid deflate block type")
                }

            case .stored(var n):
                while n > 0 && nbits >= 8 { put(UInt8(take(8))); n -= 1 }
                let avail = min(n, buf.count - ip)
                if avail > 0 {
                    for k in 0..<avail { put(buf[ip + k]) }
                    ip += avail; n -= avail
                }
                if chunk.count >= 1 << 16 { try flush(sink) }
                if n > 0 {
                    if final { throw AXError.corrupt("truncated stored block") }
                    state = .stored(n); try flush(sink); return (false, 0)
                }
                state = lastBlock ? .finished : .blockHeader

            case .huffman:
                while true {
                    refill()
                    if nbits < 48 && !final && ip >= buf.count { try flush(sink); return (false, 0) }
                    let sym = try decode(lit)
                    if sym < 256 { put(UInt8(sym)) }
                    else if sym == 256 { state = lastBlock ? .finished : .blockHeader; break }
                    else {
                        let li = sym - 257
                        guard li < 29 else { throw AXError.corrupt("invalid length code") }
                        let length = deflate64 && li == 28 ? 3 + take(16) : Inflater.lenBase[li] + take(Inflater.lenExtra[li])
                        let ds = try decode(dist)
                        guard ds < (deflate64 ? 32 : 30) else { throw AXError.corrupt("invalid distance code") }
                        refill()
                        let d = ds >= 30 ? (ds == 30 ? 32769 : 49153) + take(14) : Inflater.distBase[ds] + take(Inflater.distExtra[ds])
                        guard UInt64(d) <= total &+ UInt64(chunk.count), d <= wmask + 1 else { throw AXError.corrupt("distance too far back") }
                        var src = (wpos - d) & wmask
                        for _ in 0..<length { let b = window[src]; src = (src + 1) & wmask; put(b) }
                    }
                    if chunk.count >= 1 << 16 { try flush(sink) }
                }
            }
        }
    }
}
