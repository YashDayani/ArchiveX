import Foundation

// bzip2 (Burrows–Wheeler + MTF + Huffman): our own decoder and encoder.

private enum BZCRC {
    static let table: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i) << 24
        for _ in 0..<8 { c = (c & 0x8000_0000) != 0 ? (c << 1) ^ 0x04c1_1db7 : c << 1 }
        return c
    }
    @inline(__always) static func update(_ crc: UInt32, _ b: UInt8) -> UInt32 { (crc << 8) ^ table[Int((crc >> 24) ^ UInt32(b))] }
}

// MARK: - Decoder

final class Bzip2Source: ByteSource {
    private let input: ByteSource
    private var inBuf = [UInt8]()
    private var ip = 0
    private var bitBuf: UInt64 = 0
    private var nbits = 0
    private var out = [UInt8]()
    private var outPos = 0
    private var blockSize = 0
    private var combined: UInt32 = 0
    private var inStream = false
    private var eof = false

    init(source: ByteSource) throws {
        input = source
        try startStream(first: true)
    }

    convenience init(file: FileIn) throws { try self.init(source: FileSource(file)) }

    // bit input (MSB first)
    private func need(_ n: Int) throws {
        while nbits < n {
            if ip >= inBuf.count {
                let d = try input.read(1 << 20)
                if d.isEmpty { throw AXError.corrupt("unexpected end of bzip2 data") }
                inBuf = [UInt8](d); ip = 0
            }
            bitBuf = (bitBuf << 8) | UInt64(inBuf[ip]); ip += 1; nbits += 8
        }
    }
    private func bits(_ n: Int) throws -> UInt32 {
        if n == 0 { return 0 }
        try need(n)
        nbits -= n
        return UInt32((bitBuf >> UInt64(nbits)) & ((1 << UInt64(n)) - 1))
    }
    private func bit() throws -> UInt32 { try bits(1) }

    private func startStream(first: Bool) throws {
        let magic: [UInt8] = [0x42, 0x5a, 0x68]
        for m in magic {
            if (try? bits(8)) != UInt32(m) {
                if first { throw AXError.corrupt("not a bzip2 file") }
                eof = true; return
            }
        }
        let level = try bits(8)
        guard level >= 0x31 && level <= 0x39 else { throw AXError.corrupt("bad bzip2 block size") }
        blockSize = Int(level - 0x30) * 100_000
        combined = 0
        inStream = true
    }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && !eof { try nextBlock() }
        let take = min(n, out.count - outPos)
        let d = Data(out[outPos..<outPos + take])
        outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }

    private func nextBlock() throws {
        let hi = try bits(24), lo = try bits(24)
        let magic = UInt64(hi) << 24 | UInt64(lo)
        if magic == 0x1772_4538_5090 {
            let stored = try bits(32)
            guard stored == combined else { throw AXError.corrupt("bzip2 stream CRC mismatch") }
            nbits -= nbits % 8                                  // streams are byte aligned
            inStream = false
            // another concatenated stream?
            if ip >= inBuf.count && nbits < 8 {
                let d = try input.read(1 << 20)
                if d.isEmpty { eof = true; return }
                inBuf = [UInt8](d); ip = 0
            }
            try startStream(first: false)
            return
        }
        guard magic == 0x3141_5926_5359 else { throw AXError.corrupt("bad bzip2 block header") }
        let blockCRC = try bits(32)
        guard try bit() == 0 else { throw AXError.unsupported("randomised bzip2 blocks") }
        let origPtr = Int(try bits(24))

        // symbol map
        let used16 = try bits(16)
        var inUse = [UInt8]()
        for i in 0..<16 where used16 & (0x8000 >> UInt32(i)) != 0 {
            let m = try bits(16)
            for j in 0..<16 where m & (0x8000 >> UInt32(j)) != 0 { inUse.append(UInt8(i * 16 + j)) }
        }
        guard !inUse.isEmpty else { throw AXError.corrupt("empty bzip2 symbol map") }
        let alpha = inUse.count + 2
        let nGroups = Int(try bits(3))
        guard nGroups >= 2 && nGroups <= 6 else { throw AXError.corrupt("bad bzip2 table count") }
        let nSel = Int(try bits(15))
        guard nSel >= 1 else { throw AXError.corrupt("no bzip2 selectors") }
        var selMtf = [UInt8](repeating: 0, count: nSel)
        for i in 0..<nSel {
            var j = 0
            while try bit() == 1 { j += 1; guard j < nGroups else { throw AXError.corrupt("bad bzip2 selector") } }
            selMtf[i] = UInt8(j)
        }
        var pos = [UInt8](0..<UInt8(nGroups))
        var selectors = [UInt8](repeating: 0, count: nSel)
        for i in 0..<nSel {
            let v = Int(selMtf[i]); let t = pos[v]
            var k = v; while k > 0 { pos[k] = pos[k - 1]; k -= 1 }
            pos[0] = t; selectors[i] = t
        }

        // Huffman tables (decoding via limit/base/perm)
        struct Table { var minLen = 0, maxLen = 0; var limit = [Int](repeating: -1, count: 22); var base = [Int](repeating: 0, count: 22); var perm = [Int]() }
        var tables = [Table](repeating: Table(), count: nGroups)
        for t in 0..<nGroups {
            var len = [Int](repeating: 0, count: alpha)
            var cur = Int(try bits(5))
            for i in 0..<alpha {
                while true {
                    guard cur >= 1 && cur <= 20 else { throw AXError.corrupt("bad bzip2 code length") }
                    if try bit() == 0 { break }
                    cur += try bit() == 0 ? 1 : -1
                }
                len[i] = cur
            }
            var tb = Table()
            tb.minLen = len.min()!; tb.maxLen = len.max()!
            var p = 0
            tb.perm = []
            for l in tb.minLen...tb.maxLen { for i in 0..<alpha where len[i] == l { tb.perm.append(i); p += 1 } }
            var count = [Int](repeating: 0, count: 22)
            for l in len { count[l] += 1 }
            var code = 0, idx = 0
            for l in tb.minLen...tb.maxLen {
                tb.base[l] = code - idx          // so that perm index = code - base
                code += count[l]; idx += count[l]
                tb.limit[l] = code - 1
                code <<= 1
            }
            tables[t] = tb
        }

        // MTF + RLE2 decode into `ll`
        let eob = inUse.count + 1
        var mtf = (0..<inUse.count).map { UInt8($0) }
        var ll = [UInt8](); ll.reserveCapacity(blockSize)
        var counts = [Int](repeating: 0, count: 256)
        var groupNo = -1, groupPos = 0
        var run = 0, runMul = 1
        var tbl = tables[0]
        while true {
            if groupPos == 0 {
                groupNo += 1
                guard groupNo < nSel else { throw AXError.corrupt("bzip2 selectors exhausted") }
                groupPos = 50; tbl = tables[Int(selectors[groupNo])]
            }
            groupPos -= 1
            var zn = tbl.minLen
            var zvec = Int(try bits(zn))
            while zn <= tbl.maxLen && zvec > tbl.limit[zn] { zn += 1; zvec = (zvec << 1) | Int(try bit()) }
            guard zn <= tbl.maxLen, zvec - tbl.base[zn] >= 0, zvec - tbl.base[zn] < tbl.perm.count else { throw AXError.corrupt("bad bzip2 Huffman code") }
            let sym = tbl.perm[zvec - tbl.base[zn]]
            if sym <= 1 {
                run += runMul << sym; runMul <<= 1
                guard run <= blockSize else { throw AXError.corrupt("bzip2 run too long") }
                continue
            }
            if run > 0 {
                let uc = inUse[Int(mtf[0])]
                guard ll.count + run <= blockSize else { throw AXError.corrupt("bzip2 block overflow") }
                ll.append(contentsOf: repeatElement(uc, count: run)); counts[Int(uc)] += run
                run = 0; runMul = 1
            }
            if sym == eob { break }
            let idx = sym - 1
            guard idx < mtf.count, ll.count < blockSize else { throw AXError.corrupt("bad bzip2 MTF index") }
            let v = mtf[idx]
            var k = idx; while k > 0 { mtf[k] = mtf[k - 1]; k -= 1 }
            mtf[0] = v
            let uc = inUse[Int(v)]
            ll.append(uc); counts[Int(uc)] += 1
        }
        let n = ll.count
        guard origPtr < n || n == 0 else { throw AXError.corrupt("bad bzip2 origin pointer") }

        // inverse BWT
        var cf = [Int](repeating: 0, count: 257)
        for i in 0..<256 { cf[i + 1] = cf[i] + counts[i] }
        var tt = [UInt32](repeating: 0, count: n)
        for i in 0..<n { tt[i] = UInt32(ll[i]) }
        for i in 0..<n { let uc = Int(ll[i]); tt[cf[uc]] |= UInt32(i) << 8; cf[uc] += 1 }

        // RLE1 decode + CRC
        var crc: UInt32 = 0xffff_ffff
        var tPos = n > 0 ? Int(tt[origPtr] >> 8) : 0
        var last = -1, same = 0
        let before = out.count
        var i = 0
        while i < n {
            let e = tt[tPos]; let b = UInt8(e & 0xff); tPos = Int(e >> 8); i += 1
            if same == 4 {
                out.append(contentsOf: repeatElement(UInt8(last), count: Int(b)))
                for _ in 0..<Int(b) { crc = BZCRC.update(crc, UInt8(last)) }
                same = 0; last = -1
                continue
            }
            if Int(b) == last { same += 1 } else { same = 1; last = Int(b) }
            out.append(b); crc = BZCRC.update(crc, b)
        }
        _ = before
        guard ~crc == blockCRC else { throw AXError.corrupt("bzip2 block CRC mismatch") }
        combined = ((combined << 1) | (combined >> 31)) ^ blockCRC
    }
}

// MARK: - Encoder

final class Bzip2Sink: ByteSink {
    private let out: ByteSink
    private let blockMax: Int
    private let level: Int
    private var block = [UInt8]()
    private var blockCRC: UInt32 = 0xffff_ffff
    private var combined: UInt32 = 0
    private var runByte = -1, runLen = 0
    private var bw = Data(); private var acc: UInt64 = 0; private var accBits = 0

    init(out: ByteSink, level: Int = 9) throws {
        self.out = out
        self.level = max(1, min(9, level))
        blockMax = self.level * 100_000 - 19
        block.reserveCapacity(blockMax + 8)
        putBits(0x42, 8); putBits(0x5a, 8); putBits(0x68, 8); putBits(UInt32(0x30 + self.level), 8)
    }

    // bit output (MSB first)
    private func putBits(_ v: UInt32, _ n: Int) {
        guard n > 0 else { return }
        acc = (acc << UInt64(n)) | UInt64(v & (n == 32 ? 0xffff_ffff : (1 << UInt32(n)) - 1)); accBits += n
        while accBits >= 8 { accBits -= 8; bw.append(UInt8((acc >> UInt64(accBits)) & 0xff)) }
    }
    private func flushBytes() throws { if !bw.isEmpty { try out.write(bw); bw.removeAll(keepingCapacity: true) } }

    private func flushRun() {
        guard runLen > 0 else { return }
        let b = UInt8(runByte)
        if runLen >= 4 {
            block.append(contentsOf: [b, b, b, b, UInt8(runLen - 4)])
        } else {
            block.append(contentsOf: repeatElement(b, count: runLen))
        }
        runByte = -1; runLen = 0
    }

    func write(_ data: Data) throws {
        for b in data {
            blockCRC = BZCRC.update(blockCRC, b)
            if Int(b) == runByte && runLen < 255 + 4 { runLen += 1 }
            else { flushRun(); runByte = Int(b); runLen = 1 }
            if block.count >= blockMax { flushRun(); try emitBlock() }
        }
    }

    func finish() throws {
        flushRun()
        if !block.isEmpty { try emitBlock() }
        putBits(0x1772, 16); putBits(0x4538, 16); putBits(0x5090, 16)
        putBits(combined, 32)
        if accBits > 0 { putBits(0, 8 - accBits) }
        try flushBytes()
        try out.finish()
    }

    /// Sorts all cyclic rotations of `s` (prefix doubling with radix passes) and returns their order.
    private func sortRotations(_ s: [UInt8]) -> [Int32] {
        let n = s.count
        var sa = [Int32](repeating: 0, count: n)
        var rank = [Int32](repeating: 0, count: n)
        var tmp = [Int32](repeating: 0, count: n)
        var count = [Int](repeating: 0, count: max(256, n) + 1)
        for i in 0..<n { count[Int(s[i]) + 1] += 1 }
        for i in 0..<256 { count[i + 1] += count[i] }
        for i in 0..<n { let c = Int(s[i]); sa[count[c]] = Int32(i); count[c] += 1 }
        rank[Int(sa[0])] = 0
        var classes = 1
        for i in 1..<max(n, 1) { if s[Int(sa[i])] != s[Int(sa[i - 1])] { classes += 1 }; rank[Int(sa[i])] = Int32(classes - 1) }
        var k = 1
        var sa2 = [Int32](repeating: 0, count: n)
        while k < n && classes < n {
            for i in 0..<n { var p = Int(sa[i]) - k; if p < 0 { p += n }; sa2[i] = Int32(p) }
            for i in 0..<(classes + 1) { count[i] = 0 }
            for i in 0..<n { count[Int(rank[Int(sa2[i])]) + 1] += 1 }
            for i in 0..<classes { count[i + 1] += count[i] }
            for i in 0..<n { let r = Int(rank[Int(sa2[i])]); sa[count[r]] = sa2[i]; count[r] += 1 }
            tmp[Int(sa[0])] = 0
            var c = 1
            for i in 1..<n {
                let a = Int(sa[i]), b = Int(sa[i - 1])
                var a2 = a + k; if a2 >= n { a2 -= n }
                var b2 = b + k; if b2 >= n { b2 -= n }
                if rank[a] != rank[b] || rank[a2] != rank[b2] { c += 1 }
                tmp[a] = Int32(c - 1)
            }
            swap(&rank, &tmp); classes = c
            k <<= 1
        }
        return sa
    }

    /// Optimal-ish length-limited Huffman code lengths.
    private func codeLengths(_ freq: [Int], limit: Int) -> [Int] {
        var f = freq.map { max($0, 1) }
        while true {
            struct Node { var w: Int; var l: Int; var r: Int; var sym: Int }
            var nodes: [Node] = f.enumerated().map { Node(w: $0.element, l: -1, r: -1, sym: $0.offset) }
            var heap = Array(0..<nodes.count).sorted { nodes[$0].w < nodes[$1].w }
            while heap.count > 1 {
                let a = heap.removeFirst(), b = heap.removeFirst()
                nodes.append(Node(w: nodes[a].w + nodes[b].w, l: a, r: b, sym: -1))
                let idx = nodes.count - 1
                let at = heap.firstIndex(where: { nodes[$0].w >= nodes[idx].w }) ?? heap.count
                heap.insert(idx, at: at)
            }
            var lengths = [Int](repeating: 0, count: f.count)
            var stack = [(heap[0], 0)]
            var tooLong = false
            while let (i, d) = stack.popLast() {
                if nodes[i].sym >= 0 { lengths[nodes[i].sym] = max(d, 1); if d > limit { tooLong = true } }
                else { stack.append((nodes[i].l, d + 1)); stack.append((nodes[i].r, d + 1)) }
            }
            if !tooLong { return lengths }
            f = f.map { max(1, $0 / 2) }
        }
    }

    private func emitBlock() throws {
        let n = block.count
        let crc = ~blockCRC
        combined = ((combined << 1) | (combined >> 31)) ^ crc
        let sa = sortRotations(block)
        var origPtr = 0
        var last = [UInt8](repeating: 0, count: n)
        for i in 0..<n {
            let p = Int(sa[i])
            if p == 0 { origPtr = i; last[i] = block[n - 1] } else { last[i] = block[p - 1] }
        }
        // symbol map, MTF, RLE2
        var seen = [Bool](repeating: false, count: 256)
        for b in block { seen[Int(b)] = true }
        var unseqToSeq = [Int](repeating: 0, count: 256)
        var nInUse = 0
        for i in 0..<256 where seen[i] { unseqToSeq[i] = nInUse; nInUse += 1 }
        let eob = nInUse + 1, alpha = nInUse + 2
        var mtf = (0..<nInUse).map { UInt8($0) }
        var syms = [UInt16](); syms.reserveCapacity(n)
        var freq = [Int](repeating: 0, count: alpha)
        var zPend = 0
        func flushZ() {
            guard zPend > 0 else { return }
            zPend -= 1
            while true {
                if zPend & 1 == 1 { syms.append(1); freq[1] += 1 } else { syms.append(0); freq[0] += 1 }
                if zPend < 2 { break }
                zPend = (zPend - 2) >> 1
            }
            zPend = 0
        }
        for b in last {
            let v = UInt8(unseqToSeq[Int(b)])
            if mtf[0] == v { zPend += 1; continue }
            flushZ()
            var j = 1; var prev = mtf[0]
            while mtf[j] != v { let t = mtf[j]; mtf[j] = prev; prev = t; j += 1 }
            mtf[j] = prev; mtf[0] = v
            syms.append(UInt16(j + 1)); freq[j + 1] += 1
        }
        flushZ()
        syms.append(UInt16(eob)); freq[eob] += 1

        // choose tables
        let nMTF = syms.count
        let nGroups = nMTF < 200 ? 2 : nMTF < 600 ? 3 : nMTF < 1200 ? 4 : nMTF < 2400 ? 5 : 6
        var lens = [[Int]](repeating: [Int](repeating: 15, count: alpha), count: nGroups)
        var remaining = nMTF, start = 0, ng = nGroups
        for g in 0..<nGroups {
            let target = remaining / ng
            var end = start - 1, acc = 0
            while acc < target && end < alpha - 1 { end += 1; acc += freq[end] }
            if end > start && ng != nGroups && ng != 1 && (nGroups - ng) % 2 == 1 { acc -= freq[end]; end -= 1 }
            for i in 0..<alpha { lens[g][i] = (i >= start && i <= end) ? 0 : 15 }
            remaining -= acc; start = end + 1; ng -= 1
        }
        var selectors = [UInt8]()
        for _ in 0..<4 {
            var gfreq = [[Int]](repeating: [Int](repeating: 0, count: alpha), count: nGroups)
            selectors.removeAll(keepingCapacity: true)
            var i = 0
            while i < nMTF {
                let e = min(i + 50, nMTF)
                var bestG = 0, best = Int.max
                for g in 0..<nGroups {
                    var cost = 0
                    for k in i..<e { cost += lens[g][Int(syms[k])] }
                    if cost < best { best = cost; bestG = g }
                }
                for k in i..<e { gfreq[bestG][Int(syms[k])] += 1 }
                selectors.append(UInt8(bestG))
                i = e
            }
            for g in 0..<nGroups { lens[g] = codeLengths(gfreq[g], limit: 17) }
        }

        // write block
        putBits(0x3141, 16); putBits(0x5926, 16); putBits(0x5359, 16)
        putBits(crc, 32); putBits(0, 1); putBits(UInt32(origPtr), 24)
        var used16: UInt32 = 0
        for i in 0..<16 { for j in 0..<16 where seen[i * 16 + j] { used16 |= 0x8000 >> UInt32(i); break } }
        putBits(used16, 16)
        for i in 0..<16 where used16 & (0x8000 >> UInt32(i)) != 0 {
            var m: UInt32 = 0
            for j in 0..<16 where seen[i * 16 + j] { m |= 0x8000 >> UInt32(j) }
            putBits(m, 16)
        }
        putBits(UInt32(nGroups), 3); putBits(UInt32(selectors.count), 15)
        var pos = [UInt8](0..<UInt8(nGroups))
        for s in selectors {
            var j = 0; while pos[j] != s { j += 1 }
            for _ in 0..<j { putBits(1, 1) }; putBits(0, 1)
            let t = pos[j]; var k = j; while k > 0 { pos[k] = pos[k - 1]; k -= 1 }; pos[0] = t
        }
        var codes = [[UInt32]](repeating: [UInt32](repeating: 0, count: alpha), count: nGroups)
        for g in 0..<nGroups {
            var cur = lens[g][0]
            putBits(UInt32(cur), 5)
            for i in 0..<alpha {
                while cur < lens[g][i] { putBits(0b10, 2); cur += 1 }
                while cur > lens[g][i] { putBits(0b11, 2); cur -= 1 }
                putBits(0, 1)
            }
            var code: UInt32 = 0
            for l in (lens[g].min()!)...(lens[g].max()!) {
                for i in 0..<alpha where lens[g][i] == l { codes[g][i] = code; code += 1 }
                code <<= 1
            }
        }
        var i = 0, sel = 0
        while i < nMTF {
            let g = Int(selectors[sel]); sel += 1
            for k in i..<min(i + 50, nMTF) { putBits(codes[g][Int(syms[k])], lens[g][Int(syms[k])]) }
            i += 50
            if bw.count > 1 << 16 { try flushBytes() }
        }
        try flushBytes()
        block.removeAll(keepingCapacity: true)
        blockCRC = 0xffff_ffff
    }
}
