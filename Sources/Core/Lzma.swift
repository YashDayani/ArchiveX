import Foundation

// LZMA and LZMA2: our own decoder and encoder (format by Igor Pavlov; this is an independent
// implementation written from the published description of the algorithm).

private enum P {                      // offsets into the shared probability array
    static let isMatch = 0            // 12 << 4
    static let isRep = 192
    static let isRepG0 = 204
    static let isRepG1 = 216
    static let isRepG2 = 228
    static let isRep0Long = 240       // 12 << 4
    static let posSlot = 432          // 4 * 64
    static let posSpecial = 688       // 115
    static let align = 803            // 16
    static let lenCoder = 819         // 514
    static let repLenCoder = 1333     // 514
    static let literal = 1847
    // inside a length coder
    static let choice = 0, choice2 = 1, low = 2, mid = 130, high = 258
}

struct LzmaProps {
    var lc = 3, lp = 0, pb = 2
    init() {}
    init?(byte: UInt8) {
        let b = Int(byte)
        guard b < 9 * 5 * 5 else { return nil }
        lc = b % 9; lp = (b / 9) % 5; pb = b / 45
    }
    var byte: UInt8 { UInt8((pb * 5 + lp) * 9 + lc) }
}

enum LzmaDict {
    /// LZMA2 dictionary size from its one-byte property.
    static func size(fromLzma2 p: UInt8) throws -> Int {
        guard p <= 40 else { throw AXError.corrupt("bad LZMA2 dictionary size") }
        if p == 40 { return Int(UInt32.max) }
        return (2 | Int(p & 1)) << (Int(p) / 2 + 11)
    }
    static func lzma2Byte(for size: Int) -> UInt8 {
        for p in 0...40 where (try? Self.size(fromLzma2: UInt8(p))) ?? 0 >= size { return UInt8(p) }
        return 40
    }
}

// MARK: - Decoder core

final class LzmaDecoder {
    private var probs: UnsafeMutablePointer<UInt16>
    private var probCount = 0
    private var props = LzmaProps()
    private var win: UnsafeMutablePointer<UInt8>
    private let winSize: Int
    private var wpos = 0
    private(set) var total: UInt64 = 0
    private var dictStart: UInt64 = 0
    private var state = 0
    private var rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0
    private var pending = 0                        // bytes of an interrupted match still to copy

    // range decoder
    private var range: UInt32 = 0, code: UInt32 = 0
    private var inBuf = [UInt8](), inPos = 0
    private var refill: (() throws -> [UInt8])?

    init(dictSize: Int, sizeHint: UInt64?) {
        var n = max(dictSize, 4096)
        if let h = sizeHint, h < UInt64(n) { n = max(Int(h), 4096) }
        winSize = n
        win = UnsafeMutablePointer<UInt8>.allocate(capacity: n)
        win.initialize(repeating: 0, count: 1)
        probs = UnsafeMutablePointer<UInt16>.allocate(capacity: 1)
    }

    deinit { win.deallocate(); probs.deallocate() }

    func setProps(_ p: LzmaProps) {
        props = p
        probs.deallocate()
        probCount = P.literal + (0x300 << (p.lc + p.lp))
        probs = UnsafeMutablePointer<UInt16>.allocate(capacity: probCount)
        resetState()
    }

    func resetState() {
        if probCount > 0 { probs.update(repeating: 1024, count: probCount) }
        state = 0; rep0 = 0; rep1 = 0; rep2 = 0; rep3 = 0; pending = 0
    }

    func resetDictionary() { dictStart = total }

    // input handling
    func setInput(_ bytes: [UInt8], refill: (() throws -> [UInt8])? = nil) throws {
        inBuf = bytes; inPos = 0; self.refill = refill
        guard try nextByte() == 0 else { throw AXError.corrupt("bad LZMA stream start") }
        code = 0
        for _ in 0..<4 { code = (code << 8) | (try nextByte()) }
        range = 0xffff_ffff
    }

    @inline(__always) private func nextByte() throws -> UInt32 {
        if inPos == inBuf.count {
            guard let r = refill else { throw AXError.corrupt("unexpected end of LZMA data") }
            inBuf = try r(); inPos = 0
            if inBuf.isEmpty { throw AXError.corrupt("unexpected end of LZMA data") }
        }
        let b = inBuf[inPos]; inPos += 1
        return UInt32(b)
    }

    @inline(__always) private func bit(_ i: Int) throws -> Int {
        if range < 0x0100_0000 { range <<= 8; code = (code << 8) | (try nextByte()) }
        let p = UInt32(probs[i])
        let bound = (range >> 11) &* p
        if code < bound { range = bound; probs[i] = UInt16(p + ((2048 - p) >> 5)); return 0 }
        range &-= bound; code &-= bound; probs[i] = UInt16(p - (p >> 5)); return 1
    }

    private func direct(_ n: Int) throws -> UInt32 {
        var r: UInt32 = 0
        for _ in 0..<n {
            if range < 0x0100_0000 { range <<= 8; code = (code << 8) | (try nextByte()) }
            range >>= 1
            if code >= range { code &-= range; r = (r << 1) | 1 } else { r <<= 1 }
        }
        return r
    }

    private func tree(_ base: Int, _ bits: Int) throws -> Int {
        var m = 1
        for _ in 0..<bits { m = (m << 1) | (try bit(base + m)) }
        return m - (1 << bits)
    }

    private func reverseTree(_ base: Int, _ bits: Int) throws -> Int {
        var m = 1, sym = 0
        for i in 0..<bits { let b = try bit(base + m); m = (m << 1) | b; sym |= b << i }
        return sym
    }

    private func length(_ base: Int, _ posState: Int) throws -> Int {
        if try bit(base + P.choice) == 0 { return try tree(base + P.low + (posState << 3), 3) }
        if try bit(base + P.choice2) == 0 { return 8 + (try tree(base + P.mid + (posState << 3), 3)) }
        return 16 + (try tree(base + P.high, 8))
    }

    @inline(__always) private func put(_ b: UInt8, _ out: inout [UInt8]) {
        win[wpos] = b; wpos += 1; if wpos == winSize { wpos = 0 }
        total &+= 1
        out.append(b)
    }

    /// Writes bytes straight into the dictionary (LZMA2 uncompressed chunks).
    func append(_ data: [UInt8], _ out: inout [UInt8]) { for b in data { put(b, &out) } }

    /// Decodes until `out` holds `limit` more bytes than when called. Returns true on an end marker.
    func run(produce: Int, _ out: inout [UInt8]) throws -> Bool {
        let goal = out.count + produce
        let pbMask = (1 << props.pb) - 1, lpMask = (1 << props.lp) - 1
        while out.count < goal {
            if pending > 0 {
                let n = min(pending, goal - out.count)
                var src = wpos - rep0 - 1; if src < 0 { src += winSize }
                for _ in 0..<n { let b = win[src]; src += 1; if src == winSize { src = 0 }; put(b, &out) }
                pending -= n
                continue
            }
            let posState = Int(total) & pbMask
            if try bit(P.isMatch + (state << 4) + posState) == 0 {
                let prev: Int = total > dictStart ? Int(win[wpos == 0 ? winSize - 1 : wpos - 1]) : 0
                let base = P.literal + 0x300 * (((Int(total) & lpMask) << props.lc) + (prev >> (8 - props.lc)))
                var sym = 1
                if state >= 7 {
                    var src = wpos - rep0 - 1; if src < 0 { src += winSize }
                    var match = Int(win[src])
                    var offs = 0x100
                    repeat {
                        match <<= 1
                        let mb = match & offs
                        let b = try bit(base + offs + mb + sym)
                        sym = (sym << 1) | b
                        offs &= b == 1 ? mb : ~mb
                    } while sym < 0x100
                } else {
                    repeat { sym = (sym << 1) | (try bit(base + sym)) } while sym < 0x100
                }
                put(UInt8(truncatingIfNeeded: sym), &out)
                state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6)
                continue
            }
            var len: Int
            if try bit(P.isRep + state) == 0 {
                rep3 = rep2; rep2 = rep1; rep1 = rep0
                len = try length(P.lenCoder, posState)
                state = state < 7 ? 7 : 10
                let ls = min(len, 3)
                let slot = try tree(P.posSlot + (ls << 6), 6)
                if slot < 4 { rep0 = slot }
                else {
                    let nd = (slot >> 1) - 1
                    var d = (2 | (slot & 1)) << nd
                    if slot < 14 { d += try reverseTree(P.posSpecial + d - slot, nd) }
                    else {
                        d += Int(try direct(nd - 4)) << 4
                        d += try reverseTree(P.align, 4)
                    }
                    rep0 = d
                    if UInt32(truncatingIfNeeded: d) == 0xffff_ffff { return true }       // end marker
                }
            } else {
                guard total > dictStart else { throw AXError.corrupt("LZMA repeat before any data") }
                if try bit(P.isRepG0 + state) == 0 {
                    if try bit(P.isRep0Long + (state << 4) + posState) == 0 {
                        state = state < 7 ? 9 : 11
                        var src = wpos - rep0 - 1; if src < 0 { src += winSize }
                        put(win[src], &out)
                        continue
                    }
                } else {
                    var d: Int
                    if try bit(P.isRepG1 + state) == 0 { d = rep1 }
                    else {
                        if try bit(P.isRepG2 + state) == 0 { d = rep2 } else { d = rep3; rep3 = rep2 }
                        rep2 = rep1
                    }
                    rep1 = rep0; rep0 = d
                }
                len = try length(P.repLenCoder, posState)
                state = state < 7 ? 8 : 11
            }
            guard UInt64(rep0) < total &- dictStart, rep0 < winSize else { throw AXError.corrupt("LZMA distance out of range") }
            pending = len + 2
        }
        return false
    }
}

// MARK: - LZMA2 as a pull source

final class Lzma2Source: ByteSource {
    private let input: ByteSource
    private let dec: LzmaDecoder
    private var out = [UInt8]()
    private var outPos = 0
    private var done = false
    private var needDictReset = true
    private var needProps = true

    init(input: ByteSource, dictProp: UInt8, sizeHint: UInt64?) throws {
        self.input = input
        dec = LzmaDecoder(dictSize: try LzmaDict.size(fromLzma2: dictProp), sizeHint: sizeHint)
    }

    private func byte() throws -> Int { Int(try input.readExactly(1)[0]) }

    private func nextChunk() throws {
        let ctrl = try byte()
        if ctrl == 0 { done = true; return }
        if ctrl < 0x80 {
            guard ctrl <= 2 else { throw AXError.corrupt("bad LZMA2 control byte") }
            if ctrl == 1 { dec.resetDictionary(); needDictReset = false }
            else if needDictReset { throw AXError.corrupt("LZMA2 stream lacks a dictionary reset") }
            let size = (try byte() << 8 | byte()) + 1
            dec.append([UInt8](try input.readExactly(size)), &out)
            return
        }
        let unpack = ((ctrl & 0x1f) << 16 | (try byte()) << 8 | (try byte())) + 1
        let pack = ((try byte()) << 8 | (try byte())) + 1
        let mode = (ctrl >> 5) & 3
        if mode == 3 { dec.resetDictionary(); needDictReset = false }
        else if needDictReset { throw AXError.corrupt("LZMA2 stream lacks a dictionary reset") }
        if mode >= 2 {
            guard let p = LzmaProps(byte: UInt8(try byte())), p.lc + p.lp <= 4 else { throw AXError.corrupt("bad LZMA2 properties") }
            dec.setProps(p); needProps = false
        } else if mode == 1 { guard !needProps else { throw AXError.corrupt("LZMA2 missing properties") }; dec.resetState() }
        guard !needProps else { throw AXError.corrupt("LZMA2 missing properties") }
        let chunk = [UInt8](try input.readExactly(pack))
        try dec.setInput(chunk)
        let before = out.count
        _ = try dec.run(produce: unpack, &out)
        guard out.count - before == unpack else { throw AXError.corrupt("LZMA2 chunk ended early") }
    }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && !done { try nextChunk() }
        let take = min(n, out.count - outPos)
        let d = Data(out[outPos..<outPos + take])
        outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

/// Plain LZMA (7z "LZMA" coder): 5 property bytes, then one range-coded stream.
final class LzmaSource: ByteSource {
    private let dec: LzmaDecoder
    private var out = [UInt8]()
    private var outPos = 0
    private var remaining: UInt64
    private var finished = false

    init(input: ByteSource, props: Data, unpackSize: UInt64) throws {
        guard props.count >= 5, let p = LzmaProps(byte: props[props.startIndex]) else { throw AXError.corrupt("bad LZMA properties") }
        let dict = Int(props.le32(1))
        dec = LzmaDecoder(dictSize: dict == 0 ? 4096 : dict, sizeHint: unpackSize)
        dec.setProps(p)
        remaining = unpackSize
        try dec.setInput([UInt8](), refill: { [input] in
            let d = try input.read(1 << 16); return [UInt8](d)
        })
    }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && remaining > 0 && !finished {
            let step = Int(min(UInt64(1 << 16), remaining))
            let before = out.count
            if try dec.run(produce: step, &out) { finished = true }
            remaining -= UInt64(out.count - before)
        }
        let take = min(n, out.count - outPos)
        let d = Data(out[outPos..<outPos + take])
        outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

// MARK: - Encoder

private struct RangeEncoder {
    var low: UInt64 = 0
    var range: UInt32 = 0xffff_ffff
    var cache: UInt8 = 0
    var cacheSize = 1
    var out = [UInt8]()

    mutating func reset() { low = 0; range = 0xffff_ffff; cache = 0; cacheSize = 1; out.removeAll(keepingCapacity: true) }

    @inline(__always) mutating func shiftLow() {
        if UInt32(truncatingIfNeeded: low) < 0xff00_0000 || (low >> 32) != 0 {
            var temp = cache
            repeat { out.append(temp &+ UInt8(truncatingIfNeeded: low >> 32)); temp = 0xff; cacheSize -= 1 } while cacheSize != 0
            cache = UInt8(truncatingIfNeeded: low >> 24)
        }
        cacheSize += 1
        low = (low & 0x00ff_ffff) << 8
    }

    @inline(__always) mutating func bit(_ probs: UnsafeMutablePointer<UInt16>, _ i: Int, _ b: Int) {
        let p = UInt32(probs[i])
        let bound = (range >> 11) &* p
        if b == 0 { range = bound; probs[i] = UInt16(p + ((2048 - p) >> 5)) }
        else { low &+= UInt64(bound); range &-= bound; probs[i] = UInt16(p - (p >> 5)) }
        while range < 0x0100_0000 { range <<= 8; shiftLow() }
    }

    mutating func direct(_ value: UInt32, _ n: Int) {
        var i = n - 1
        while i >= 0 {
            range >>= 1
            if (value >> UInt32(i)) & 1 == 1 { low &+= UInt64(range) }
            while range < 0x0100_0000 { range <<= 8; shiftLow() }
            i -= 1
        }
    }

    mutating func flush() { for _ in 0..<5 { shiftLow() } }
    var pending: Int { out.count + cacheSize + 4 }
}

final class LzmaEncoder {
    let props: LzmaProps
    private var probs: UnsafeMutablePointer<UInt16>
    private let probCount: Int
    private var rc = RangeEncoder()
    private var state = 0
    private var rep = [0, 0, 0, 0]

    // sliding window + hash chains
    let dictSize: Int
    private let histKeep: Int
    private let capacity: Int
    private var buf: UnsafeMutablePointer<UInt8>
    private(set) var pos = 0                 // next byte to encode
    private var end = 0                      // bytes valid in buf
    private var baseTotal: UInt64 = 0        // absolute offset of buf[0]
    private var head: [UInt32]
    private var prev: [UInt32]
    private let hashMask: Int
    private let dictMask: Int
    private let depth: Int
    private let nice: Int

    var chunkStart = 0                       // buf index where the current LZMA2 chunk began
    var total: UInt64 { baseTotal + UInt64(pos) }
    var available: Int { end - pos }
    var pendingBytes: Int { rc.pending }

    init(props: LzmaProps = LzmaProps(), dictSize requested: Int, level: Int, totalHint: UInt64?) {
        self.props = props
        var d = 4096
        while d < requested { d <<= 1 }
        if let h = totalHint { while d > 4096 && UInt64(d / 2) >= h { d >>= 1 } }
        dictSize = d
        histKeep = max(d, 1 << 22)
        capacity = histKeep + (1 << 22)
        buf = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity + 8)
        buf.initialize(repeating: 0, count: 1)
        dictMask = d - 1
        let hbits = d >= 1 << 20 ? 18 : 16
        hashMask = (1 << hbits) - 1
        head = [UInt32](repeating: 0, count: 1 << hbits)
        prev = [UInt32](repeating: 0, count: d)
        depth = [4, 8, 16, 24, 48, 96][min(max(level, 0), 5)]
        nice = level >= 4 ? 273 : 64
        probCount = P.literal + (0x300 << (props.lc + props.lp))
        probs = UnsafeMutablePointer<UInt16>.allocate(capacity: probCount)
        resetState()
    }

    deinit { buf.deallocate(); probs.deallocate() }

    func resetState() {
        probs.update(repeating: 1024, count: probCount)
        state = 0; rep = [0, 0, 0, 0]
    }

    // MARK: input
    func feed(_ data: Data) {
        data.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                if end == capacity { slide() }
                let n = min(raw.count - off, capacity - end)
                (buf + end).update(from: raw.baseAddress!.assumingMemoryBound(to: UInt8.self) + off, count: n)
                end += n; off += n
                if off < raw.count && end == capacity && pos == 0 { break }   // cannot grow further until encoded
            }
        }
    }

    var freeSpace: Int { capacity - end + max(0, pos - histKeep) }

    private func slide() {
        let shift = pos - histKeep
        guard shift > 0 else { return }
        buf.update(from: buf + shift, count: end - shift)
        end -= shift; pos -= shift; baseTotal += UInt64(shift); chunkStart -= shift
    }

    // MARK: hashing / matching
    @inline(__always) private func hash(_ i: Int) -> Int {
        let v = (UInt32(buf[i]) << 16) | (UInt32(buf[i + 1]) << 8) | UInt32(buf[i + 2])
        return Int((v &* 2_654_435_761) >> 14) & hashMask
    }

    @inline(__always) private func insert(_ i: Int) {
        guard i + 2 < end else { return }
        let h = hash(i)
        let abs = UInt32(truncatingIfNeeded: baseTotal &+ UInt64(i))
        prev[Int(abs) & dictMask] = head[h]
        head[h] = abs
    }

    @inline(__always) private func matchLen(_ a: Int, _ b: Int, _ maxLen: Int) -> Int {
        var n = 0
        while n < maxLen && buf[a + n] == buf[b + n] { n += 1 }
        return n
    }

    private func findMatch(_ i: Int, _ maxLen: Int) -> (len: Int, dist: Int) {
        guard maxLen >= 3, i + 2 < end else { return (0, 0) }
        var best = 0, bestDist = 0
        let absI = UInt32(truncatingIfNeeded: baseTotal &+ UInt64(i))
        var cand = head[hash(i)]
        var steps = depth
        let limit = min(Int(total), dictSize - 1)
        while steps > 0 {
            let dist = Int(absI &- cand)
            if dist < 1 || dist > limit || dist > i { break }
            let c = i - dist
            if best == 0 || buf[c + best] == buf[i + best] {
                let l = matchLen(c, i, maxLen)
                if l > best { best = l; bestDist = dist; if l >= nice || l == maxLen { break } }
            }
            let next = prev[Int(cand) & dictMask]
            if next == cand { break }
            cand = next; steps -= 1
        }
        return (best >= 3 ? best : 0, bestDist)
    }

    // MARK: symbol coding
    private func encTree(_ base: Int, _ bits: Int, _ value: Int) {
        var m = 1
        for i in stride(from: bits - 1, through: 0, by: -1) { let b = (value >> i) & 1; rc.bit(probs, base + m, b); m = (m << 1) | b }
    }
    private func encReverse(_ base: Int, _ bits: Int, _ value: Int) {
        var m = 1
        for i in 0..<bits { let b = (value >> i) & 1; rc.bit(probs, base + m, b); m = (m << 1) | b }
    }
    private func encLen(_ base: Int, _ len0: Int, _ posState: Int) {
        if len0 < 8 { rc.bit(probs, base + P.choice, 0); encTree(base + P.low + (posState << 3), 3, len0) }
        else if len0 < 16 { rc.bit(probs, base + P.choice, 1); rc.bit(probs, base + P.choice2, 0); encTree(base + P.mid + (posState << 3), 3, len0 - 8) }
        else { rc.bit(probs, base + P.choice, 1); rc.bit(probs, base + P.choice2, 1); encTree(base + P.high, 8, len0 - 16) }
    }

    private func encLiteral(_ i: Int) {
        let t = Int(total)
        let posState = t & ((1 << props.pb) - 1)
        rc.bit(probs, P.isMatch + (state << 4) + posState, 0)
        let prevByte = t > 0 ? Int(buf[i - 1]) : 0
        let base = P.literal + 0x300 * (((t & ((1 << props.lp) - 1)) << props.lc) + (prevByte >> (8 - props.lc)))
        let sym = Int(buf[i])
        var s = 1
        if state >= 7 {
            var match = Int(buf[i - rep[0] - 1])
            var offs = 0x100
            for k in stride(from: 7, through: 0, by: -1) {
                let b = (sym >> k) & 1
                match <<= 1
                let mb = match & offs
                rc.bit(probs, base + offs + mb + s, b)
                s = (s << 1) | b
                offs &= b == 1 ? mb : ~mb
            }
        } else {
            for k in stride(from: 7, through: 0, by: -1) { let b = (sym >> k) & 1; rc.bit(probs, base + s, b); s = (s << 1) | b }
        }
        state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6)
    }

    private func encMatch(dist0: Int, len: Int) {
        let posState = Int(total) & ((1 << props.pb) - 1)
        rc.bit(probs, P.isMatch + (state << 4) + posState, 1)
        rc.bit(probs, P.isRep + state, 0)
        encLen(P.lenCoder, len - 2, posState)
        state = state < 7 ? 7 : 10
        let ls = min(len - 2, 3)
        var slot = dist0
        if dist0 >= 4 { let n = Int.bitWidth - 1 - dist0.leadingZeroBitCount; slot = 2 * n + ((dist0 >> (n - 1)) & 1) }
        encTree(P.posSlot + (ls << 6), 6, slot)
        if slot >= 4 {
            let nd = (slot >> 1) - 1
            let base = (2 | (slot & 1)) << nd
            let reduced = dist0 - base
            if slot < 14 { encReverse(P.posSpecial + base - slot, nd, reduced) }
            else { rc.direct(UInt32(reduced >> 4), nd - 4); encReverse(P.align, 4, reduced & 15) }
        }
        rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = dist0
    }

    private func encRep(_ idx: Int, len: Int) {
        let posState = Int(total) & ((1 << props.pb) - 1)
        rc.bit(probs, P.isMatch + (state << 4) + posState, 1)
        rc.bit(probs, P.isRep + state, 1)
        if idx == 0 {
            rc.bit(probs, P.isRepG0 + state, 0); rc.bit(probs, P.isRep0Long + (state << 4) + posState, 1)
        } else {
            rc.bit(probs, P.isRepG0 + state, 1)
            if idx == 1 { rc.bit(probs, P.isRepG1 + state, 0) }
            else { rc.bit(probs, P.isRepG1 + state, 1); rc.bit(probs, P.isRepG2 + state, idx == 2 ? 0 : 1) }
            let d = rep[idx]
            if idx == 3 { rep[3] = rep[2] }
            if idx >= 2 { rep[2] = rep[1] }
            rep[1] = rep[0]; rep[0] = d
        }
        encLen(P.repLenCoder, len - 2, posState)
        state = state < 7 ? 8 : 11
    }

    private func encShortRep() {
        let posState = Int(total) & ((1 << props.pb) - 1)
        rc.bit(probs, P.isMatch + (state << 4) + posState, 1)
        rc.bit(probs, P.isRep + state, 1)
        rc.bit(probs, P.isRepG0 + state, 0)
        rc.bit(probs, P.isRep0Long + (state << 4) + posState, 0)
        state = state < 7 ? 9 : 11
    }

    /// Encodes one symbol at `pos`; `final` allows encoding with less than a full lookahead.
    func step(final: Bool) {
        let i = pos
        let avail = end - i
        let maxLen = min(273, avail)
        let t = Int(total)

        var repLen = 0, repIdx = 0
        for r in 0..<4 {
            let d = rep[r] + 1
            if t >= d && i >= d {
                let l = matchLen(i, i - d, maxLen)
                if l > repLen { repLen = l; repIdx = r }
            }
        }
        let m = findMatch(i, maxLen)
        var consumed = 1
        if repLen >= 2 && repLen + 1 >= m.len {
            encRep(repIdx, len: repLen); consumed = repLen
        } else if m.len >= 3 && !(m.len == 3 && m.dist > 1 << 12) {
            encMatch(dist0: m.dist - 1, len: m.len); consumed = m.len
        } else if t > rep[0], i > rep[0], buf[i] == buf[i - rep[0] - 1], state >= 7 || repLen == 1 || t > 0 {
            encShortRep()
        } else {
            encLiteral(i)
        }
        for k in 0..<consumed { insert(i + k) }
        pos += consumed
    }

    // MARK: range coder access for LZMA2 chunks
    func beginChunk() { rc.reset(); chunkStart = pos }
    func endChunk() -> [UInt8] { rc.flush(); return rc.out }
    func rawChunk() -> [UInt8] { Array(UnsafeBufferPointer(start: buf + chunkStart, count: pos - chunkStart)) }
}

/// LZMA2 encoder as a byte sink: data in, an LZMA2 stream (ending with 0x00) out.
final class Lzma2Sink: ByteSink {
    private let out: ByteSink
    private let enc: LzmaEncoder
    private var dictDone = false          // a dictionary-reset chunk has been written
    private var propsSent = false         // an LZMA chunk carrying properties has been written
    private var needStateReset = false
    private var inChunk = false
    private var chunkTotal: UInt64 = 0
    let dictProp: UInt8

    init(out: ByteSink, dictSize: Int, level: Int, totalHint: UInt64?) {
        self.out = out
        enc = LzmaEncoder(props: LzmaProps(), dictSize: dictSize, level: level, totalHint: totalHint)
        dictProp = LzmaDict.lzma2Byte(for: enc.dictSize)
    }

    func write(_ data: Data) throws {
        var rest = data[...]
        while !rest.isEmpty {
            let room = max(1, enc.freeSpace)
            let part = rest.prefix(room)
            enc.feed(Data(part))
            rest = rest.dropFirst(part.count)
            try drain(final: false)
        }
    }

    func finish() throws {
        try drain(final: true)
        if inChunk { try closeChunk() }
        try out.write(Data([0]))
    }

    private func openChunk() { enc.beginChunk(); chunkTotal = enc.total; inChunk = true }

    private func drain(final: Bool) throws {
        while enc.available >= 273 || (final && enc.available > 0) {
            try Task.checkCancellation()
            if !inChunk { openChunk() }
            enc.step(final: final)
            if enc.total - chunkTotal >= (1 << 21) - 300 || enc.pendingBytes >= 60_000 { try closeChunk() }
        }
    }

    private func closeChunk() throws {
        inChunk = false
        let unc = Int(enc.total - chunkTotal)
        guard unc > 0 else { return }
        let packed = enc.endChunk()
        let raw = enc.rawChunk()
        if packed.count < unc && packed.count <= 65_536 {
            var h = Data()
            let mode = !dictDone ? 3 : (!propsSent ? 2 : (needStateReset ? 1 : 0))
            h.append(UInt8(0x80 | (mode << 5) | ((unc - 1) >> 16)))
            h.append(UInt8(((unc - 1) >> 8) & 0xff)); h.append(UInt8((unc - 1) & 0xff))
            h.append(UInt8(((packed.count - 1) >> 8) & 0xff)); h.append(UInt8((packed.count - 1) & 0xff))
            if mode >= 2 { h.append(enc.props.byte) }
            try out.write(h); try out.write(Data(packed))
            dictDone = true; propsSent = true; needStateReset = false
        } else {
            // incompressible: store it (in ≤ 64 KB pieces) and reset the model, as the format requires
            var off = 0
            while off < raw.count {
                let n = min(65_536, raw.count - off)
                var h = Data([dictDone ? 2 : 1, UInt8(((n - 1) >> 8) & 0xff), UInt8((n - 1) & 0xff)])
                h.append(contentsOf: raw[off..<off + n])
                try out.write(h)
                dictDone = true; off += n
            }
            enc.resetState()
            needStateReset = true
        }
    }
}
