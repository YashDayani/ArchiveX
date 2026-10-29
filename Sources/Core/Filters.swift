import Foundation

// Branch-call-jump (BCJ) executable filters and Delta, used by XZ and 7z in front of LZMA2.
// Written from the published descriptions of the transforms.

protocol StreamFilter: AnyObject {
    /// Transforms `buf[0..<count]` in place; returns how many leading bytes are final.
    /// `nowPos` is the stream offset of buf[0]. When `final` every byte is final.
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int
}

final class BCJx86: StreamFilter {
    private var prevMask: UInt32 = 0
    private var prevPos: UInt32 = UInt32.max - 4          // (uint32)(-5)
    private static let allowed: [Bool] = [true, true, true, false, true, false, false, false]
    private static let bitNumber: [UInt32] = [0, 1, 2, 2, 3, 3, 3, 3]
    @inline(__always) private func test(_ b: UInt8) -> Bool { b == 0 || b == 0xff }

    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        guard count >= 5 else { return final ? count : 0 }
        let pos32 = UInt32(truncatingIfNeeded: nowPos)
        if pos32 &- prevPos > 5 { prevPos = pos32 &- 5 }
        let limit = count - 5
        var i = 0
        while i <= limit {
            var b = buf[i]
            if b != 0xe8 && b != 0xe9 { i += 1; continue }
            let offset = pos32 &+ UInt32(i) &- prevPos
            prevPos = pos32 &+ UInt32(i)
            if offset > 5 { prevMask = 0 }
            else { for _ in 0..<offset { prevMask &= 0x77; prevMask <<= 1 } }
            b = buf[i + 4]
            if test(b) && BCJx86.allowed[Int((prevMask >> 1) & 7)] && (prevMask >> 1) < 0x10 {
                var src = UInt32(b) << 24 | UInt32(buf[i + 3]) << 16 | UInt32(buf[i + 2]) << 8 | UInt32(buf[i + 1])
                var dest: UInt32
                while true {
                    dest = decode ? src &- (pos32 &+ UInt32(i) &+ 5) : src &+ (pos32 &+ UInt32(i) &+ 5)
                    if prevMask == 0 { break }
                    let k = BCJx86.bitNumber[Int(prevMask >> 1)]
                    b = UInt8(truncatingIfNeeded: dest >> (24 - k * 8))
                    if !test(b) { break }
                    src = dest ^ ((1 << (32 - k * 8)) &- 1)
                }
                buf[i + 4] = UInt8(truncatingIfNeeded: ~(((dest >> 24) & 1) &- 1))
                buf[i + 3] = UInt8(truncatingIfNeeded: dest >> 16)
                buf[i + 2] = UInt8(truncatingIfNeeded: dest >> 8)
                buf[i + 1] = UInt8(truncatingIfNeeded: dest)
                i += 5
                prevMask = 0
            } else {
                i += 1
                prevMask |= 1
                if test(b) { prevMask |= 0x10 }
            }
        }
        return final ? count : i
    }
}

final class BCJARM: StreamFilter {
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        var i = 0
        while i + 4 <= count {
            if buf[i + 3] == 0xeb {
                var src = UInt32(buf[i + 2]) << 16 | UInt32(buf[i + 1]) << 8 | UInt32(buf[i])
                src <<= 2
                let pc = UInt32(truncatingIfNeeded: nowPos) &+ UInt32(i) &+ 8
                let dest = (decode ? src &- pc : src &+ pc) >> 2
                buf[i + 2] = UInt8(truncatingIfNeeded: dest >> 16); buf[i + 1] = UInt8(truncatingIfNeeded: dest >> 8); buf[i] = UInt8(truncatingIfNeeded: dest)
            }
            i += 4
        }
        return final ? count : i
    }
}

final class BCJARM64: StreamFilter {
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        var i = 0
        while i + 4 <= count {
            var instr = UInt32(buf[i]) | UInt32(buf[i + 1]) << 8 | UInt32(buf[i + 2]) << 16 | UInt32(buf[i + 3]) << 24
            var pc = UInt32(truncatingIfNeeded: nowPos) &+ UInt32(i)
            var changed = false
            if instr >> 26 == 0x25 {                                  // BL
                let src = instr
                instr = 0x9400_0000
                pc >>= 2
                if decode { pc = 0 &- pc }
                instr |= (src &+ pc) & 0x03ff_ffff
                changed = true
            } else if instr & 0x9f00_0000 == 0x9000_0000 {            // ADRP
                let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001f_fffc)
                if (src &+ 0x0002_0000) & 0x001c_0000 == 0 {
                    instr &= 0x9000_001f
                    pc >>= 12
                    if decode { pc = 0 &- pc }
                    let dest = src &+ pc
                    instr |= (dest & 3) << 29
                    instr |= (dest & 0x0003_fffc) << 3
                    instr |= (0 &- (dest & 0x0002_0000)) & 0x00e0_0000
                    changed = true
                }
            }
            if changed {
                buf[i] = UInt8(truncatingIfNeeded: instr); buf[i + 1] = UInt8(truncatingIfNeeded: instr >> 8)
                buf[i + 2] = UInt8(truncatingIfNeeded: instr >> 16); buf[i + 3] = UInt8(truncatingIfNeeded: instr >> 24)
            }
            i += 4
        }
        return final ? count : i
    }
}

/// PowerPC (big-endian) branch converter.
final class BCJPPC: StreamFilter {
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        var i = 0
        while i + 4 <= count {
            if buf[i] >> 2 == 0x12 && buf[i + 3] & 3 == 1 {
                let src = UInt32(buf[i] & 3) << 24 | UInt32(buf[i + 1]) << 16 | UInt32(buf[i + 2]) << 8 | UInt32(buf[i + 3] & ~3)
                let pc = UInt32(truncatingIfNeeded: nowPos) &+ UInt32(i)
                let dest = decode ? src &- pc : src &+ pc
                buf[i] = 0x48 | UInt8(truncatingIfNeeded: (dest >> 24) & 3)
                buf[i + 1] = UInt8(truncatingIfNeeded: dest >> 16)
                buf[i + 2] = UInt8(truncatingIfNeeded: dest >> 8)
                buf[i + 3] = (buf[i + 3] & 3) | UInt8(truncatingIfNeeded: dest & ~3)
            }
            i += 4
        }
        return final ? count : i
    }
}

/// SPARC call converter.
final class BCJSPARC: StreamFilter {
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        var i = 0
        while i + 4 <= count {
            if (buf[i] == 0x40 && buf[i + 1] & 0xc0 == 0) || (buf[i] == 0x7f && buf[i + 1] & 0xc0 == 0xc0) {
                var src = UInt32(buf[i]) << 24 | UInt32(buf[i + 1]) << 16 | UInt32(buf[i + 2]) << 8 | UInt32(buf[i + 3])
                src <<= 2
                let pc = UInt32(truncatingIfNeeded: nowPos) &+ UInt32(i)
                var dest = decode ? src &- pc : src &+ pc
                dest >>= 2
                dest = (((0 &- ((dest >> 22) & 1)) << 22) & 0x3fff_ffff) | (dest & 0x3f_ffff) | 0x4000_0000
                buf[i] = UInt8(truncatingIfNeeded: dest >> 24); buf[i + 1] = UInt8(truncatingIfNeeded: dest >> 16)
                buf[i + 2] = UInt8(truncatingIfNeeded: dest >> 8); buf[i + 3] = UInt8(truncatingIfNeeded: dest)
            }
            i += 4
        }
        return final ? count : i
    }
}

/// ARM Thumb branch-with-link converter.
final class BCJARMT: StreamFilter {
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        var i = 0
        while i + 4 <= count {
            if buf[i + 1] & 0xf8 == 0xf0 && buf[i + 3] & 0xf8 == 0xf8 {
                var src = (UInt32(buf[i + 1] & 7) << 19) | (UInt32(buf[i]) << 11) | (UInt32(buf[i + 3] & 7) << 8) | UInt32(buf[i + 2])
                src <<= 1
                let pc = UInt32(truncatingIfNeeded: nowPos) &+ UInt32(i) &+ 4
                var dest = decode ? src &- pc : src &+ pc
                dest >>= 1
                buf[i + 1] = 0xf0 | UInt8(truncatingIfNeeded: (dest >> 19) & 7)
                buf[i] = UInt8(truncatingIfNeeded: dest >> 11)
                buf[i + 3] = 0xf8 | UInt8(truncatingIfNeeded: (dest >> 8) & 7)
                buf[i + 2] = UInt8(truncatingIfNeeded: dest)
                i += 2
            }
            i += 2
        }
        return final ? count : i
    }
}

/// Itanium branch converter.
final class BCJIA64: StreamFilter {
    private static let table: [UInt32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0]
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        var i = 0
        while i + 16 <= count {
            let mask = BCJIA64.table[Int(buf[i] & 0x1f)]
            var bitPos = 5
            for slot in 0..<3 {
                defer { bitPos += 41 }
                if (mask >> UInt32(slot)) & 1 == 0 { continue }
                let bytePos = bitPos >> 3, bitRes = UInt64(bitPos & 7)
                var instruction: UInt64 = 0
                for j in 0..<6 { instruction |= UInt64(buf[i + j + bytePos]) << UInt64(8 * j) }
                var norm = instruction >> bitRes
                if (norm >> 37) & 0xf == 0x5 && (norm >> 9) & 0x7 == 0 {
                    var src = UInt32(truncatingIfNeeded: (norm >> 13) & 0xf_ffff)
                    src |= UInt32(truncatingIfNeeded: (norm >> 36) & 1) << 20
                    src <<= 4
                    let pc = UInt32(truncatingIfNeeded: nowPos) &+ UInt32(i)
                    var dest = decode ? src &- pc : src &+ pc
                    dest >>= 4
                    norm &= ~(UInt64(0x8f_ffff) << 13)
                    norm |= UInt64(dest & 0xf_ffff) << 13
                    norm |= UInt64(dest & 0x10_0000) << (36 - 20)
                    instruction &= (UInt64(1) << bitRes) - 1
                    instruction |= norm << bitRes
                    for j in 0..<6 { buf[i + j + bytePos] = UInt8(truncatingIfNeeded: instruction >> UInt64(8 * j)) }
                }
            }
            i += 16
        }
        return final ? count : i
    }
}

final class DeltaFilter: StreamFilter {
    private let dist: Int
    private var history = [UInt8](repeating: 0, count: 256)
    private var pos = 0
    init(distance: Int) { dist = max(1, min(256, distance)) }
    func process(_ buf: inout [UInt8], count: Int, nowPos: UInt64, decode: Bool, final: Bool) -> Int {
        for i in 0..<count {
            let prev = history[(pos - dist) & 255]
            let v = decode ? buf[i] &+ prev : buf[i] &- prev
            // history always stores decoded bytes
            history[pos & 255] = decode ? v : buf[i]
            buf[i] = v
            pos += 1
        }
        return count
    }
}

/// Applies a StreamFilter to another source (decoding direction).
final class FilterSource: ByteSource {
    private let input: ByteSource
    private let filter: StreamFilter
    private var raw = [UInt8]()           // bytes read but not yet passed through the filter
    private var ready = [UInt8]()
    private var readyPos = 0
    private var nowPos: UInt64 = 0
    private var eof = false

    init(input: ByteSource, filter: StreamFilter) { self.input = input; self.filter = filter }

    private func pump() throws {
        let d = try input.read(1 << 16)
        if d.isEmpty { eof = true } else { raw.append(contentsOf: d) }
        let n = filter.process(&raw, count: raw.count, nowPos: nowPos, decode: true, final: eof)
        ready.append(contentsOf: raw[0..<n])
        raw.removeFirst(n)
        nowPos &+= UInt64(n)
    }

    func read(_ n: Int) throws -> Data {
        while ready.count - readyPos < n && !(eof && raw.isEmpty) { try pump() }
        let take = min(n, ready.count - readyPos)
        let d = Data(ready[readyPos..<readyPos + take])
        readyPos += take
        if readyPos > 1 << 20 { ready.removeFirst(readyPos); readyPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

/// Applies a StreamFilter on the way into a sink (encoding direction).
final class FilterSink: ByteSink {
    private let out: ByteSink
    private let filter: StreamFilter
    private var raw = [UInt8]()
    private var nowPos: UInt64 = 0

    init(out: ByteSink, filter: StreamFilter) { self.out = out; self.filter = filter }

    func write(_ data: Data) throws {
        raw.append(contentsOf: data)
        let n = filter.process(&raw, count: raw.count, nowPos: nowPos, decode: false, final: false)
        if n > 0 { try out.write(Data(raw[0..<n])); raw.removeFirst(n); nowPos &+= UInt64(n) }
    }

    func finish() throws {
        let n = filter.process(&raw, count: raw.count, nowPos: nowPos, decode: false, final: true)
        if n > 0 { try out.write(Data(raw[0..<n])) }
        raw.removeAll()
    }
}

// MARK: - BCJ2 (7z coder 0303011B)

/// x86 branch converter with four input streams: the main bytes, the absolute CALL targets, the absolute JMP targets
/// and a range-coded stream of "was this branch converted" flags.
final class Bcj2Source: ByteSource {
    private final class Reader {
        let src: ByteSource
        var buf = [UInt8](); var pos = 0
        init(_ s: ByteSource) { src = s }
        @inline(__always) func next() throws -> UInt8? {
            if pos == buf.count {
                let d = try src.read(1 << 16)
                if d.isEmpty { return nil }
                buf = [UInt8](d); pos = 0
            }
            defer { pos += 1 }
            return buf[pos]
        }
    }
    private let main: Reader, call: Reader, jump: Reader, rc: Reader
    private var probs = [UInt32](repeating: 1 << 10, count: 258)
    private var range: UInt32 = 0xffff_ffff
    private var code: UInt32 = 0
    private var prev: UInt8 = 0
    private var outPos: UInt64 = 0
    private let outSize: UInt64
    private var pending = [UInt8]()            // converted address bytes not yet returned
    private var started = false

    init(main: ByteSource, call: ByteSource, jump: ByteSource, rc: ByteSource, outSize: UInt64) {
        self.main = Reader(main); self.call = Reader(call); self.jump = Reader(jump); self.rc = Reader(rc); self.outSize = outSize
    }

    private func rcByte() throws -> UInt32 {
        guard let b = try rc.next() else { throw AXError.corrupt("truncated BCJ2 data") }
        return UInt32(b)
    }

    func read(_ n: Int) throws -> Data {
        if !started {
            started = true
            for _ in 0..<5 { code = code << 8 | (try rcByte()) }
        }
        var out = [UInt8]()
        out.reserveCapacity(min(n, 1 << 16))
        while out.count < n, outPos < outSize {
            if !pending.isEmpty { out.append(pending.removeFirst()); outPos += 1; continue }
            guard let b = try main.next() else { throw AXError.corrupt("truncated BCJ2 data") }
            out.append(b); outPos += 1
            let isJcc = prev == 0x0f && (b & 0xf0) == 0x80
            if !((b & 0xfe) == 0xe8 || isJcc) { prev = b; continue }
            if outPos == outSize { break }
            let pi = b == 0xe8 ? Int(prev) : (b == 0xe9 ? 256 : 257)
            let ttt = probs[pi]
            let bound = (range >> 11) * ttt
            var bit: Bool
            if code < bound { range = bound; probs[pi] = ttt + ((2048 - ttt) >> 5); bit = false }
            else { range -= bound; code -= bound; probs[pi] = ttt - (ttt >> 5); bit = true }
            if range < (1 << 24) { range <<= 8; code = code << 8 | (try rcByte()) }
            if !bit { prev = b; continue }
            let src = b == 0xe8 ? call : jump
            var v: UInt32 = 0
            for _ in 0..<4 { guard let x = try src.next() else { throw AXError.corrupt("truncated BCJ2 data") }; v = v << 8 | UInt32(x) }
            let dest = v &- UInt32(truncatingIfNeeded: outPos + 4)
            pending = [UInt8(truncatingIfNeeded: dest), UInt8(truncatingIfNeeded: dest >> 8), UInt8(truncatingIfNeeded: dest >> 16), UInt8(truncatingIfNeeded: dest >> 24)]
            prev = pending[3]
        }
        return Data(out)
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}
