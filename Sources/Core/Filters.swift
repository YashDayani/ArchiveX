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
