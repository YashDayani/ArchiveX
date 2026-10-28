import Foundation

// gzip (RFC 1952): a pull-based decoder usable as a ByteSource, and an encoder usable as a ByteSink.

final class GzipSource: ByteSource {
    private let file: FileIn
    private var filePos: UInt64 = 0
    private var inBuf = Data()
    private var out = Data()
    private var outPos = 0
    private var inflater: Inflater?
    private var crc: UInt32 = 0
    private var isize: UInt32 = 0
    private var eof = false
    private(set) var storedName: String?
    private var memberOpen = false

    init(file: FileIn) throws {
        self.file = file
        try beginMember(first: true)
    }

    private func fill(_ n: Int) throws {
        while inBuf.count < n {
            let d = try file.read(at: filePos, 1 << 20)
            if d.isEmpty { return }
            filePos += UInt64(d.count)
            inBuf.append(d)
        }
    }

    private func beginMember(first: Bool) throws {
        try fill(10)
        guard inBuf.count >= 10, inBuf[inBuf.startIndex] == 0x1f, inBuf[inBuf.startIndex + 1] == 0x8b else {
            if first { throw AXError.corrupt("not a gzip file") }
            eof = true; return                                   // trailing garbage after the last member
        }
        guard inBuf[inBuf.startIndex + 2] == 8 else { throw AXError.unsupported("gzip method \(inBuf[inBuf.startIndex + 2])") }
        let flags = inBuf[inBuf.startIndex + 3]
        var idx = 10
        if flags & 4 != 0 {
            try fill(idx + 2)
            guard inBuf.count >= idx + 2 else { throw AXError.corrupt("truncated gzip header") }
            idx += 2 + Int(inBuf.le16(idx))
        }
        func cString(_ start: Int) throws -> (String, Int) {
            var i = start
            while true {
                try fill(i + 1)
                guard inBuf.count > i else { throw AXError.corrupt("truncated gzip header") }
                if inBuf[inBuf.startIndex + i] == 0 { break }
                i += 1
            }
            let s = String(data: inBuf.subdata(in: inBuf.startIndex + start..<inBuf.startIndex + i), encoding: .isoLatin1) ?? ""
            return (s, i + 1)
        }
        if flags & 8 != 0 { let (n, e) = try cString(idx); if first { storedName = n }; idx = e }
        if flags & 16 != 0 { idx = try cString(idx).1 }
        if flags & 2 != 0 { idx += 2 }
        try fill(idx)
        guard inBuf.count >= idx else { throw AXError.corrupt("truncated gzip header") }
        inBuf.removeFirst(idx)
        inflater = Inflater()
        crc = 0; isize = 0; memberOpen = true
    }

    private func pump() throws {
        if eof { return }
        if inBuf.isEmpty { try fill(1) }
        guard !inBuf.isEmpty else { throw AXError.corrupt("unexpected end of gzip data") }
        guard let inf = inflater else { eof = true; return }
        let before = out.count
        let r = try inf.process(inBuf, final: filePos >= file.size) { self.out.append($0) }
        let produced = out.subdata(in: out.startIndex + before..<out.endIndex)
        crc = CRC32.update(crc, produced)
        isize = isize &+ UInt32(truncatingIfNeeded: produced.count)
        inBuf.removeFirst(inBuf.count - r.unused)
        if r.ended {
            try fill(8)
            guard inBuf.count >= 8 else { throw AXError.corrupt("truncated gzip trailer") }
            guard inBuf.le32(0) == crc, inBuf.le32(4) == isize else { throw AXError.corrupt("gzip CRC mismatch") }
            inBuf.removeFirst(8)
            memberOpen = false; inflater = nil
            try fill(2)
            if inBuf.count >= 2 { try beginMember(first: false) } else { eof = true }
        }
    }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && !eof { try pump() }
        let take = min(n, out.count - outPos)
        let d = out.subdata(in: out.startIndex + outPos..<out.startIndex + outPos + take)
        outPos += take
        if outPos > 4 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }

    func skip(_ n: UInt64) throws { try discard(n) }

    /// Uncompressed size recorded in the trailer (modulo 2^32).
    static func recordedSize(of file: FileIn) -> UInt64? {
        guard file.size >= 18, let t = try? file.read(at: file.size - 4, 4), t.count == 4 else { return nil }
        return UInt64(t.le32(0))
    }
}

final class GzipSink: ByteSink {
    private let out: FileOut
    private let deflater: Deflater
    private var crc: UInt32 = 0
    private var size: UInt32 = 0

    init(out: FileOut, name: String?, mtime: Date) throws {
        self.out = out
        deflater = try Deflater(encode: true)
        var h = Data([0x1f, 0x8b, 8, name == nil ? 0 : 8])
        h.put32(UInt32(max(0, min(4_294_967_295, mtime.timeIntervalSince1970))))
        h.append(contentsOf: [0, 3])
        if let n = name { h.append(Data(n.utf8.filter { $0 != 0 })); h.append(0) }
        try out.write(h)
    }

    func write(_ data: Data) throws {
        crc = CRC32.update(crc, data)
        size = size &+ UInt32(truncatingIfNeeded: data.count)
        try deflater.process(data, final: false) { try self.out.write($0) }
    }

    func finish() throws {
        try deflater.process(Data(), final: true) { try self.out.write($0) }
        var t = Data(); t.put32(crc); t.put32(size)
        try out.write(t)
    }
}
