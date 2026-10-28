import Foundation

// POSIX ustar + pax + GNU long-name reader, and a ustar/pax writer.

/// Sequential byte input (a plain file, or a decompressing stream).
protocol ByteSource: AnyObject {
    /// Up to `n` bytes; empty at end of input.
    func read(_ n: Int) throws -> Data
    func skip(_ n: UInt64) throws
}

extension ByteSource {
    func readExactly(_ n: Int) throws -> Data {
        var out = Data()
        while out.count < n {
            let d = try read(n - out.count)
            if d.isEmpty { throw AXError.corrupt("unexpected end of data") }
            out.append(d)
        }
        return out
    }
    /// Like readExactly but returns what is there at a clean end of input.
    func readUpTo(_ n: Int) throws -> Data {
        var out = Data()
        while out.count < n {
            let d = try read(n - out.count)
            if d.isEmpty { break }
            out.append(d)
        }
        return out
    }
    func discard(_ n: UInt64) throws {
        var left = n
        while left > 0 {
            let d = try read(Int(min(left, 1 << 20)))
            if d.isEmpty { throw AXError.corrupt("unexpected end of data") }
            left -= UInt64(d.count)
        }
    }
}

final class FileSource: ByteSource {
    private let file: FileIn
    private(set) var pos: UInt64 = 0
    init(_ file: FileIn) { self.file = file }
    func read(_ n: Int) throws -> Data {
        let d = try file.read(at: pos, min(n, 1 << 20)); pos += UInt64(d.count); return d
    }
    func skip(_ n: UInt64) throws { pos += n }
}

struct TarEntry {
    var path: String
    var isDir: Bool
    var type: UInt8
    var size: UInt64
    var mode: UInt32
    var mtime: Date?
    var link: String
    var raw: Data            // every header block that introduced this entry (pax / long-name included)
    var uid = 0
}

final class TarReader {
    private let src: ByteSource
    private var sawEntry = false

    init(_ src: ByteSource) { self.src = src }

    private static func octal(_ d: Data) -> UInt64 {
        if let f = d.first, f & 0x80 != 0 {                      // GNU base-256 for huge values
            var v: UInt64 = UInt64(f & 0x7f)
            for b in d.dropFirst() { v = v << 8 | UInt64(b) }
            return v
        }
        var v: UInt64 = 0
        for b in d {
            if b == 0 || b == 0x20 { if v == 0 && b == 0x20 { continue } else { break } }
            guard b >= 0x30, b <= 0x37 else { break }
            v = v << 3 | UInt64(b - 0x30)
        }
        return v
    }

    private static func string(_ d: Data) -> String {
        let end = d.firstIndex(of: 0) ?? d.endIndex
        let s = d[d.startIndex..<end]
        return String(data: s, encoding: .utf8) ?? String(data: s, encoding: .isoLatin1) ?? ""
    }

    private func pad(_ size: UInt64) -> UInt64 { (512 - size % 512) % 512 }

    private func parsePax(_ data: Data) -> [String: String] {
        var out: [String: String] = [:]
        var i = data.startIndex
        while i < data.endIndex {
            guard let sp = data[i...].firstIndex(of: 0x20),
                  let len = Int(String(decoding: data[i..<sp], as: UTF8.self)), len > 0,
                  i + len <= data.endIndex else { break }
            let rec = data[(sp + 1)..<(i + len)]
            if let eq = rec.firstIndex(of: 0x3d) {
                let key = String(decoding: rec[rec.startIndex..<eq], as: UTF8.self)
                var val = rec[(eq + 1)...]
                if val.last == 0x0a { val = val.dropLast() }
                out[key] = String(decoding: val, as: UTF8.self)
            }
            i += len
        }
        return out
    }

    /// Reads the next entry's header(s); leaves the source positioned at its data. nil at end of archive.
    func next() throws -> TarEntry? {
        var raw = Data()
        var longName: String?, longLink: String?
        var pax: [String: String] = [:]
        while true {
            let block = try src.readUpTo(512)
            if block.count < 512 {
                if block.isEmpty || block.allSatisfy({ $0 == 0 }) { return nil }
                throw AXError.corrupt("truncated TAR header")
            }
            if block.allSatisfy({ $0 == 0 }) { return nil }

            // checksum: sum of all bytes with the checksum field read as spaces
            var sum: UInt64 = 0
            for (i, b) in block.enumerated() { sum += (i >= 148 && i < 156) ? 0x20 : UInt64(b) }
            let stored = TarReader.octal(block.subdata(in: block.startIndex + 148..<block.startIndex + 156))
            guard sum == stored else {
                if !sawEntry { throw AXError.corrupt("not a TAR archive") }
                throw AXError.corrupt("TAR header checksum mismatch")
            }
            sawEntry = true
            raw.append(block)

            let type = block[block.startIndex + 156]
            let size = TarReader.octal(block.subdata(in: block.startIndex + 124..<block.startIndex + 136))

            if type == UInt8(ascii: "x") || type == UInt8(ascii: "g") || type == UInt8(ascii: "L") || type == UInt8(ascii: "K") {
                guard size < 16 << 20 else { throw AXError.corrupt("oversized TAR extension header") }
                let data = try src.readExactly(Int(size))
                try src.discard(pad(size))
                raw.append(data)
                if pad(size) > 0 { raw.append(Data(count: Int(pad(size)))) }
                switch type {
                case UInt8(ascii: "x"): pax.merge(parsePax(data)) { _, new in new }
                case UInt8(ascii: "L"): longName = TarReader.string(data)
                case UInt8(ascii: "K"): longLink = TarReader.string(data)
                default: break                                   // global pax: ignored
                }
                continue
            }

            var name = TarReader.string(block.subdata(in: block.startIndex..<block.startIndex + 100))
            let magic = TarReader.string(block.subdata(in: block.startIndex + 257..<block.startIndex + 262))
            if magic == "ustar" {
                let prefix = TarReader.string(block.subdata(in: block.startIndex + 345..<block.startIndex + 500))
                if !prefix.isEmpty { name = prefix + "/" + name }
            }
            var link = TarReader.string(block.subdata(in: block.startIndex + 157..<block.startIndex + 257))
            if let p = pax["path"] ?? longName { name = p }
            if let l = pax["linkpath"] ?? longLink { link = l }
            let realSize = pax["size"].flatMap(UInt64.init) ?? size
            var mtime = Date(timeIntervalSince1970: TimeInterval(TarReader.octal(block.subdata(in: block.startIndex + 136..<block.startIndex + 148))))
            if let m = pax["mtime"], let v = Double(m) { mtime = Date(timeIntervalSince1970: v) }
            let mode = UInt32(TarReader.octal(block.subdata(in: block.startIndex + 100..<block.startIndex + 108)))
            let isDir = type == UInt8(ascii: "5") || name.hasSuffix("/")
            return TarEntry(path: name.trimmingCharacters(in: CharacterSet(charactersIn: "/")), isDir: isDir, type: type,
                            size: isDir ? 0 : realSize, mode: mode, mtime: mtime, link: link, raw: raw)
        }
    }

    func copyData(_ e: TarEntry, to sink: ByteSink, progress: ProgressTracker?) throws {
        var left = e.size
        while left > 0 {
            let d = try src.read(Int(min(left, 1 << 20)))
            if d.isEmpty { throw AXError.corrupt("unexpected end of TAR data") }
            left -= UInt64(d.count)
            try sink.write(d)
            try progress?.add(d.count)
        }
        try src.discard(pad(e.size))
    }

    func skipData(_ e: TarEntry) throws {
        try src.skip(e.size + pad(e.size))
        if src is GzipSource { /* GzipSource.skip decodes and discards */ }
    }

    var isFile: (TarEntry) -> Bool { { $0.type == 0 || $0.type == UInt8(ascii: "0") || $0.type == UInt8(ascii: "7") } }
}

// MARK: - Writer

final class TarWriter {
    private let sink: ByteSink

    init(sink: ByteSink) { self.sink = sink }

    private func octal(_ v: UInt64, width: Int) -> Data {
        var s = String(v, radix: 8)
        if s.count < width - 1 { s = String(repeating: "0", count: width - 1 - s.count) + s }
        return Data(s.utf8) + Data([0])
    }

    private func fits(_ v: UInt64, width: Int) -> Bool { v < (1 << (3 * UInt64(width - 1))) }

    private func record(_ key: String, _ value: String) -> Data {
        let body = " \(key)=\(value)\n"
        var len = body.utf8.count + 1
        while String(len).utf8.count + body.utf8.count != len { len = String(len).utf8.count + body.utf8.count }
        return Data("\(len)\(body)".utf8)
    }

    private func block(name: Data, mode: UInt32, uid: UInt64, gid: UInt64, size: UInt64, mtime: UInt64, type: UInt8,
                       link: Data, prefix: Data) -> Data {
        var h = Data(count: 512)
        func put(_ d: Data, at o: Int, max: Int) { h.replaceSubrange(o..<o + min(d.count, max), with: d.prefix(max)) }
        put(name, at: 0, max: 100)
        put(octal(UInt64(mode & 0o7777), width: 8), at: 100, max: 8)
        put(octal(uid, width: 8), at: 108, max: 8)
        put(octal(gid, width: 8), at: 116, max: 8)
        put(octal(size, width: 12), at: 124, max: 12)
        put(octal(mtime, width: 12), at: 136, max: 12)
        h.replaceSubrange(148..<156, with: Data(repeating: 0x20, count: 8))
        h[156] = type
        put(link, at: 157, max: 100)
        put(Data("ustar\0".utf8), at: 257, max: 6)
        put(Data("00".utf8), at: 263, max: 2)
        put(prefix, at: 345, max: 155)
        let sum = h.reduce(UInt64(0)) { $0 + UInt64($1) }
        put(Data(String(format: "%06o", sum).utf8) + Data([0, 0x20]), at: 148, max: 8)
        return h
    }

    private func writeHeader(name rawName: String, mode: UInt32, uid: UInt64, gid: UInt64, size: UInt64, mtime: Date,
                             type: UInt8, link: String) throws {
        var name = rawName
        var pax = Data()
        let nameBytes = Data(name.utf8)
        let ascii = nameBytes.allSatisfy { $0 < 0x80 }
        var prefix = Data()
        var shortName = nameBytes

        if !ascii || nameBytes.count > 100 {
            // try the ustar prefix split first (ASCII only), otherwise fall back to a pax record
            var split = false
            if ascii, let idx = name.indices.filter({ name[$0] == "/" }).last(where: { i in
                let p = name[name.startIndex..<i], r = name[name.index(after: i)...]
                return p.utf8.count <= 155 && r.utf8.count <= 100 && !r.isEmpty
            }) {
                prefix = Data(name[name.startIndex..<idx].utf8)
                shortName = Data(name[name.index(after: idx)...].utf8)
                split = true
            }
            if !split {
                pax.append(record("path", name))
                shortName = Data(name.unicodeScalars.map { $0.isASCII ? UInt8($0.value) : UInt8(ascii: "_") }.prefix(100))
            }
        }
        let linkBytes = Data(link.utf8)
        if linkBytes.count > 100 || !linkBytes.allSatisfy({ $0 < 0x80 }) { pax.append(record("linkpath", link)) }
        if !fits(size, width: 12) { pax.append(record("size", String(size))) }
        let secs = UInt64(max(0, mtime.timeIntervalSince1970))
        if !fits(secs, width: 12) { pax.append(record("mtime", String(secs))) }
        name = ""

        if !pax.isEmpty {
            try sink.write(block(name: Data("PaxHeader".utf8), mode: 0o644, uid: 0, gid: 0, size: UInt64(pax.count), mtime: secs,
                                 type: UInt8(ascii: "x"), link: Data(), prefix: Data()))
            try sink.write(pax)
            let pad = (512 - pax.count % 512) % 512
            if pad > 0 { try sink.write(Data(count: pad)) }
        }
        try sink.write(block(name: shortName, mode: mode, uid: uid, gid: gid, size: fits(size, width: 12) ? size : 0,
                             mtime: fits(secs, width: 12) ? secs : 0, type: type, link: linkBytes, prefix: prefix))
    }

    func addDirectory(name: String, mode: UInt32, mtime: Date) throws {
        try writeHeader(name: name.hasSuffix("/") ? name : name + "/", mode: mode, uid: 0, gid: 0, size: 0, mtime: mtime,
                        type: UInt8(ascii: "5"), link: "")
    }

    func addSymlink(name: String, target: String, mode: UInt32, mtime: Date) throws {
        try writeHeader(name: name, mode: mode, uid: 0, gid: 0, size: 0, mtime: mtime, type: UInt8(ascii: "2"), link: target)
    }

    func addFile(source: URL, name: String, mode: UInt32, mtime: Date, progress: ProgressTracker?) throws {
        let src = try FileIn(source)
        try writeHeader(name: name, mode: mode, uid: 0, gid: 0, size: src.size, mtime: mtime, type: UInt8(ascii: "0"), link: "")
        var off: UInt64 = 0
        while off < src.size {
            let d = try src.read(at: off, 1 << 20)
            if d.isEmpty { throw AXError.io("“\(source.lastPathComponent)” changed while it was being archived.") }
            off += UInt64(d.count)
            try sink.write(d)
            try progress?.add(d.count)
        }
        let pad = Int((512 - src.size % 512) % 512)
        if pad > 0 { try sink.write(Data(count: pad)) }
    }

    /// Copies an existing entry byte-for-byte (used when editing a tar).
    func addRaw(_ e: TarEntry, from reader: TarReader, progress: ProgressTracker?) throws {
        try sink.write(e.raw)
        try reader.copyData(e, to: sink, progress: progress)
        let pad = Int((512 - e.size % 512) % 512)
        if pad > 0 { try sink.write(Data(count: pad)) }
    }

    func finish() throws {
        try sink.write(Data(count: 1024))
        try sink.finish()
    }
}
