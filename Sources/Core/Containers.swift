import Foundation

// Read-only package and legacy formats that share one simple model: a list of items, each of which can be opened as a
// decoded byte stream. AR/DEB, compress (.Z), RPM, XAR/PKG and CAB live here; disk images are in Dmg.swift.

struct ContainerItem {
    var path: String
    var isDir = false
    var size: UInt64 = 0
    var sizeKnown = true
    var packed: UInt64 = 0
    var mtime: Date?
    var mode: UInt32?
    var link: String?
    var crc: UInt32?
}

protocol ContainerArchive: AnyObject {
    var details: String { get }
    var items: [ContainerItem] { get }
    /// The decoded bytes of `items[i]`.
    func stream(_ i: Int) throws -> ByteSource
}

enum Container {
    static func listing(_ a: ContainerArchive) -> Listing {
        var l = Listing()
        l.details = a.details
        l.entries = a.items.map { it in
            let size = Int64(it.size)
            return ArchiveEntry(path: SafePath.clean(it.path) ?? it.path, isDir: it.isDir, size: size, packed: Int64(it.packed),
                                ratio: (!it.isDir && size > 0 && it.packed > 0) ? "\(min(100, Int(Double(it.packed) / Double(size) * 100)))%" : "",
                                mtime: Dates.text(it.mtime), crc: it.crc.map { String(format: "%08X", $0) } ?? "", attrs: "", encrypted: false)
        }
        return l
    }

    private static func copy(_ a: ContainerArchive, _ i: Int, to sink: ByteSink, progress: ProgressTracker?) throws {
        let it = a.items[i]
        let s = try a.stream(i)
        var n: UInt64 = 0
        var crc: UInt32 = 0
        while true {
            let d = try s.read(1 << 20)
            if d.isEmpty { break }
            crc = CRC32.update(crc, d); n += UInt64(d.count)
            try sink.write(d); try progress?.add(d.count)
        }
        if it.sizeKnown, n != it.size { throw AXError.corrupt("“\(it.path)” is shorter or longer than recorded") }
        if let want = it.crc, want != crc { throw AXError.corrupt("CRC mismatch in “\(it.path)”") }
    }

    static func extract(_ a: ContainerArchive, to ex: Extractor, progress: ProgressTracker?) throws {
        var dirs: [(URL, UInt32?, Date?)] = []
        for (i, it) in a.items.enumerated() {
            try Task.checkCancellation()
            guard let clean = SafePath.clean(it.path) else { if !it.path.isEmpty { _ = try ex.destination(for: it.path, isDir: it.isDir) }; continue }
            guard ex.isSelected(clean) else { continue }
            if it.isDir {
                if ex.keepPaths, let u = try ex.destination(for: it.path, isDir: true) {
                    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
                    dirs.append((u, it.mode, it.mtime))
                }
                continue
            }
            if let t = it.link { if let u = try ex.destination(for: it.path, isDir: false) { ex.makeSymlink(at: u, target: t) }; continue }
            guard let u = try ex.destination(for: it.path, isDir: false) else { continue }
            let out = try FileOut(u)
            do { try copy(a, i, to: out, progress: progress) } catch { try? FileManager.default.removeItem(at: u); throw error }
            ex.finalize(u, mode: it.mode, mtime: it.mtime)
        }
        for (u, m, t) in dirs.reversed() { ex.finalize(u, mode: m, mtime: t) }
    }

    static func test(_ a: ContainerArchive, progress: ProgressTracker?) throws {
        for (i, it) in a.items.enumerated() where !it.isDir && it.link == nil { try Task.checkCancellation(); try copy(a, i, to: NullSink(), progress: progress) }
    }

    static func total(_ a: ContainerArchive) -> Int64 {
        a.items.reduce(Int64(0)) { $0 + Int64($1.isDir || $1.link != nil ? 0 : ($1.sizeKnown ? $1.size : $1.packed * 3)) }
    }
}

@inline(__always) private func be16(_ d: Data, _ o: Int) -> Int { Int(d[d.startIndex + o]) << 8 | Int(d[d.startIndex + o + 1]) }
@inline(__always) private func be32(_ d: Data, _ o: Int) -> Int {
    Int(d[d.startIndex + o]) << 24 | Int(d[d.startIndex + o + 1]) << 16 | Int(d[d.startIndex + o + 2]) << 8 | Int(d[d.startIndex + o + 3])
}
@inline(__always) private func be64(_ d: Data, _ o: Int) -> UInt64 { UInt64(be32(d, o)) << 32 | UInt64(be32(d, o + 4)) }

/// Reads a window of a file as a ByteSource.
private func windowSource(_ url: URL, _ offset: UInt64, _ length: UInt64) -> ByteSource {
    if let f = try? FileIn(window: url, offset: offset, length: length) { return FileSource(f) }
    return ClosureSource { Data() }
}

/// A zlib stream (2-byte header, deflate data, checksum ignored).
final class ZlibSource: ByteSource {
    private var inner: ByteSource?
    private let input: ByteSource
    init(_ i: ByteSource) { input = i }
    func read(_ n: Int) throws -> Data {
        if inner == nil {
            let h = try input.readExactly(2)
            guard h[h.startIndex] & 0x0f == 8 else { throw AXError.corrupt("bad zlib header") }
            inner = InflateSource(input: input)
        }
        return try inner!.read(n)
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

// MARK: - ar archives and Debian packages

final class ArArchive: ContainerArchive {
    private let file: FileIn
    private(set) var items: [ContainerItem] = []
    private var ranges: [(UInt64, UInt64)] = []
    private(set) var details = "ar"

    init(url: URL) throws {
        file = try FileIn(url)
        guard file.size >= 8, String(decoding: try file.readExactly(at: 0, 8), as: UTF8.self) == "!<arch>\n" else { throw AXError.corrupt("not an ar archive") }
        var pos: UInt64 = 8
        var longNames = Data()
        while pos + 60 <= file.size {
            let h = try file.readExactly(at: pos, 60)
            guard h[h.startIndex + 58] == 0x60, h[h.startIndex + 59] == 0x0a else { throw AXError.corrupt("bad ar member header") }
            func field(_ o: Int, _ n: Int) -> String { String(decoding: h.subdata(in: h.startIndex + o..<h.startIndex + o + n), as: UTF8.self).trimmingCharacters(in: .whitespaces) }
            var name = field(0, 16)
            let mtime = TimeInterval(field(16, 12)) ?? 0
            let mode = UInt32(field(40, 8), radix: 8) ?? 0o644
            var size = UInt64(field(48, 10)) ?? 0
            var dataPos = pos + 60
            guard dataPos + size <= file.size else { throw AXError.corrupt("ar archive is truncated") }
            let advance = (size + 1) & ~1
            if name == "//" {
                longNames = try file.readExactly(at: dataPos, Int(size))
            } else if name == "/" || name == "/SYM64/" || name.hasPrefix("__.SYMDEF") {
                // symbol table
            } else {
                if name.hasPrefix("#1/"), let n = Int(name.dropFirst(3)), UInt64(n) <= size {          // BSD long name
                    let nd = try file.readExactly(at: dataPos, n)
                    name = String(decoding: nd.prefix { $0 != 0 }, as: UTF8.self)
                    dataPos += UInt64(n); size -= UInt64(n)
                } else if name.hasPrefix("/"), let off = Int(name.dropFirst()), off < longNames.count {  // GNU long name
                    let tail = longNames.subdata(in: longNames.startIndex + off..<longNames.endIndex)
                    let end = tail.firstIndex(of: 0x0a) ?? tail.endIndex
                    name = String(decoding: tail[tail.startIndex..<end], as: UTF8.self)
                }
                if name.hasSuffix("/") { name.removeLast() }
                if name.hasPrefix("__.SYMDEF") { pos += 60 + advance; continue }
                items.append(ContainerItem(path: name, size: size, packed: size, mtime: Date(timeIntervalSince1970: mtime), mode: mode & 0o7777))
                ranges.append((dataPos, size))
            }
            pos += 60 + advance
        }
        if items.first?.path == "debian-binary" { details = "Debian package (ar)" }
    }

    func stream(_ i: Int) throws -> ByteSource { RangeSource(file: file, offset: ranges[i].0, length: ranges[i].1) }
}

// MARK: - compress (.Z)

final class LzwSource: ByteSource {
    private let file: FileIn
    private var base = 0                      // stream index of buf[0]
    private var buf = [UInt8]()
    private var filePos: UInt64 = 3
    private var fileEnd = false
    private let maxBits: Int
    private let blockMode: Bool
    private var nBits = 9
    private var maxcode = 511
    private var freeEnt: Int
    private var bitPos = 0
    private var oldcode = -1
    private var finchar: UInt8 = 0
    private var prefix = [UInt16](repeating: 0, count: 1 << 16)
    private var suffix = [UInt8](repeating: 0, count: 1 << 16)
    private var stack = [UInt8]()
    private var out = [UInt8]()
    private var outPos = 0
    private var done = false

    init(file: FileIn) throws {
        self.file = file
        let h = try file.read(at: 0, 3)
        guard h.count == 3, h[h.startIndex] == 0x1f, h[h.startIndex + 1] == 0x9d else { throw AXError.corrupt("not a compress (.Z) file") }
        let flags = Int(h[h.startIndex + 2])
        maxBits = flags & 0x1f
        blockMode = flags & 0x80 != 0
        guard maxBits >= 9, maxBits <= 16 else { throw AXError.unsupported("compress with \(maxBits)-bit codes") }
        freeEnt = blockMode ? 257 : 256
        for i in 0..<256 { suffix[i] = UInt8(i) }
    }

    private func byte(_ i: Int) throws -> Int? {
        while i - base >= buf.count {
            if fileEnd { return nil }
            let d = try file.read(at: filePos, 1 << 20)
            if d.isEmpty { fileEnd = true; return nil }
            filePos += UInt64(d.count)
            let keep = max(0, (bitPos >> 3) - 8 - base)
            if keep > 1 << 20 { buf.removeFirst(keep); base += keep }
            buf.append(contentsOf: d)
        }
        return Int(buf[i - base])
    }

    /// Codes are written in groups of eight; a change of width (or a clear) skips to the end of the current group.
    private var groupBase = 0
    private func alignGroup() { let g = nBits * 8; bitPos = groupBase + (bitPos - groupBase + g - 1) / g * g; groupBase = bitPos }

    private func readCode() throws -> Int? {
        var v = 0
        let first = bitPos >> 3
        // need the bytes that contain bits [bitPos, bitPos + nBits)
        let lastByte = (bitPos + nBits - 1) >> 3
        var bytes = [Int]()
        for i in first...lastByte { guard let b = try byte(i) else { return nil }; bytes.append(b) }
        for (k, b) in bytes.enumerated() { v |= b << (8 * k) }
        v = (v >> (bitPos & 7)) & ((1 << nBits) - 1)
        bitPos += nBits
        return v
    }

    private func step() throws {
        if freeEnt > maxcode {
            alignGroup()
            nBits += 1
            maxcode = nBits == maxBits ? 1 << maxBits : (1 << nBits) - 1
        }
        guard var code = try readCode() else { done = true; return }
        if oldcode == -1 {
            guard code < 256 else { throw AXError.corrupt("bad compress data") }
            finchar = UInt8(code); oldcode = code; out.append(finchar)
            return
        }
        if code == 256 && blockMode {
            alignGroup()
            freeEnt = 256; nBits = 9; maxcode = 511
            return
        }
        let incode = code
        stack.removeAll(keepingCapacity: true)
        if code >= freeEnt {
            guard code == freeEnt else { throw AXError.corrupt("bad compress data") }
            stack.append(finchar); code = oldcode
        }
        while code >= 256 { stack.append(suffix[code]); code = Int(prefix[code]) }
        finchar = suffix[code]
        stack.append(finchar)
        out.append(contentsOf: stack.reversed())
        if freeEnt < 1 << maxBits {
            prefix[freeEnt] = UInt16(oldcode); suffix[freeEnt] = finchar; freeEnt += 1
        }
        oldcode = incode
    }

    func read(_ n: Int) throws -> Data {
        while out.count - outPos < n && !done { try step() }
        let take = min(n, out.count - outPos)
        let d = Data(out[outPos..<outPos + take]); outPos += take
        if outPos > 1 << 20 { out.removeFirst(outPos); outPos = 0 }
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

final class LzwArchive: ContainerArchive {
    private let file: FileIn
    let items: [ContainerItem]
    let details = "compress (LZW)"
    init(url: URL) throws {
        file = try FileIn(url)
        _ = try LzwSource(file: file)
        var name = url.lastPathComponent
        if name.hasSuffix(".Z") || name.hasSuffix(".z") { name.removeLast(2) }
        items = [ContainerItem(path: name, size: 0, sizeKnown: false, packed: file.size)]
    }
    func stream(_ i: Int) throws -> ByteSource { try LzwSource(file: file) }
}

// MARK: - RPM

final class RpmArchive: ContainerArchive {
    private let cpioURL: URL
    private let cpio: CpioArchive
    private(set) var details = "RPM"

    init(url: URL) throws {
        let f = try FileIn(url)
        guard f.size > 104, try f.readExactly(at: 0, 4) == Data([0xed, 0xab, 0xee, 0xdb]) else { throw AXError.corrupt("not an RPM package") }
        var pos: UInt64 = 96
        func header(sigPad: Bool) throws -> (tags: [Int: String], end: UInt64) {
            let h = try f.readExactly(at: pos, 16)
            guard h.prefix(3) == Data([0x8e, 0xad, 0xe8]) else { throw AXError.corrupt("bad RPM header") }
            let n = be32(h, 8), size = be32(h, 12)
            guard n < 100_000, size < 1 << 28 else { throw AXError.corrupt("bad RPM header") }
            let idx = try f.readExactly(at: pos + 16, n * 16)
            let store = try f.readExactly(at: pos + 16 + UInt64(n * 16), size)
            var tags: [Int: String] = [:]
            for i in 0..<n {
                let tag = be32(idx, i * 16), type = be32(idx, i * 16 + 4), off = be32(idx, i * 16 + 8)
                if type == 6 || type == 9, off < store.count {
                    let tail = store.subdata(in: store.startIndex + off..<store.endIndex)
                    tags[tag] = String(decoding: tail.prefix { $0 != 0 }, as: UTF8.self)
                }
            }
            var end = pos + 16 + UInt64(n * 16 + size)
            if sigPad { end = (end + 7) & ~7 }
            return (tags, end)
        }
        pos = try header(sigPad: true).end
        let main = try header(sigPad: false)
        pos = main.end
        let name = main.tags[1000] ?? "", ver = main.tags[1001] ?? ""
        details = "RPM" + (name.isEmpty ? "" : " · \(name) \(ver)")
        let magic = try f.read(at: pos, 6)
        let payload = try FileIn(window: url, offset: pos, length: f.size - pos)
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("archivex-\(UUID().uuidString).cpio")
        cpioURL = tmp
        let src: ByteSource
        if magic.starts(with: [0x1f, 0x8b]) { src = try GzipSource(file: payload); details += " · gzip" }
        else if magic.starts(with: [0x42, 0x5a, 0x68]) { src = try Bzip2Source(file: payload); details += " · bzip2" }
        else if magic.starts(with: [0xfd, 0x37, 0x7a, 0x58, 0x5a]) { src = try XzSource(file: payload); details += " · xz" }
        else if magic.starts(with: [0x28, 0xb5, 0x2f, 0xfd]) { src = try ZstdSource(file: payload); details += " · zstd" }
        else if magic.starts(with: [0x30, 0x37, 0x30, 0x37]) { src = FileSource(payload) }
        else { throw AXError.unsupported("this RPM payload format") }
        let out = try FileOut(tmp)
        do {
            while true {
                let d = try src.read(1 << 20)
                if d.isEmpty { break }
                try out.write(d); try Task.checkCancellation()
            }
        } catch { try? FileManager.default.removeItem(at: tmp); throw error }
        cpio = try CpioArchive(url: tmp)
    }
    deinit { try? FileManager.default.removeItem(at: cpioURL) }

    var items: [ContainerItem] {
        cpio.entries.map { ContainerItem(path: $0.path, isDir: $0.isDir, size: $0.size, packed: $0.size, mtime: $0.mtime, mode: $0.mode, link: $0.link) }
    }
    func stream(_ i: Int) throws -> ByteSource {
        let e = cpio.entries[i]
        return RangeSource(file: cpio.file, offset: e.dataOffset, length: e.size)
    }
}

// MARK: - XAR (macOS .pkg, .xar)

final class XarArchive: ContainerArchive, @unchecked Sendable {
    private struct Node { var path = ""; var type = "file"; var mode: UInt32?; var mtime: Date?; var link: String?
        var offset: UInt64 = 0; var length: UInt64 = 0; var size: UInt64 = 0; var style = ""; var hasData = false }
    private let url: URL
    private var heap: UInt64 = 0
    private var nodes: [Node] = []
    private(set) var items: [ContainerItem] = []
    let details: String

    init(url: URL) throws {
        self.url = url
        let f = try FileIn(url)
        let h = try f.readExactly(at: 0, 28)
        guard h.prefix(4) == Data("xar!".utf8) else { throw AXError.corrupt("not a XAR archive") }
        let hdr = be16(h, 4), tocLen = Int(be64(h, 8)), tocRaw = Int(be64(h, 16))
        guard tocLen < 1 << 28, tocRaw < 1 << 29 else { throw AXError.corrupt("bad XAR table of contents") }
        let zToc = try f.readExactly(at: UInt64(hdr), tocLen)
        heap = UInt64(hdr + tocLen)
        let tocMem = MemorySource(zToc)
        let xml = try ZlibSource(tocMem).readAll(limit: tocRaw + 1024)
        let parser = XMLParser(data: xml)
        let delegate = TocParser()
        parser.delegate = delegate
        guard parser.parse() else { throw AXError.corrupt("bad XAR table of contents") }
        nodes = delegate.nodes.map { n in
            var m = Node(); m.path = n.path; m.type = n.type; m.mode = n.mode; m.mtime = n.mtime; m.link = n.link
            m.offset = n.offset; m.length = n.length; m.size = n.size; m.style = n.style; m.hasData = n.hasData
            return m
        }
        items = nodes.map { n in
            ContainerItem(path: n.path, isDir: n.type == "directory", size: n.size, packed: n.length, mtime: n.mtime, mode: n.mode,
                          link: n.type == "symlink" ? n.link : nil)
        }
        details = "XAR"
    }

    func stream(_ i: Int) throws -> ByteSource {
        let n = nodes[i]
        guard n.hasData else { return MemorySource(Data()) }
        let raw = windowSource(url, heap + n.offset, n.length)
        if n.style.contains("gzip") { return ZlibSource(raw) }
        if n.style.contains("bzip2") { return try Bzip2Source(source: raw) }
        if n.style.contains("lzma") || n.style.contains("xz") {
            return try XzSource(file: FileIn(window: url, offset: heap + n.offset, length: n.length))
        }
        if n.style.isEmpty || n.style.contains("octet-stream") { return raw }
        throw AXError.unsupported("XAR encoding “\(n.style)”")
    }

    private final class TocParser: NSObject, XMLParserDelegate {
        struct N { var path = ""; var type = "file"; var mode: UInt32?; var mtime: Date?; var link: String?
            var offset: UInt64 = 0; var length: UInt64 = 0; var size: UInt64 = 0; var style = ""; var hasData = false }
        var nodes: [N] = []
        private var stack: [(name: String, idx: Int)] = []
        private var elements: [String] = []
        private var text = ""
        private var base64Name = false
        private let iso = ISO8601DateFormatter()
        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes a: [String: String] = [:]) {
            elements.append(name); text = ""
            if name == "name" { base64Name = a["enctype"] == "base64" || a["enc"] == "base64" }
            if name == "file" {
                nodes.append(N()); stack.append(("", nodes.count - 1))
            } else if name == "encoding", let i = stack.last?.idx, elements.dropLast().last == "data" {
                nodes[i].style = a["style"] ?? ""
            } else if name == "data", let i = stack.last?.idx { nodes[i].hasData = true }
        }
        func parser(_ parser: XMLParser, foundCharacters s: String) { text += s }
        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            defer { elements.removeLast() }
            guard let top = stack.last else { return }
            let parent = elements.count >= 2 ? elements[elements.count - 2] : ""
            var t = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if name == "name", base64Name, let d = Data(base64Encoded: t) { t = String(decoding: d, as: UTF8.self) }
            switch (parent, name) {
            case ("file", "name"):
                stack[stack.count - 1].name = t
                let path = stack.map(\.name).filter { !$0.isEmpty }.joined(separator: "/")
                nodes[top.idx].path = path
            case ("file", "type"): nodes[top.idx].type = t
            case ("file", "mode"): nodes[top.idx].mode = UInt32(t, radix: 8).map { $0 & 0o7777 }
            case ("file", "mtime"): nodes[top.idx].mtime = iso.date(from: t)
            case ("file", "link"): nodes[top.idx].link = t
            case ("data", "offset"): nodes[top.idx].offset = UInt64(t) ?? 0
            case ("data", "length"): nodes[top.idx].length = UInt64(t) ?? 0
            case ("data", "size"): nodes[top.idx].size = UInt64(t) ?? 0
            case (_, "file"): stack.removeLast()
            default: break
            }
        }
    }
}

final class MemorySource: ByteSource {
    private var data: Data
    init(_ d: Data) { data = d }
    func read(_ n: Int) throws -> Data {
        let t = min(n, data.count)
        let d = data.subdata(in: data.startIndex..<data.startIndex + t)
        data = data.subdata(in: data.startIndex + t..<data.endIndex)
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

extension ByteSource {
    func readAll(limit: Int) throws -> Data {
        var out = Data()
        while true {
            let d = try read(1 << 16)
            if d.isEmpty { return out }
            out.append(d)
            if out.count > limit { throw AXError.corrupt("data larger than recorded") }
        }
    }
}

// MARK: - CAB (Microsoft cabinet): stored and MSZIP

final class CabArchive: ContainerArchive {
    private struct Folder { var dataOffset: UInt64; var blocks: Int; var method: Int }
    private struct FileRec { var folder: Int; var offset: UInt64 }
    private let file: FileIn
    private var folders: [Folder] = []
    private var recs: [FileRec] = []
    private var perDataReserve = 0
    private(set) var items: [ContainerItem] = []
    private(set) var details = "CAB"
    private var cache: (folder: Int, src: ByteSource, pos: UInt64)?

    init(url: URL) throws {
        file = try FileIn(url)
        let h = try file.readExactly(at: 0, 36)
        guard h.prefix(4) == Data("MSCF".utf8) else { throw AXError.corrupt("not a cabinet file") }
        func le16(_ o: Int) -> Int { Int(h[h.startIndex + o]) | Int(h[h.startIndex + o + 1]) << 8 }
        func le32(_ o: Int) -> Int { le16(o) | le16(o + 2) << 16 }
        let coffFiles = le32(16), nFolders = le16(26), nFiles = le16(28), flags = le16(30)
        var p: UInt64 = 36
        var folderReserve = 0
        if flags & 4 != 0 {
            let r = try file.readExactly(at: p, 4)
            let headerReserve = Int(r[r.startIndex]) | Int(r[r.startIndex + 1]) << 8
            folderReserve = Int(r[r.startIndex + 2]); perDataReserve = Int(r[r.startIndex + 3])
            p += 4 + UInt64(headerReserve)
        }
        if flags & 1 != 0 || flags & 2 != 0 {                      // previous / next cabinet names
            func skipString() throws { while true { let b = try file.readExactly(at: p, 1); p += 1; if b[b.startIndex] == 0 { break } } }
            if flags & 1 != 0 { try skipString(); try skipString() }
            if flags & 2 != 0 { try skipString(); try skipString() }
        }
        var methods = Set<Int>()
        for _ in 0..<nFolders {
            let d = try file.readExactly(at: p, 8)
            let off = Int(d[d.startIndex]) | Int(d[d.startIndex + 1]) << 8 | Int(d[d.startIndex + 2]) << 16 | Int(d[d.startIndex + 3]) << 24
            let blocks = Int(d[d.startIndex + 4]) | Int(d[d.startIndex + 5]) << 8
            let method = (Int(d[d.startIndex + 6]) | Int(d[d.startIndex + 7]) << 8) & 0xff
            folders.append(Folder(dataOffset: UInt64(off), blocks: blocks, method: method)); methods.insert(method)
            p += 8 + UInt64(folderReserve)
        }
        p = UInt64(coffFiles)
        for _ in 0..<nFiles {
            let d = try file.readExactly(at: p, 16)
            func u16(_ o: Int) -> Int { Int(d[d.startIndex + o]) | Int(d[d.startIndex + o + 1]) << 8 }
            func u32(_ o: Int) -> Int { u16(o) | u16(o + 2) << 16 }
            var name = Data(); var q = p + 16
            while true { let b = try file.readExactly(at: q, 1); q += 1; if b[b.startIndex] == 0 { break }; name.append(b); if name.count > 1024 { throw AXError.corrupt("bad cabinet file name") } }
            p = q
            let attr = u16(14), date = u16(10), time = u16(12), fi = u16(8)
            guard fi < folders.count else { throw AXError.unsupported("files continued from another cabinet") }
            let utf8 = attr & 0x80 != 0
            let nm = (utf8 ? String(data: name, encoding: .utf8) : nil) ?? String(data: name, encoding: .windowsCP1252) ?? String(decoding: name, as: UTF8.self)
            items.append(ContainerItem(path: nm.replacingOccurrences(of: "\\", with: "/"), size: UInt64(u32(0)), packed: UInt64(u32(0)),
                                       mtime: DOSTime.date(time: UInt16(time), date: UInt16(date)), mode: nil))
            recs.append(FileRec(folder: fi, offset: UInt64(u32(4))))
        }
        var names: [String] = []
        for m in methods.sorted() { names.append(m == 0 ? "stored" : m == 1 ? "MSZIP" : m == 2 ? "Quantum" : "LZX") }
        details = "CAB · " + names.joined(separator: ", ")
    }

    /// The uncompressed bytes of one folder, block by block.
    private final class FolderSource: ByteSource {
        let file: FileIn; let blocks: Int; let method: Int; let reserve: Int
        var pos: UInt64; var next = 0
        var out = Data(); var outPos = 0
        let inflater = Inflater()
        init(file: FileIn, folder: Folder, reserve: Int) { self.file = file; blocks = folder.blocks; method = folder.method; self.reserve = reserve; pos = folder.dataOffset }
        func read(_ n: Int) throws -> Data {
            while out.count - outPos < n && next < blocks {
                let h = try file.readExactly(at: pos, 8 + reserve)
                let cb = Int(h[h.startIndex + 4]) | Int(h[h.startIndex + 5]) << 8, cu = Int(h[h.startIndex + 6]) | Int(h[h.startIndex + 7]) << 8
                let data = try file.readExactly(at: pos + 8 + UInt64(reserve), cb)
                pos += 8 + UInt64(reserve) + UInt64(cb); next += 1
                if outPos > 0 { out.removeSubrange(0..<outPos); outPos = 0 }
                switch method {
                case 0: out.append(data)
                case 1:
                    guard cb >= 2, data[data.startIndex] == 0x43, data[data.startIndex + 1] == 0x4b else { throw AXError.corrupt("bad MSZIP block") }
                    inflater.restartKeepingWindow()
                    var got = Data()
                    _ = try inflater.process(data.dropFirst(2), final: true) { got.append($0) }
                    out.append(got)
                default: throw AXError.unsupported(method == 2 ? "Quantum-compressed cabinets" : "LZX-compressed cabinets")
                }
                _ = cu
            }
            let take = min(n, out.count - outPos)
            let d = out.subdata(in: out.startIndex + outPos..<out.startIndex + outPos + take); outPos += take
            return d
        }
        func skip(_ n: UInt64) throws { try discard(n) }
    }

    func stream(_ i: Int) throws -> ByteSource {
        let r = recs[i]
        var src: ByteSource, pos: UInt64
        if let c = cache, c.folder == r.folder, c.pos <= r.offset { src = c.src; pos = c.pos }
        else { src = FolderSource(file: file, folder: folders[r.folder], reserve: perDataReserve); pos = 0 }
        try src.discard(r.offset - pos)
        cache = (r.folder, src, r.offset + items[i].size)
        return LimitSource(src, limit: items[i].size)
    }
}


// MARK: - lzma-alone (.lzma)

final class LzmaAloneArchive: ContainerArchive {
    private let file: FileIn
    private let props: Data
    private let size: UInt64?
    let items: [ContainerItem]
    let details = "LZMA"
    init(url: URL) throws {
        file = try FileIn(url)
        let h = try file.readExactly(at: 0, 13)
        props = h.prefix(5)
        guard h[h.startIndex] < 225 else { throw AXError.corrupt("not an LZMA file") }
        let sz = (0..<8).reduce(UInt64(0)) { $0 | UInt64(h[h.startIndex + 5 + $1]) << UInt64(8 * $1) }
        size = sz == UInt64.max ? nil : sz
        var name = url.lastPathComponent
        if name.lowercased().hasSuffix(".lzma") { name.removeLast(5) }
        items = [ContainerItem(path: name, size: size ?? 0, sizeKnown: size != nil, packed: file.size)]
    }
    func stream(_ i: Int) throws -> ByteSource {
        let src = FileSource(file)
        try src.skip(13)
        return try LzmaSource(input: src, props: props, unpackSize: size ?? UInt64.max / 2)
    }
}
