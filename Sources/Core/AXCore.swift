import Foundation

// The façade the app talks to. Every function here is synchronous and cancellable
// (Task.checkCancellation), so the model runs them on a background task.

enum AXKind { case zip, tar, gz, tgz, bz2, tbz2, xz, txz, zst, tzst, sevenZ, rar, iso, cpio, ar, lzw, rpm, xar, cab, dmg, lzma }

extension AXKind {
    /// kinds whose payload is one compressed stream
    var isStream: Bool { self == .gz || self == .bz2 || self == .xz || self == .zst }
    /// kinds handled through the generic `ContainerArchive` layer
    var isContainer: Bool { self == .ar || self == .lzw || self == .rpm || self == .xar || self == .cab || self == .dmg || self == .lzma }
    /// kinds that are a tar inside a compressor
    var isCompressedTar: Bool { self == .tgz || self == .tbz2 || self == .txz || self == .tzst }
    var isTarLike: Bool { self == .tar || isCompressedTar }
}

struct AXCreate {
    var format: ArchiveFormat          // .zip, .tar or .tgz
    var output: URL
    var items: [URL]
    var level = 6
    var password: String?
    var legacyZipCrypto = false
    var deleteAfter = false
    var solid = true                    // 7z: one compressed block for all files
    var encryptNames = false            // 7z: encrypt the file list too
    var comment: String? = nil
    var splitVolumeSize: UInt64? = nil
}

struct AXItem {
    enum Kind { case file, dir, symlink }
    var url: URL
    var name: String
    var kind: Kind
    var size: UInt64
    var mtime: Date
    var mode: UInt32
}

enum AXCore {
    // MARK: - format detection

    static func kind(of url: URL) -> AXKind? {
        var n = url.lastPathComponent.lowercased()
        if n.count > 4, let dot = n.lastIndex(of: "."), n.distance(from: dot, to: n.endIndex) == 4,
           n[n.index(after: dot)...].allSatisfy({ $0.isASCII && $0.isNumber }) {
            let baseExt = String(n[..<dot])
            if baseExt.hasSuffix(".7z") || baseExt.hasSuffix(".zip") || baseExt.hasSuffix(".tar") || baseExt.hasSuffix(".rar") {
                n = baseExt                                           // split archive: name.7z.001, name.zip.002, name.tar.001, …
            }
        }
        if n.hasSuffix(".tar.gz") || n.hasSuffix(".tgz") || n.hasSuffix(".taz") { return .tgz }
        if n.hasSuffix(".tar.bz2") || n.hasSuffix(".tbz2") || n.hasSuffix(".tbz") || n.hasSuffix(".tb2") { return .tbz2 }
        if n.hasSuffix(".bz2") { return .bz2 }
        if n.hasSuffix(".tar.xz") || n.hasSuffix(".txz") { return .txz }
        if n.hasSuffix(".xz") { return .xz }
        if n.hasSuffix(".tar.zst") || n.hasSuffix(".tzst") { return .tzst }
        if n.hasSuffix(".zst") { return .zst }
        for e in [".zip", ".jar", ".cbz", ".apk", ".ipa", ".epub"] where n.hasSuffix(e) { return .zip }
        if n.hasSuffix(".7z") { return .sevenZ }
        if n.hasSuffix(".iso") { return .iso }
        if n.hasSuffix(".cpio") { return .cpio }
        for e in [".deb", ".udeb", ".ar", ".a"] where n.hasSuffix(e) { return .ar }
        if n.hasSuffix(".rpm") { return .rpm }
        if n.hasSuffix(".xar") || n.hasSuffix(".pkg") || n.hasSuffix(".mpkg") { return .xar }
        if n.hasSuffix(".cab") { return .cab }
        if n.hasSuffix(".dmg") { return .dmg }
        if n.hasSuffix(".z") { return .lzw }
        if n.hasSuffix(".lzma") { return .lzma }
        if n.hasSuffix(".rar") { return .rar }
        if n.count > 4, let dot = n.lastIndex(of: "."), n.distance(from: dot, to: n.endIndex) == 4 {       // old volume names: .r00 … .r99, .s00 …
            let ext = n[n.index(after: dot)...]
            if (ext.first == "r" || ext.first == "s"), ext.dropFirst().allSatisfy({ $0.isASCII && $0.isNumber }) { return .rar }
            if ext.first == "z", ext.dropFirst().allSatisfy({ $0.isASCII && $0.isNumber }) { return .zip }          // spanned ZIP: name.z01
        }
        if n.hasSuffix(".tar") { return .tar }
        if n.hasSuffix(".gz") { return .gz }
        return nil
    }

    static func container(_ url: URL, _ k: AXKind) throws -> ContainerArchive {
        switch k {
        case .ar: return try ArArchive(url: url)
        case .lzw: return try LzwArchive(url: url)
        case .rpm: return try RpmArchive(url: url)
        case .xar: return try XarArchive(url: url)
        case .cab: return try CabArchive(url: url)
        case .dmg: return try DmgArchive(url: url)
        case .lzma: return try LzmaAloneArchive(url: url)
        default: throw AXError.unsupported(url.pathExtension)
        }
    }

    static func handles(_ url: URL) -> Bool { kind(of: url) != nil }

    // MARK: - listing

    private static func modeString(_ mode: UInt32, dir: Bool, link: Bool) -> String {
        let t = dir ? "d" : link ? "l" : "-"
        let bits = ["r", "w", "x"]
        var s = t
        for i in (0..<9).reversed() { s += (mode >> UInt32(i)) & 1 == 1 ? bits[(8 - i) % 3] : "-" }
        return s
    }

    /// Sequential decompressed stream of a single-stream or tar-in-compressor archive.
    private static func decoded(_ url: URL, _ k: AXKind) throws -> (ByteSource, FileIn) {
        let f = try FileIn.openArchive(url)
        switch k {
        case .tgz, .gz: return (try GzipSource(file: f), f)
        case .tbz2, .bz2: return (try Bzip2Source(file: f), f)
        case .txz, .xz: return (try XzSource(file: f), f)
        case .tzst, .zst: return (try ZstdSource(file: f), f)
        default: return (FileSource(f), f)
        }
    }
    private static func tarSource(_ url: URL, _ k: AXKind) throws -> (ByteSource, FileIn) { try decoded(url, k) }

    /// Name of the single file inside a .gz/.bz2 (from the gzip header, otherwise the archive name).
    private static func streamName(_ url: URL, _ k: AXKind, _ stored: String?) -> String {
        if let s = stored, !s.isEmpty { return s }
        return (url.lastPathComponent as NSString).deletingPathExtension
    }

    static func list(_ url: URL, password: String?) throws -> Listing {
        guard let k = kind(of: url) else { throw AXError.unsupported(url.pathExtension) }
        switch k {
        case .zip:
            return try ZipArchive(url: url).listing
        case .sevenZ:
            return try SevenZipArchive(url: url, password: password).listing
        case .rar:
            return try RarArchive(url: url, password: password).listing
        case .iso:
            return try IsoArchive(url: url).listing
        case .cpio:
            return try CpioArchive(url: url).listing
        case .ar, .lzw, .rpm, .xar, .cab, .dmg, .lzma:
            return Container.listing(try container(url, k))
        case .tar, .tgz, .tbz2, .txz, .tzst:
            let (src, f) = try tarSource(url, k)
            let reader = TarReader(src)
            var l = Listing()
            l.details = k == .tgz ? "TAR · gzip" : k == .tbz2 ? "TAR · bzip2" : k == .txz ? "TAR · xz" : k == .tzst ? "TAR · Zstandard" : "TAR"
            while let e = try reader.next() {
                try Task.checkCancellation()
                try reader.skipData(e)
                l.entries.append(ArchiveEntry(path: e.path, isDir: e.isDir, size: Int64(e.size), packed: Int64(e.size), ratio: "",
                                              mtime: Dates.text(e.mtime), crc: "",
                                              attrs: modeString(e.mode, dir: e.isDir, link: e.type == UInt8(ascii: "2")), encrypted: false))
            }
            _ = f
            return l
        case .bz2, .xz, .zst:
            let f = try FileIn.openArchive(url)
            _ = try decoded(url, k)
            var l = Listing()
            l.details = k == .xz ? "xz" : k == .zst ? "Zstandard" : "bzip2"
            let size = Int64(k == .xz ? (XzSource.recordedSize(of: f) ?? 0) : 0)
            l.entries = [ArchiveEntry(path: streamName(url, k, nil), isDir: false, size: size, packed: Int64(f.size),
                                      ratio: size > 0 ? "\(min(100, Int(Double(f.size) / Double(size) * 100)))%" : "", mtime: "",
                                      crc: "", attrs: "", encrypted: false)]
            return l
        case .gz:
            let f = try FileIn.openArchive(url)
            let g = try GzipSource(file: f)
            let name = streamName(url, k, g.storedName)
            var l = Listing()
            l.details = "gzip"
            let size = Int64(GzipSource.recordedSize(of: f) ?? 0)
            l.entries = [ArchiveEntry(path: name, isDir: false, size: size, packed: Int64(f.size),
                                      ratio: size > 0 ? "\(min(100, Int(Double(f.size) / Double(size) * 100)))%" : "",
                                      mtime: "", crc: "", attrs: "", encrypted: false)]
            return l
        }
    }

    // MARK: - extraction

    /// Returns names of entries that were skipped because they were unsafe.
    @discardableResult
    static func extract(_ url: URL, selection: [(path: String, isDir: Bool)], to dest: URL, overwrite: Extractor.Overwrite,
                        keepPaths: Bool, password: String?, progress: @escaping (Double) -> Void) throws -> [String] {
        guard let k = kind(of: url) else { throw AXError.unsupported(url.pathExtension) }
        let ex = try Extractor(destination: dest, overwrite: overwrite, keepPaths: keepPaths, selection: selection)
        switch k {
        case .zip:
            let z = try ZipArchive(url: url)
            let total = z.entries.filter { !$0.isDir && (selection.isEmpty || ex.isSelected(SafePath.clean($0.name) ?? "")) }
                .reduce(Int64(0)) { $0 + Int64($1.usize) }
            try z.extract(selection: selection, to: ex, password: password, progress: ProgressTracker(total: total, report: progress))
        case .ar, .lzw, .rpm, .xar, .cab, .dmg, .lzma:
            let z = try container(url, k)
            try Container.extract(z, to: ex, progress: ProgressTracker(total: Container.total(z), report: progress))
        case .iso:
            let z = try IsoArchive(url: url)
            let total = z.entries.filter { !$0.isDir && ex.isSelected(SafePath.clean($0.path) ?? "") }.reduce(Int64(0)) { $0 + Int64($1.size) }
            try z.extract(to: ex, progress: ProgressTracker(total: total, report: progress))
        case .cpio:
            let z = try CpioArchive(url: url)
            let total = z.entries.filter { !$0.isDir && ex.isSelected(SafePath.clean($0.path) ?? "") }.reduce(Int64(0)) { $0 + Int64($1.size) }
            try z.extract(to: ex, progress: ProgressTracker(total: total, report: progress))
        case .rar:
            let z = try RarArchive(url: url, password: password)
            let total = z.entries.filter { !$0.isDir && ex.isSelected(SafePath.clean($0.name) ?? "") }.reduce(Int64(0)) { $0 + Int64($1.size ?? $1.packSize) }
            try z.extract(to: ex, progress: ProgressTracker(total: total, report: progress))
        case .sevenZ:
            let z = try SevenZipArchive(url: url, password: password)
            let total = z.files.filter { !$0.isDir && ex.isSelected(SafePath.clean($0.name) ?? "") }.reduce(Int64(0)) { $0 + Int64($1.size) }
            try z.extract(to: ex, progress: ProgressTracker(total: total, report: progress))
        case .tar, .tgz, .tbz2, .txz, .tzst:
            let (src, f) = try tarSource(url, k)
            let reader = TarReader(src)
            let tracker = ProgressTracker(total: k == .tar ? Int64(f.size) : Int64(f.size) * 4, report: progress)
            var written: [String: URL] = [:]
            var dirs: [(URL, UInt32, Date?)] = []
            while let e = try reader.next() {
                try Task.checkCancellation()
                guard let clean = SafePath.clean(e.path) else {
                    if !e.path.isEmpty { _ = try ex.destination(for: e.path, isDir: e.isDir) }
                    try reader.skipData(e); continue
                }
                guard ex.isSelected(clean) else { try reader.skipData(e); continue }
                if e.isDir {
                    if keepPaths, let u = try ex.destination(for: e.path, isDir: true) {
                        try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
                        dirs.append((u, e.mode, e.mtime))
                    }
                    continue
                }
                switch e.type {
                case UInt8(ascii: "2"):
                    try reader.skipData(e)
                    if let u = try ex.destination(for: e.path, isDir: false) { ex.makeSymlink(at: u, target: e.link) }
                case UInt8(ascii: "1"):
                    try reader.skipData(e)
                    if let src = SafePath.clean(e.link).flatMap({ written[$0] }), let u = try ex.destination(for: e.path, isDir: false) {
                        try? FileManager.default.copyItem(at: src, to: u)
                        written[clean] = u
                    }
                case 0, UInt8(ascii: "0"), UInt8(ascii: "7"):
                    guard let u = try ex.destination(for: e.path, isDir: false) else { try reader.skipData(e); continue }
                    let out = try FileOut(u)
                    do { try reader.copyData(e, to: out, progress: tracker) }
                    catch { try? FileManager.default.removeItem(at: u); throw error }
                    ex.finalize(u, mode: e.mode, mtime: e.mtime)
                    written[clean] = u
                default:
                    try reader.skipData(e)
                }
            }
            while !(try src.read(1 << 20)).isEmpty { try Task.checkCancellation() }       // verify the container's final checksums
            for (u, m, t) in dirs.reversed() { ex.finalize(u, mode: m, mtime: t) }
        case .gz, .bz2, .xz, .zst:
            let (g, f) = try decoded(url, k)
            let name = streamName(url, k, (g as? GzipSource)?.storedName)
            if let u = try ex.destination(for: name, isDir: false) {
                let out = try FileOut(u)
                let tracker = ProgressTracker(total: Int64(f.size) * 3, report: progress)
                do {
                    while true {
                        let d = try g.read(1 << 20)
                        if d.isEmpty { break }
                        try out.write(d); try tracker.add(d.count / 3)
                    }
                } catch { try? FileManager.default.removeItem(at: u); throw error }
            }
        }
        ex.verifyLinks()
        return ex.skippedUnsafe
    }

    static func test(_ url: URL, password: String?, progress: @escaping (Double) -> Void) throws {
        guard let k = kind(of: url) else { throw AXError.unsupported(url.pathExtension) }
        switch k {
        case .zip:
            let z = try ZipArchive(url: url)
            let total = z.entries.reduce(Int64(0)) { $0 + Int64($1.usize) }
            try z.test(password: password, progress: ProgressTracker(total: total, report: progress))
        case .ar, .lzw, .rpm, .xar, .cab, .dmg, .lzma:
            let z = try container(url, k)
            try Container.test(z, progress: ProgressTracker(total: Container.total(z), report: progress))
        case .iso:
            let z = try IsoArchive(url: url)
            try z.test(progress: ProgressTracker(total: z.entries.reduce(Int64(0)) { $0 + Int64($1.size) }, report: progress))
        case .cpio:
            let z = try CpioArchive(url: url)
            try z.test(progress: ProgressTracker(total: z.entries.reduce(Int64(0)) { $0 + Int64($1.size) }, report: progress))
        case .rar:
            let z = try RarArchive(url: url, password: password)
            try z.test(progress: ProgressTracker(total: z.entries.reduce(Int64(0)) { $0 + Int64($1.size ?? $1.packSize) }, report: progress))
        case .sevenZ:
            let z = try SevenZipArchive(url: url, password: password)
            try z.test(progress: ProgressTracker(total: z.files.reduce(Int64(0)) { $0 + Int64($1.size) }, report: progress))
        case .tar, .tgz, .tbz2, .txz, .tzst:
            let (src, f) = try tarSource(url, k)
            let reader = TarReader(src)
            let tracker = ProgressTracker(total: Int64(f.size) * (k == .tar ? 1 : 4), report: progress)
            let null = NullSink()
            while let e = try reader.next() { try Task.checkCancellation(); try reader.copyData(e, to: null, progress: tracker) }
            while !(try src.read(1 << 20)).isEmpty { try Task.checkCancellation() }       // run the container's final checksums
        case .gz, .bz2, .xz, .zst:
            let (g, _) = try decoded(url, k)
            while !(try g.read(1 << 20)).isEmpty { try Task.checkCancellation() }
        }
    }

    // MARK: - creating

    static func collect(_ roots: [URL]) throws -> [AXItem] {
        var out: [AXItem] = []
        func visit(_ url: URL, _ name: String) throws {
            var st = stat()
            guard lstat(url.path, &st) == 0 else { throw AXError.io("Can’t read “\(url.lastPathComponent)”.") }
            let kind = st.st_mode & S_IFMT
            let mtime = Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec))
            let mode = UInt32(st.st_mode & 0o7777)
            if kind == S_IFDIR {
                out.append(AXItem(url: url, name: name, kind: .dir, size: 0, mtime: mtime, mode: mode))
                for child in try FileManager.default.contentsOfDirectory(atPath: url.path).sorted() {
                    try visit(url.appendingPathComponent(child), name + "/" + child)
                }
            } else if kind == S_IFLNK {
                out.append(AXItem(url: url, name: name, kind: .symlink, size: 0, mtime: mtime, mode: mode))
            } else if kind == S_IFREG {
                out.append(AXItem(url: url, name: name, kind: .file, size: UInt64(st.st_size), mtime: mtime, mode: mode))
            }
        }
        for r in roots { try visit(r, r.lastPathComponent) }
        return out
    }

    /// Copies `size` bytes of a file into a sink.
    private static func pump(_ url: URL, into sink: ByteSink, progress: ProgressTracker?) throws {
        let f = try FileIn(url)
        var off: UInt64 = 0
        while off < f.size {
            let d = try f.read(at: off, 1 << 20)
            if d.isEmpty { break }
            off += UInt64(d.count)
            try sink.write(d)
            try progress?.add(d.count)
        }
    }

    private static func writeSevenZ(items: [AXItem], to tmp: URL, spec: AXCreate, progress: ProgressTracker) throws {
        let total = items.reduce(UInt64(0)) { $0 + $1.size }
        let w = try SevenZipWriter(url: tmp, options: .init(level: spec.level, solid: spec.solid, password: spec.password,
                                                            encryptHeader: spec.encryptNames, totalHint: total))
        for it in items {
            try Task.checkCancellation()
            switch it.kind {
            case .dir: w.addDirectory(name: it.name, mtime: it.mtime, mode: it.mode)
            case .symlink:
                let target = Data(((try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? "").utf8)
                try w.addFile(name: it.name, size: UInt64(target.count), mtime: it.mtime, mode: it.mode, symlink: true) { try $0.write(target) }
            case .file:
                try w.addFile(name: it.name, size: it.size, mtime: it.mtime, mode: it.mode) { sink in try pump(it.url, into: sink, progress: progress) }
            }
        }
        try w.finish()
    }

    private static func writeRar(items: [AXItem], to tmp: URL, spec: AXCreate, progress: ProgressTracker) throws {
        let w = try Rar5Writer(url: tmp, solid: false, password: spec.password)
        for it in items {
            try Task.checkCancellation()
            switch it.kind {
            case .dir:
                try w.addDirectory(name: it.name, mtime: it.mtime, mode: it.mode)
            case .symlink:
                let target = (try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? ""
                try w.addSymlink(name: it.name, target: target, mtime: it.mtime, mode: it.mode)
            case .file:
                try w.addFile(source: it.url, name: it.name, size: it.size, mtime: it.mtime, mode: it.mode, progress: progress)
            }
        }
        try w.finish()
    }

    private static func write(items: [AXItem], format: ArchiveFormat, to tmp: URL, level: Int, password: String?, legacy: Bool,
                              comment: String? = nil, progress: ProgressTracker) throws {
        switch format {
        case .zip:
            let w = try ZipWriter(url: tmp, password: password, legacyCrypto: legacy, level: level, comment: comment)
            for it in items {
                try Task.checkCancellation()
                switch it.kind {
                case .dir: try w.addDirectory(name: it.name, mtime: it.mtime, mode: it.mode)
                case .symlink: try w.addSymlink(name: it.name, target: (try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? "", mtime: it.mtime)
                case .file: try w.addFile(source: it.url, name: it.name, mtime: it.mtime, mode: it.mode, progress: progress)
                }
            }
            try w.finish()
        case .tar, .tgz, .tbz2, .txz:
            let file = try FileOut(tmp)
            let sink: ByteSink
            switch format {
            case .tgz: sink = try GzipSink(out: file, name: nil, mtime: Date())
            case .tbz2: sink = try Bzip2Sink(out: file, level: 9)
            case .txz: sink = try XzSink(out: file, level: level >= 6 ? 4 : 3, totalHint: nil)
            default: sink = file
            }
            let w = TarWriter(sink: sink)
            for it in items {
                try Task.checkCancellation()
                switch it.kind {
                case .dir: try w.addDirectory(name: it.name, mode: it.mode, mtime: it.mtime)
                case .symlink: try w.addSymlink(name: it.name, target: (try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? "", mode: it.mode, mtime: it.mtime)
                case .file: try w.addFile(source: it.url, name: it.name, mode: it.mode, mtime: it.mtime, progress: progress)
                }
            }
            try w.finish()
        default:
            throw AXError.unsupported("creating \(format.rawValue)")
        }
    }

    @discardableResult
    private static func commit(_ tmp: URL, as final: URL, splitVolumeSize: UInt64? = nil) throws -> URL {
        if let volSize = splitVolumeSize, volSize > 0 {
            var baseName = final.lastPathComponent
            if baseName.count > 4, let dot = baseName.lastIndex(of: "."), baseName[dot...].hasPrefix(".00") {
                baseName = String(baseName[..<dot])
            }
            let dir = final.deletingLastPathComponent()
            // A set from an earlier run under the same name would otherwise be joined to the new one (.004, .005 … left over).
            for old in (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [] {
                guard old.hasPrefix(baseName + "."), old.count == baseName.count + 4,
                      old.suffix(3).allSatisfy({ $0.isASCII && $0.isNumber }) else { continue }
                try? FileManager.default.removeItem(at: dir.appendingPathComponent(old))
            }
            let file = try FileIn(tmp)
            let total = file.size
            var offset: UInt64 = 0
            var partIndex = 1
            let firstURL = dir.appendingPathComponent(baseName + ".001")
            var made: [URL] = []
            do {
            while offset < total || (total == 0 && partIndex == 1) {
                let partURL = dir.appendingPathComponent(baseName + "." + String(format: "%03d", partIndex))
                made.append(partURL)
                let partOut = try FileOut(partURL)
                let toWrite = min(volSize, total - offset)
                var written: UInt64 = 0
                while written < toWrite {
                    let chunk = Int(min(UInt64(1 << 20), toWrite - written))
                    let d = try file.readExactly(at: offset + written, chunk)
                    try partOut.write(d)
                    written += UInt64(d.count)
                }
                offset += toWrite
                partIndex += 1
                if total == 0 { break }
            }
            } catch {
                for u in made { try? FileManager.default.removeItem(at: u) }       // never leave half a set behind
                throw error
            }
            try? FileManager.default.removeItem(at: tmp)
            return firstURL
        }
        if FileManager.default.fileExists(atPath: final.path) { _ = try FileManager.default.replaceItemAt(final, withItemAt: tmp) }
        else { try FileManager.default.moveItem(at: tmp, to: final) }
        return final
    }

    static func create(_ spec: AXCreate, progress: @escaping (Double) -> Void) throws {
        let items = try collect(spec.items)
        let tracker = ProgressTracker(total: items.reduce(0) { $0 + Int64($1.size) }, report: progress)
        let tmp = spec.output.deletingLastPathComponent().appendingPathComponent(".\(UUID().uuidString).axtmp")
        let finalOutput: URL
        do {
            if spec.format == .sevenZ { try writeSevenZ(items: items, to: tmp, spec: spec, progress: tracker) }
            else if spec.format == .rar { try writeRar(items: items, to: tmp, spec: spec, progress: tracker) }
            else {
                try write(items: items, format: spec.format, to: tmp, level: spec.level, password: spec.password,
                          legacy: spec.legacyZipCrypto, comment: spec.comment, progress: tracker)
            }
            finalOutput = try commit(tmp, as: spec.output, splitVolumeSize: spec.splitVolumeSize)
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            throw error
        }
        if spec.deleteAfter {
            try test(finalOutput, password: spec.password, progress: { _ in })      // never delete sources unverified
            for r in spec.items { try? FileManager.default.removeItem(at: r) }
        }
    }

    // MARK: - editing (rewrite the archive without / with extra entries)

    private static func editRar(url: URL, tmp: URL, remove selection: [(path: String, isDir: Bool)], add items: [AXItem], roots: [URL],
                                level: Int, password: String?, progress: ProgressTracker) throws {
        let arc = try RarArchive(url: url, password: password)
        let newNames = Set(items.map(\.name))
        func matches(_ path: String) -> Bool {
            selection.contains { $0.path == path || ($0.isDir && path.hasPrefix($0.path + "/")) } || newNames.contains(path)
        }
        let tempDir = tmp.deletingLastPathComponent().appendingPathComponent(".\(UUID().uuidString).axrebuild")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Entries whose names fail the path check (“../…”, absolute paths) are never carried over: they were not extracted
        // either, and falling back to the raw name would read whatever file that name points at outside the temp folder.
        let keepEntries = arc.entries.filter { e in SafePath.clean(e.name).map { !matches($0) } ?? false }
        let ex = try Extractor(destination: tempDir, overwrite: .all, keepPaths: true, selection: [])
        try arc.extract(to: ex, progress: progress)

        let w = try Rar5Writer(url: tmp, solid: false, password: password)
        for e in keepEntries {
            try Task.checkCancellation()
            guard let clean = SafePath.clean(e.name) else { continue }
            let localURL = tempDir.appendingPathComponent(clean)
            let inside = tempDir.resolvingSymlinksInPath().path + "/"
            guard localURL.resolvingSymlinksInPath().path.hasPrefix(inside) || e.isDir || e.link != nil else { continue }
            if e.isDir {
                try w.addDirectory(name: clean, mtime: e.mtime ?? Date(), mode: UInt32(e.attrib & 0o7777))
            } else if let link = e.link {
                try w.addSymlink(name: clean, target: link.target, mtime: e.mtime ?? Date(), mode: UInt32(e.attrib & 0o7777))
            } else if FileManager.default.fileExists(atPath: localURL.path) {
                let sz = (try? FileManager.default.attributesOfItem(atPath: localURL.path)[.size] as? UInt64) ?? 0
                try w.addFile(source: localURL, name: clean, size: sz, mtime: e.mtime ?? Date(), mode: UInt32(e.attrib & 0o7777), progress: progress)
            }
        }
        for it in items {
            try Task.checkCancellation()
            switch it.kind {
            case .dir: try w.addDirectory(name: it.name, mtime: it.mtime, mode: it.mode)
            case .symlink:
                let target = (try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? ""
                try w.addSymlink(name: it.name, target: target, mtime: it.mtime, mode: it.mode)
            case .file: try w.addFile(source: it.url, name: it.name, size: it.size, mtime: it.mtime, mode: it.mode, progress: progress)
            }
        }
        try w.finish()
    }

    static func canEdit(_ url: URL) -> Bool { [.zip, .tar, .sevenZ, .rar].contains(kind(of: url)) }

    static func edit(_ url: URL, remove selection: [(path: String, isDir: Bool)], add roots: [URL], level: Int, password: String?,
                     legacy: Bool, progress: @escaping (Double) -> Void) throws {
        guard let k = kind(of: url), k == .zip || k == .tar || k == .sevenZ || k == .rar else { throw AXError.unsupported("editing this format") }
        let newItems = try collect(roots)
        let newNames = Set(newItems.map(\.name))
        func matches(_ path: String) -> Bool {
            selection.contains { $0.path == path || ($0.isDir && path.hasPrefix($0.path + "/")) } || newNames.contains(path)
        }
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(UUID().uuidString).axtmp")
        do {
            if k == .rar {
                let total = Int64((try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? UInt64) ?? 0) + newItems.reduce(0) { $0 + Int64($1.size) }
                let tracker = ProgressTracker(total: total, report: progress)
                try editRar(url: url, tmp: tmp, remove: selection, add: newItems, roots: roots, level: level, password: password, progress: tracker)
            } else if k == .sevenZ {
                let arc = try SevenZipArchive(url: url, password: password)
                let total = arc.files.reduce(Int64(0)) { $0 + Int64($1.size) } + newItems.reduce(0) { $0 + Int64($1.size) }
                let tracker = ProgressTracker(total: total, report: progress)
                let w = try SevenZipWriter(url: tmp, options: .init(level: level, solid: true, password: password,
                                                                    encryptHeader: arc.headerEncrypted, totalHint: UInt64(max(total, 0))))
                try arc.rebuild(keep: { !matches(SafePath.clean($0.name) ?? $0.name) }) { f, src in
                    let mtime = f.mtime ?? Date()
                    if f.isDir { w.addDirectory(name: f.name, mtime: mtime, mode: f.unixMode ?? 0o755); return }
                    guard let src else { try w.addFile(name: f.name, size: 0, mtime: mtime, mode: f.unixMode ?? 0o644) { _ in }; return }
                    try w.addFile(name: f.name, size: f.size, mtime: mtime, mode: f.unixMode ?? 0o644, symlink: f.isSymlink) { sink in
                        var left = f.size; var crc: UInt32 = 0
                        while left > 0 {
                            try Task.checkCancellation()
                            let d = try src.read(Int(min(left, 1 << 20)))
                            if d.isEmpty { throw AXError.corrupt("“\(f.name)” ended unexpectedly") }
                            left -= UInt64(d.count); crc = CRC32.update(crc, d); try sink.write(d); try tracker.add(d.count)
                        }
                        if let want = f.crc, want != crc { throw AXError.corrupt("CRC mismatch in “\(f.name)”") }
                    }
                }
                for it in newItems {
                    try Task.checkCancellation()
                    switch it.kind {
                    case .dir: w.addDirectory(name: it.name, mtime: it.mtime, mode: it.mode)
                    case .symlink:
                        let target = Data(((try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? "").utf8)
                        try w.addFile(name: it.name, size: UInt64(target.count), mtime: it.mtime, mode: it.mode, symlink: true) { try $0.write(target) }
                    case .file: try w.addFile(name: it.name, size: it.size, mtime: it.mtime, mode: it.mode) { try pump(it.url, into: $0, progress: tracker) }
                    }
                }
                try w.finish()
            } else if k == .zip {
                let arc = try ZipArchive(url: url)
                let total = arc.entries.reduce(Int64(0)) { $0 + Int64($1.usize) } + newItems.reduce(0) { $0 + Int64($1.size) }
                let tracker = ProgressTracker(total: total, report: progress)
                let existingComment = arc.comment.isEmpty ? nil : (String(data: arc.comment, encoding: .utf8) ?? String(data: arc.comment, encoding: .isoLatin1))
                let w = try ZipWriter(url: tmp, password: password, legacyCrypto: legacy, level: level, comment: existingComment)
                let ordered = arc.entries.enumerated().sorted { $0.element.localOffset < $1.element.localOffset }
                var ends: [Int: UInt64] = [:]
                for (n, item) in ordered.enumerated() {
                    ends[item.offset] = n + 1 < ordered.count ? ordered[n + 1].element.localOffset + arc.prefix : arc.cdOffset + arc.prefix
                }
                for (i, e) in arc.entries.enumerated() where !matches(SafePath.clean(e.name) ?? e.name) {
                    try Task.checkCancellation()
                    try w.addRaw(from: arc, entry: e, endOffset: ends[i]!, progress: tracker)
                }
                for it in newItems {
                    try Task.checkCancellation()
                    switch it.kind {
                    case .dir: try w.addDirectory(name: it.name, mtime: it.mtime, mode: it.mode)
                    case .symlink: try w.addSymlink(name: it.name, target: (try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? "", mtime: it.mtime)
                    case .file: try w.addFile(source: it.url, name: it.name, mtime: it.mtime, mode: it.mode, progress: tracker)
                    }
                }
                try w.finish()
            } else {
                let f = try FileIn(url)
                let reader = TarReader(FileSource(f))
                let tracker = ProgressTracker(total: Int64(f.size) + newItems.reduce(0) { $0 + Int64($1.size) }, report: progress)
                let w = TarWriter(sink: try FileOut(tmp))
                while let e = try reader.next() {
                    try Task.checkCancellation()
                    if matches(e.path) { try reader.skipData(e) } else { try w.addRaw(e, from: reader, progress: tracker) }
                }
                for it in newItems {
                    try Task.checkCancellation()
                    switch it.kind {
                    case .dir: try w.addDirectory(name: it.name, mode: it.mode, mtime: it.mtime)
                    case .symlink: try w.addSymlink(name: it.name, target: (try? FileManager.default.destinationOfSymbolicLink(atPath: it.url.path)) ?? "", mode: it.mode, mtime: it.mtime)
                    case .file: try w.addFile(source: it.url, name: it.name, mode: it.mode, mtime: it.mtime, progress: tracker)
                    }
                }
                try w.finish()
            }
            try commit(tmp, as: url)
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            throw error
        }
    }
}
