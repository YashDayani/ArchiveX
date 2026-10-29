import Foundation
import zlib

// ArchiveX Core — our own archive engine. Everything under Sources/Core is original code;
// the only external pieces it touches are Apple system frameworks (Foundation, Compression,
// CommonCrypto, CryptoKit), exactly like the SwiftUI interface does.

enum AXError: LocalizedError {
    case corrupt(String)
    case unsupported(String)
    case wrongPassword
    case passwordRequired
    case io(String)
    case unsafe(String)

    var errorDescription: String? {
        switch self {
        case .corrupt(let m): return "The archive is damaged: \(m)"
        case .unsupported(let m): return "Not supported: \(m)"
        case .wrongPassword: return "Wrong password."
        case .passwordRequired: return "A password is required."
        case .io(let m): return m
        case .unsafe(let m): return "Skipped unsafe entry: \(m)"
        }
    }
}

// MARK: - Little-endian helpers

extension Data {
    func le16(_ o: Int) -> UInt16 { UInt16(self[startIndex + o]) | UInt16(self[startIndex + o + 1]) << 8 }
    func le32(_ o: Int) -> UInt32 { UInt32(le16(o)) | UInt32(le16(o + 2)) << 16 }
    func le64(_ o: Int) -> UInt64 { UInt64(le32(o)) | UInt64(le32(o + 4)) << 32 }

    mutating func put16(_ v: UInt16) { append(UInt8(v & 0xff)); append(UInt8(v >> 8)) }
    mutating func put32(_ v: UInt32) { put16(UInt16(v & 0xffff)); put16(UInt16(v >> 16)) }
    mutating func put64(_ v: UInt64) { put32(UInt32(v & 0xffff_ffff)); put32(UInt32(v >> 32)) }
}

// MARK: - Checksums

enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    /// Raw table step without the pre/post inversion (used by ZipCrypto).
    @inline(__always) static func step(_ crc: UInt32, _ byte: UInt8) -> UInt32 {
        table[Int((crc ^ UInt32(byte)) & 0xff)] ^ (crc >> 8)
    }

    static func update(_ crc: UInt32, _ data: Data) -> UInt32 {
        guard !data.isEmpty else { return crc }
        return data.withUnsafeBytes { raw in
            UInt32(zlib.crc32(uLong(crc), raw.bindMemory(to: Bytef.self).baseAddress, uInt(raw.count)))
        }
    }
}

// MARK: - File access (POSIX, so large files and random access are cheap)

final class FileIn {
    let size: UInt64
    let url: URL
    /// One entry per file; a split archive (name.7z.001, name.7z.002, …) reads as one continuous file.
    private(set) var parts: [(fd: Int32, start: UInt64, size: UInt64, base: UInt64)] = []
    let partURLs: [URL]

    convenience init(_ url: URL) throws { try self.init(parts: [url], shownAs: url) }

    init(parts urls: [URL], shownAs: URL) throws {
        url = shownAs
        partURLs = urls
        var start: UInt64 = 0
        for u in urls {
            let fd = open(u.path, O_RDONLY)
            guard fd >= 0 else {
                for p in parts { close(p.fd) }
                throw AXError.io("Can’t open “\(u.lastPathComponent)”: \(String(cString: strerror(errno)))")
            }
            var st = stat()
            fstat(fd, &st)
            parts.append((fd, start, UInt64(st.st_size), 0))
            start += UInt64(st.st_size)
        }
        size = start
    }
    /// A window onto part of a file (a payload inside a package), readable like a file of its own.
    init(window u: URL, offset: UInt64, length: UInt64) throws {
        url = u
        partURLs = [u]
        let fd = open(u.path, O_RDONLY)
        guard fd >= 0 else { throw AXError.io("Can’t open “\(u.lastPathComponent)”: \(String(cString: strerror(errno)))") }
        var st = stat()
        fstat(fd, &st)
        let avail = UInt64(st.st_size) > offset ? UInt64(st.st_size) - offset : 0
        let len = min(length, avail)
        parts = [(fd, 0, len, offset)]
        size = len
    }
    deinit { for p in parts { close(p.fd) } }

    func read(at offset: UInt64, _ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        var got = 0
        var pos = offset
        for p in parts where got < count && pos < p.start + p.size {
            let inPart = pos - p.start
            let want = min(count - got, Int(p.size - inPart))
            let n = data.withUnsafeMutableBytes { pread(p.fd, $0.baseAddress! + got, want, off_t(inPart + p.base)) }
            if n < 0 { throw AXError.io("Read error: \(String(cString: strerror(errno)))") }
            got += n; pos += UInt64(n)
            if n < want { break }
        }
        if got < count { data.removeSubrange(got..<count) }
        return data
    }

    /// Reads exactly `count` bytes or throws (truncated archive).
    func readExactly(at offset: UInt64, _ count: Int) throws -> Data {
        let d = try read(at: offset, count)
        guard d.count == count else { throw AXError.corrupt("unexpected end of file") }
        return d
    }

    /// Opens an archive, joining the parts of a split set when `url` names one.
    static func openArchive(_ url: URL) throws -> FileIn {
        if let set = splitSet(for: url) ?? zipSpanSet(for: url) { return try FileIn(parts: set, shownAs: url) }
        return try FileIn(url)
    }

    /// Info-ZIP style spanned archives: name.z01, name.z02, …, then name.zip last.
    static func zipSpanSet(for url: URL) -> [URL]? {
        let dir = url.deletingLastPathComponent()
        let name = url.lastPathComponent
        let ext = url.pathExtension.lowercased()
        let base = (name as NSString).deletingPathExtension
        guard ext == "zip" || (ext.count == 3 && ext.hasPrefix("z") && Int(ext.dropFirst()) != nil) else { return nil }
        var out: [URL] = []
        var i = 1
        while true {
            let u = dir.appendingPathComponent(base + ".z" + String(format: "%02d", i))
            guard FileManager.default.fileExists(atPath: u.path) else { break }
            out.append(u); i += 1
        }
        guard !out.isEmpty else { return nil }
        let last = dir.appendingPathComponent(base + ".zip")
        guard FileManager.default.fileExists(atPath: last.path) else { return nil }
        return out + [last]
    }

    /// Finds the other parts of a split archive from the name of one of them (“x.7z.001”, “x.zip.002”, …).
    static func splitSet(for url: URL) -> [URL]? {
        let name = url.lastPathComponent
        guard let dot = name.lastIndex(of: "."), name.distance(from: dot, to: name.endIndex) == 4,
              let n = Int(name[name.index(after: dot)...]), n >= 1 else { return nil }
        let base = String(name[..<dot])
        let width = 3
        var out: [URL] = []
        var i = 1
        while true {
            let u = url.deletingLastPathComponent().appendingPathComponent(base + "." + String(format: "%0*d", width, i))
            guard FileManager.default.fileExists(atPath: u.path) else { break }
            out.append(u); i += 1
        }
        return out.isEmpty ? nil : out
    }
}

protocol ByteSink: AnyObject {
    func write(_ data: Data) throws
    func finish() throws
}

final class FileOut: ByteSink {
    let fd: Int32
    private(set) var position: UInt64 = 0
    let url: URL

    init(_ url: URL, mode: mode_t = 0o644) throws {
        self.url = url
        fd = open(url.path, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw AXError.io("Can’t create “\(url.lastPathComponent)”: \(String(cString: strerror(errno)))") }
    }
    deinit { close(fd) }

    func write(_ data: Data) throws {
        try data.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                let n = Foundation.write(fd, raw.baseAddress! + off, raw.count - off)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw AXError.io("Write error: \(String(cString: strerror(errno)))")
                }
                off += n
            }
        }
        position += UInt64(data.count)
    }

    func write(at offset: UInt64, _ data: Data) throws {
        let n = data.withUnsafeBytes { pwrite(fd, $0.baseAddress, data.count, off_t(offset)) }
        if n != data.count { throw AXError.io("Write error: \(String(cString: strerror(errno)))") }
    }

    func seekToEnd(of offset: UInt64) { lseek(fd, off_t(offset), SEEK_SET); position = offset }
    func truncate(to length: UInt64) { ftruncate(fd, off_t(length)); lseek(fd, off_t(length), SEEK_SET); position = length }
    func finish() throws {}
}

/// Collects everything in memory (small streams only).
final class MemorySink: ByteSink {
    var data = Data()
    func write(_ d: Data) throws { data.append(d) }
    func finish() throws {}
}

/// Throws the bytes away (used for integrity tests) while counting them.
final class NullSink: ByteSink {
    var count: UInt64 = 0
    func write(_ d: Data) throws { count += UInt64(d.count) }
    func finish() throws {}
}

// MARK: - Progress

final class ProgressTracker {
    let total: Int64
    private(set) var done: Int64 = 0
    private let report: (Double) -> Void
    private var last = -1

    init(total: Int64, report: @escaping (Double) -> Void) { self.total = max(total, 1); self.report = report }

    func add(_ n: Int) throws {
        try Task.checkCancellation()
        done += Int64(n)
        let pct = min(100, Int(Double(done) / Double(total) * 100))
        if pct != last { last = pct; report(Double(pct) / 100) }
    }
}

// MARK: - Paths

enum SafePath {
    /// Turns an archive member name into a safe relative path, or nil when it could escape
    /// the destination (absolute paths, "..", empty names). Windows separators are accepted.
    static func clean(_ name: String) -> String? {
        let comps = name.replacingOccurrences(of: "\\", with: "/")
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
            .filter { $0 != "." }
        if comps.isEmpty || comps.contains("..") { return nil }
        return comps.joined(separator: "/")
    }
}

/// Writes archive members under a destination folder with overwrite policy and zip-slip protection.
final class Extractor {
    enum Overwrite { case all, skip, rename }

    let root: URL
    let rootReal: String
    let overwrite: Overwrite
    let keepPaths: Bool
    let selection: [(path: String, isDir: Bool)]
    private(set) var skippedUnsafe: [String] = []
    private var createdLinks: [URL] = []
    private(set) var extracted = 0

    init(destination: URL, overwrite: Overwrite, keepPaths: Bool, selection: [(path: String, isDir: Bool)]) throws {
        root = destination
        self.overwrite = overwrite
        self.keepPaths = keepPaths
        self.selection = selection
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        rootReal = destination.resolvingSymlinksInPath().path
    }

    func isSelected(_ path: String) -> Bool {
        if selection.isEmpty { return true }
        return selection.contains { $0.path == path || ($0.isDir && path.hasPrefix($0.path + "/")) }
    }

    private func inside(_ path: String) -> Bool { path == rootReal || path.hasPrefix(rootReal + "/") }

    /// Creates the parent folders of `relative` one component at a time, checking after every step that the real
    /// (symlink-resolved) location is still inside the destination. Returns nil when the path would leave it.
    private func safeParent(of relative: String) throws -> URL? {
        let comps = relative.split(separator: "/").dropLast().map(String.init)
        var cur = rootReal
        let fm = FileManager.default
        for c in comps {
            let next = cur + "/" + c
            var st = stat()
            if lstat(next, &st) == 0 {
                if (st.st_mode & S_IFMT) == S_IFLNK {                           // an existing symlink: only follow it if it stays inside
                    let real = URL(fileURLWithPath: next).resolvingSymlinksInPath().path
                    guard inside(real) else { return nil }
                    cur = real
                } else { cur = next }
            } else {
                try fm.createDirectory(atPath: next, withIntermediateDirectories: false)
                cur = next
            }
            guard inside(cur) else { return nil }
        }
        return URL(fileURLWithPath: cur)
    }

    /// Where a member should be written, or nil to skip it (unsafe, or "skip existing").
    func destination(for rawName: String, isDir: Bool) throws -> URL? {
        guard let rel = SafePath.clean(rawName) else { skippedUnsafe.append(rawName); return nil }
        let relative = keepPaths ? rel : (rel as NSString).lastPathComponent
        let fm = FileManager.default
        guard let parent = try safeParent(of: relative) else { skippedUnsafe.append(rawName); return nil }
        var url = parent.appendingPathComponent((relative as NSString).lastPathComponent)

        if isDir {
            // never "create" a folder over a symlink: attributes would then be applied to wherever it points
            if isSymlink(url) { skippedUnsafe.append(rawName); return nil }
            extracted += 1
            return url
        }
        if fm.fileExists(atPath: url.path) || (try? url.checkResourceIsReachable()) == true || isSymlink(url) {
            switch overwrite {
            case .skip: return nil
            case .all: try? fm.removeItem(at: url)
            case .rename: url = uniqueName(url)
            }
        }
        extracted += 1
        return url
    }

    private func isSymlink(_ url: URL) -> Bool {
        var st = stat()
        return lstat(url.path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK
    }

    private func uniqueName(_ url: URL) -> URL {
        let dir = url.deletingLastPathComponent()
        let ext = url.pathExtension
        let base = url.deletingPathExtension().lastPathComponent
        var i = 1
        while true {
            let name = ext.isEmpty ? "\(base) (\(i))" : "\(base) (\(i)).\(ext)"
            let candidate = dir.appendingPathComponent(name)
            if !FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            i += 1
        }
    }

    /// Applies permissions and modification time recorded in the archive.
    func finalize(_ url: URL, mode: UInt32?, mtime: Date?) {
        guard !isSymlink(url) else { return }
        var attrs: [FileAttributeKey: Any] = [:]
        if let mode { attrs[.posixPermissions] = Int(mode & 0o7777) }
        if let mtime { attrs[.modificationDate] = mtime }
        if !attrs.isEmpty { try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path) }
    }

    /// True when following `target` from `directory` (a real path inside the destination) never leaves the destination.
    /// Existing symlinks along the way are expanded component by component, so tricks like a link that points at a
    /// deeper-looking path and is then walked back out with `..` are caught.
    private func staysInside(_ target: String, from directory: String) -> Bool {
        var cur = directory
        var pending = target.split(separator: "/").map(String.init).reversed() as [String]
        var hops = 0
        while let c = pending.popLast() {
            if c.isEmpty || c == "." { continue }
            if c == ".." {
                if cur == rootReal { return false }
                cur = (cur as NSString).deletingLastPathComponent
                continue
            }
            let next = cur + "/" + c
            var st = stat()
            if lstat(next, &st) != 0 {
                // A component that doesn't exist yet could later become a symlink, which would change what a
                // following ".." means. Don't guess: refuse such targets.
                if pending.contains("..") { return false }
                cur = next
                continue
            }
            if (st.st_mode & S_IFMT) == S_IFLNK {
                hops += 1
                guard hops <= 40, let t = try? FileManager.default.destinationOfSymbolicLink(atPath: next), !t.hasPrefix("/") else { return false }
                pending.append(contentsOf: t.split(separator: "/").map(String.init).reversed())
                continue
            }
            cur = next
        }
        return inside(cur)
    }

    /// Creates a symlink only when it stays inside the destination.
    func makeSymlink(at url: URL, target: String) {
        guard !target.hasPrefix("/") else { skippedUnsafe.append(url.lastPathComponent + " → " + target); return }
        let dir = url.deletingLastPathComponent().resolvingSymlinksInPath().path
        guard inside(dir), staysInside(target, from: dir) else { skippedUnsafe.append(url.lastPathComponent + " → " + target); return }
        if (try? FileManager.default.createSymbolicLink(atPath: url.path, withDestinationPath: target)) != nil || FileManager.default.fileExists(atPath: url.path) {
            createdLinks.append(url)
            if !inside(url.resolvingSymlinksInPath().path) {                      // belt and braces: check the result too
                try? FileManager.default.removeItem(at: url); createdLinks.removeLast()
                skippedUnsafe.append(url.lastPathComponent + " → " + target)
            }
        }
    }

    /// Final sweep: entries extracted later may have changed what an earlier symlink resolves to.
    func verifyLinks() {
        for u in createdLinks where !inside(u.resolvingSymlinksInPath().path) {
            try? FileManager.default.removeItem(at: u)
            skippedUnsafe.append(u.lastPathComponent + " (link would leave the destination)")
        }
    }
}

enum Dates {
    static let formatter: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd HH:mm"; return f
    }()
    static func text(_ d: Date?) -> String { d.map { formatter.string(from: $0) } ?? "" }
}
