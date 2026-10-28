import Foundation

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
        var c = ~crc
        data.withUnsafeBytes { raw in
            table.withUnsafeBufferPointer { t in
                for b in raw.bindMemory(to: UInt8.self) { c = t[Int((c ^ UInt32(b)) & 0xff)] ^ (c >> 8) }
            }
        }
        return ~c
    }
}

// MARK: - File access (POSIX, so large files and random access are cheap)

final class FileIn {
    let fd: Int32
    let size: UInt64
    let url: URL

    init(_ url: URL) throws {
        self.url = url
        fd = open(url.path, O_RDONLY)
        guard fd >= 0 else { throw AXError.io("Can’t open “\(url.lastPathComponent)”: \(String(cString: strerror(errno)))") }
        var st = stat()
        fstat(fd, &st)
        size = UInt64(st.st_size)
    }
    deinit { close(fd) }

    func read(at offset: UInt64, _ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let n = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress, count, off_t(offset)) }
        if n < 0 { throw AXError.io("Read error: \(String(cString: strerror(errno)))") }
        if n < count { data.removeSubrange(n..<count) }
        return data
    }

    /// Reads exactly `count` bytes or throws (truncated archive).
    func readExactly(at offset: UInt64, _ count: Int) throws -> Data {
        let d = try read(at: offset, count)
        guard d.count == count else { throw AXError.corrupt("unexpected end of file") }
        return d
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
        fd = open(url.path, O_RDWR | O_CREAT | O_TRUNC, mode)
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

    /// Where a member should be written, or nil to skip it (unsafe, or "skip existing").
    func destination(for rawName: String, isDir: Bool) throws -> URL? {
        guard let rel = SafePath.clean(rawName) else { skippedUnsafe.append(rawName); return nil }
        let relative = keepPaths ? rel : (rel as NSString).lastPathComponent
        var url = root.appendingPathComponent(relative)
        let fm = FileManager.default

        // Resolve symlinks in the parent chain: a previously extracted symlink must not redirect writes.
        let parent = url.deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true)
        let parentReal = parent.resolvingSymlinksInPath().path
        guard parentReal == rootReal || parentReal.hasPrefix(rootReal + "/") else {
            skippedUnsafe.append(rawName); return nil
        }

        if !isDir, fm.fileExists(atPath: url.path) || (try? url.checkResourceIsReachable()) == true || isSymlink(url) {
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
        var attrs: [FileAttributeKey: Any] = [:]
        if let mode { attrs[.posixPermissions] = Int(mode & 0o7777) }
        if let mtime { attrs[.modificationDate] = mtime }
        if !attrs.isEmpty { try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path) }
    }

    /// Creates a symlink only when it stays inside the destination.
    func makeSymlink(at url: URL, target: String) {
        guard !target.hasPrefix("/") else { skippedUnsafe.append(url.lastPathComponent + " → " + target); return }
        let resolved = url.deletingLastPathComponent().appendingPathComponent(target).standardized.path
        let rootStd = root.standardized.path
        guard resolved == rootStd || resolved.hasPrefix(rootStd + "/") else {
            skippedUnsafe.append(url.lastPathComponent + " → " + target); return
        }
        try? FileManager.default.createSymbolicLink(atPath: url.path, withDestinationPath: target)
    }
}

enum Dates {
    static let formatter: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd HH:mm"; return f
    }()
    static func text(_ d: Date?) -> String { d.map { formatter.string(from: $0) } ?? "" }
}
