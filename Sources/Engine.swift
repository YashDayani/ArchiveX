import Foundation

// Shared data types for the interface, and the table of formats ArchiveX understands.
// All archive work is done by ArchiveX Core (Sources/Core).

struct ArchiveEntry: Identifiable, Hashable {
    var id: String { path }
    var path: String
    var isDir: Bool
    var size: Int64
    var packed: Int64
    var ratio: String
    var mtime: String
    var crc: String
    var attrs: String
    var encrypted: Bool
}

struct Listing {
    var entries: [ArchiveEntry] = []
    var details: String = ""
    var solid = false
    var headerEncrypted = false
    /// Real packed size of the whole archive when per-file values are unknown (solid archives).
    var totalPacked: Int64?
}

// MARK: - Display rows (one folder level of the archive)

struct Row: Identifiable, Hashable {
    var id: String          // full path inside the archive
    var name: String
    var isDir: Bool
    var size: Int64
    var packed: Int64
    var ratio: String
    var mtime: String
    var crc: String
    var encrypted: Bool
    /// Solid archives only record a packed size per block, so per-item values are meaningless.
    var hidePacked = false

    var kind: String {
        if isDir { return "Folder" }
        let ext = (name as NSString).pathExtension
        return ext.isEmpty ? "File" : "\(ext.uppercased()) file"
    }
    var sizeText: String { isDir && size == 0 ? "" : Fmt.bytes(size) }
    var packedText: String { hidePacked || (isDir && packed == 0) ? "" : Fmt.bytes(packed) }
}

enum Fmt {
    static func bytes(_ n: Int64) -> String {
        n == 0 ? "0 bytes" : ByteCountFormatter.string(fromByteCount: n, countStyle: .file)
    }
}

func rows(from entries: [ArchiveEntry], in dir: String) -> [Row] {
    let prefix = dir.isEmpty ? "" : dir + "/"
    var folders: [String: Row] = [:]
    var files: [Row] = []
    for e in entries where e.path.hasPrefix(prefix) && e.path.count > prefix.count {
        let rest = e.path.dropFirst(prefix.count)
        if let slash = rest.firstIndex(of: "/") {
            let name = String(rest[..<slash])
            var f = folders[name] ?? Row(id: prefix + name, name: name, isDir: true, size: 0, packed: 0,
                                         ratio: "", mtime: "", crc: "", encrypted: false)
            if !e.isDir { f.size += e.size; f.packed += e.packed }
            f.encrypted = f.encrypted || e.encrypted
            folders[name] = f
        } else if e.isDir {
            var f = folders[String(rest)] ?? Row(id: e.path, name: String(rest), isDir: true, size: 0, packed: 0,
                                                 ratio: "", mtime: "", crc: "", encrypted: false)
            f.mtime = e.mtime
            folders[String(rest)] = f
        } else {
            files.append(Row(id: e.path, name: String(rest), isDir: false, size: e.size, packed: e.packed,
                             ratio: e.ratio, mtime: e.mtime, crc: e.crc, encrypted: e.encrypted))
        }
    }
    return Array(folders.values) + files
}

// MARK: - Formats

enum ArchiveFormat: String, CaseIterable, Identifiable {
    case sevenZ = "7z", zip = "ZIP", rar = "RAR", tar = "TAR"
    case tgz = "TAR.GZ", tbz2 = "TAR.BZ2", txz = "TAR.XZ"
    var id: String { rawValue }

    var ext: String {
        switch self {
        case .sevenZ: return "7z"; case .zip: return "zip"; case .rar: return "rar"; case .tar: return "tar"
        case .tgz: return "tar.gz"; case .tbz2: return "tar.bz2"; case .txz: return "tar.xz"
        }
    }
    var isTarCompressed: Bool { self == .tgz || self == .tbz2 || self == .txz }
    var password: Bool { self == .sevenZ || self == .zip || self == .rar }
    var headerEncryption: Bool { self == .sevenZ }
    var level: Bool { self != .tar && self != .rar }
    var solid: Bool { self == .sevenZ }                      // RAR files are written uncompressed, so “solid” would mean nothing
    /// Formats whose archives can have files added or removed in place.
    var canUpdate: Bool { self == .sevenZ || self == .zip || self == .tar || self == .rar }

    /// Extensions ArchiveX can open.
    static let knownExtensions: Set<String> = [
        "zip", "jar", "cbz", "apk", "ipa", "epub", "7z", "rar", "tar", "gz", "tgz", "taz", "bz2", "tbz", "tbz2", "tb2",
        "xz", "txz", "iso", "cpio"
    ]

    /// Format of an existing archive that can be edited.
    static func forExisting(_ url: URL) -> ArchiveFormat? {
        let n = url.lastPathComponent.lowercased()
        if n.hasSuffix(".7z") { return .sevenZ }
        if n.hasSuffix(".zip") || n.hasSuffix(".cbz") || n.hasSuffix(".jar") { return .zip }
        if n.hasSuffix(".tar") { return .tar }
        if n.hasSuffix(".rar") { return .rar }
        return nil
    }

    static func isArchive(_ url: URL) -> Bool { AXCore.handles(url) }
}
