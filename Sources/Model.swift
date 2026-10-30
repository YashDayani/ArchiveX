import SwiftUI
import CryptoKit
import UniformTypeIdentifiers
import AppKit
import Darwin

struct ArchiveInfo: Identifiable {
    let id = UUID()
    var name: String
    var path: String
    var formatName: String
    var fileSize: Int64
    var fileCount: Int
    var folderCount: Int
    var totalUncompressed: Int64
    var totalPacked: Int64
    var compressionRatio: String
    var isSolid: Bool
    var isEncrypted: Bool
    var encryptionDetails: String
    var details: String
    var comment: String? = nil
}

struct AlertInfo: Identifiable {
    let id = UUID()
    var title: String
    var message: String
    var actionTitle: String? = nil
    var isDestructive = false
    var action: (() -> Void)? = nil
}

enum SplitPreset: String, CaseIterable, Identifiable {
    case none = "None"
    case mb10 = "10 MB"
    case mb100 = "100 MB"
    case cd700 = "700 MB (CD)"
    case fat32 = "4 GB (FAT32)"
    case custom = "Custom…"

    var id: String { rawValue }

    var bytes: UInt64? {
        switch self {
        case .none: return nil
        case .mb10: return 10 * 1024 * 1024
        case .mb100: return 100 * 1024 * 1024
        case .cd700: return 700 * 1024 * 1024
        case .fat32: return 4_294_967_295
        case .custom: return nil
        }
    }
}

struct AddDraft: Identifiable {
    let id = UUID()
    var files: [URL]
    var archivePath: String
    var format = ArchiveFormat.sevenZ
    var level = 3                 // 0 Store ... 5 Best
    var solid = true
    var test = false
    var deleteAfter = false
    var encryptNames = false
    var password = ""
    var confirm = ""
    var legacyZipCrypto = false   // ZIP only: PKWARE ZipCrypto (opens in macOS Archive Utility, but weak)
    var updatingExisting = false
    var comment: String = ""
    var splitPreset: SplitPreset = .none
    var customSplitMB: Int = 100
}

struct ExtractDraft: Identifiable {
    let id = UUID()
    var destination: String
    var onlySelected: Bool
    var overwrite = Prefs.overwrite
    var keepPaths = true
    var openAfter = Prefs.reveal
    var hasSelection: Bool

    enum Overwrite: String, CaseIterable, Identifiable {
        case all = "Overwrite existing files"
        case skip = "Skip existing files"
        case rename = "Rename extracted files"
        var id: String { rawValue }
        var core: Extractor.Overwrite { self == .all ? .all : self == .skip ? .skip : .rename }
    }
}

@MainActor
final class ArchiveModel: ObservableObject {
    @Published var archiveURL: URL?
    @Published var entries: [ArchiveEntry] = []
    @Published var details = ""
    @Published var packedPerFileUnknown = false
    @Published var packedTotal: Int64?
    @Published var currentDir = ""
    @Published var selection = Set<String>()
    @Published var busy = false
    @Published var busyLabel = ""
    @Published var progress: Double?
    @Published var progressDetail: String?
    @Published var alert: AlertInfo?
    @Published var addDraft: AddDraft?
    @Published var extractDraft: ExtractDraft?
    @Published var passwordPrompt = false
    @Published var password: String?
    @Published var quickLookURL: URL?
    @Published var searchQuery = ""
    @Published var hashResults: [ArchiveHasher.Result]?
    /// The side panel with a preview and details (⌘I); remembered between launches, on by default.
    @Published var showInspector = UserDefaults.standard.object(forKey: "showInspector") as? Bool ?? true {
        didSet { UserDefaults.standard.set(showInspector, forKey: "showInspector") }
    }
    @Published var archiveComment: String? = nil
    @Published var searchFieldFocused = false

    private var afterPassword: (() -> Void)?
    private var cancelWork: (() -> Void)?

    // MARK: running jobs (in-process, cancellable)

    /// Runs one of the blocking jobs of ArchiveX Core off the main thread, with progress and cancel.
    private func run<T: Sendable>(_ label: String,
                                  _ work: @escaping @Sendable (@escaping @Sendable (Double) -> Void) throws -> T) async -> Result<T, Error> {
        busy = true; busyLabel = label; progress = nil; progressDetail = nil
        let started = Date()
        let onProgress: @Sendable (Double) -> Void = { [weak self] p in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.progress = p
                let elapsed = Date().timeIntervalSince(started)
                let left = JobTime.remaining(elapsed: elapsed, fraction: p).map(JobTime.text(remaining:))
                self.progressDetail = [left, "Elapsed \(JobTime.elapsed(elapsed))"].compactMap { $0 }.joined(separator: " · ")
                JobNotifier.dock(p)
            }
        }
        let task = Task.detached(priority: .userInitiated) { () throws -> T in
            try work(onProgress)
        }
        cancelWork = { task.cancel() }
        let result = await task.result
        cancelWork = nil; busy = false; progress = nil; progressDetail = nil
        let what = label.trimmingCharacters(in: CharacterSet(charactersIn: ". …"))
        switch result {
        case .success: JobNotifier.finished("\(what) finished.", afterSeconds: Date().timeIntervalSince(started))
        case .failure(let e):
            if e is CancellationError { JobNotifier.dock(nil) }
            else { JobNotifier.finished("\(what) didn’t finish. Open ArchiveX to see why.", afterSeconds: Date().timeIntervalSince(started)) }
        }
        return result
    }

    func cancel() { cancelWork?() }

    private func needsPassword(_ e: Error) -> Bool {
        guard let ax = e as? AXError else { return false }
        switch ax { case .passwordRequired, .wrongPassword: return true; default: return false }
    }

    /// Password prompts, silent cancellation, and alerts for everything else.
    private func handle(_ error: Error, title: String, retry: @escaping () -> Void) {
        if error is CancellationError { return }
        if needsPassword(error) {
            if case .wrongPassword? = error as? AXError { password = nil }
            afterPassword = retry; passwordPrompt = true
            return
        }
        alert = AlertInfo(title: title, message: FriendlyError.describe(error))
    }

    private var selectionPairs: [(path: String, isDir: Bool)] { selectedRows.map { (path: $0.id, isDir: $0.isDir) } }

    // MARK: derived

    var visibleRows: [Row] {
        let q = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        let r: [Row]
        if q.isEmpty {
            r = rows(from: entries, in: currentDir)
        } else {
            let qLower = q.lowercased()
            let isWildcard = q.contains("*") || q.contains("?")
            let matched = entries.filter { e in
                let name = (e.path as NSString).lastPathComponent
                let full = e.path
                if isWildcard {
                    return fnmatch(q, name, FNM_CASEFOLD) == 0 || fnmatch(q, full, FNM_CASEFOLD) == 0
                }
                let nameLower = name.lowercased()
                let fullLower = full.lowercased()
                if qLower.hasPrefix(".") {
                    return nameLower.hasSuffix(qLower) || fullLower.hasSuffix(qLower)
                }
                return nameLower.contains(qLower) || fullLower.contains(qLower)
            }
            r = matched.map { e in
                Row(id: e.path, name: e.path, isDir: e.isDir, size: e.size, packed: e.packed,
                    ratio: e.ratio, mtime: e.mtime, crc: e.crc, encrypted: e.encrypted)
            }
        }
        guard packedPerFileUnknown else { return r }
        return r.map { var x = $0; x.hidePacked = true; x.ratio = ""; return x }
    }
    var hasArchive: Bool { archiveURL != nil }
    var fileCount: Int { entries.filter { !$0.isDir }.count }
    var totalSize: Int64 { entries.reduce(0) { $0 + ($1.isDir ? 0 : $1.size) } }
    var totalPacked: Int64 { packedTotal ?? entries.reduce(0) { $0 + ($1.isDir ? 0 : $1.packed) } }
    var title: String { archiveURL?.lastPathComponent ?? "ArchiveX" }

    var selectedRows: [Row] {
        let ids = selection
        return visibleRows.filter { ids.contains($0.id) }
    }

    // MARK: open / refresh

    func open(_ url: URL) {
        guard AXCore.handles(url) else {
            alert = AlertInfo(title: "Can’t open this file",
                              message: "ArchiveX opens ZIP, 7z, RAR 5, TAR, GZ, BZ2, XZ, ISO and CPIO archives. “\(url.lastPathComponent)” is not one of them.")
            return
        }
        let pw = password
        Task { [weak self] in
            guard let self else { return }
            switch await self.run("Opening archive…", { _ in try AXCore.list(url, password: pw) }) {
            case .success(let l):
                if self.archiveURL != url { self.selection = [] }
                self.archiveURL = url
                self.entries = l.entries; self.details = l.details
                self.packedPerFileUnknown = l.solid
                self.packedTotal = l.totalPacked
                self.archiveComment = l.comment
                self.currentDir = ""
                NSDocumentController.shared.noteNewRecentDocumentURL(url)
            case .failure(let e):
                self.handle(e, title: "Can’t open archive") { [weak self] in self?.open(url) }
            }
        }
    }

    func refresh() {
        guard let url = archiveURL else { return }
        let dir = currentDir, pw = password
        Task {
            if case .success(let l) = await run("Refreshing…", { _ in try AXCore.list(url, password: pw) }) {
                entries = l.entries; details = l.details
                packedPerFileUnknown = l.solid; packedTotal = l.totalPacked
                archiveComment = l.comment
                currentDir = entries.contains { $0.path.hasPrefix(dir + "/") } ? dir : ""
                selection = []
            }
        }
    }

    func close() {
        archiveURL = nil; entries = []; details = ""; currentDir = ""; selection = []; password = nil; archiveComment = nil
    }

    func goUp() {
        guard !currentDir.isEmpty else { return }
        currentDir = (currentDir as NSString).deletingLastPathComponent
        selection = []
    }

    func enter(_ row: Row) {
        if row.isDir { currentDir = row.id; selection = [] } else { view(row) }
    }

    /// Return / ⌘↓: opens the selected folder, or views the selected file.
    func openSelected() {
        guard selectedRows.count == 1, let r = selectedRows.first else { return }
        enter(r)
    }

    private var typeBuffer = "", typeStamp = Date.distantPast

    /// Typing letters jumps to the first row whose name starts with them (the buffer resets after a second).
    @discardableResult func typeahead(_ chars: String) -> Bool {
        let now = Date()
        typeBuffer = now.timeIntervalSince(typeStamp) > 1 ? chars.lowercased() : typeBuffer + chars.lowercased()
        typeStamp = now
        let rows = visibleRows.sorted { ($0.isDir ? 0 : 1, $0.name.lowercased()) < ($1.isDir ? 0 : 1, $1.name.lowercased()) }
        guard let hit = rows.first(where: { $0.name.lowercased().hasPrefix(typeBuffer) }) else { return false }
        selection = [hit.id]
        return true
    }

    // MARK: extract

    /// Archive name without its extension (handles .tar.gz and friends).
    private func baseName(_ url: URL) -> String {
        let n = url.lastPathComponent
        for e in [".tar.gz", ".tar.bz2", ".tar.xz"] where n.lowercased().hasSuffix(e) { return String(n.dropLast(e.count)) }
        return (n as NSString).deletingPathExtension
    }

    func prepareExtract() {
        guard let url = archiveURL else { return }
        let folder = url.deletingLastPathComponent().appendingPathComponent(baseName(url)).path
        let saved = UserDefaults.standard.string(forKey: "lastExtractDir")
        extractDraft = ExtractDraft(destination: saved.map { $0 + "/" + baseName(url) } ?? folder,
                                    onlySelected: !selection.isEmpty,
                                    hasSelection: !selection.isEmpty)
    }

    func quickExtract(toSubfolder: Bool) {
        guard let url = archiveURL else { return }
        let base = url.deletingLastPathComponent()
        let dest = toSubfolder ? base.appendingPathComponent(baseName(url)) : base
        extract(ExtractDraft(destination: dest.path, onlySelected: false, hasSelection: false))
    }

    func extract(_ d: ExtractDraft) {
        guard let url = archiveURL else { return }
        let dest = URL(fileURLWithPath: d.destination)
        UserDefaults.standard.set(dest.deletingLastPathComponent().path, forKey: "lastExtractDir")
        let sel = d.onlySelected ? selectionPairs : []
        let pw = password
        Task { [weak self] in
            guard let self else { return }
            switch await self.run("Extracting…", { p in
                try AXCore.extract(url, selection: sel, to: dest, overwrite: d.overwrite.core, keepPaths: d.keepPaths, password: pw, progress: p)
            }) {
            case .success(let skipped):
                if !skipped.isEmpty {
                    self.alert = AlertInfo(title: "Some entries were skipped",
                                           message: "\(skipped.count) entr\(skipped.count == 1 ? "y" : "ies") had unsafe paths (for example “../”) and were not extracted:\n" + skipped.prefix(5).joined(separator: "\n"))
                }
                if d.openAfter { NSWorkspace.shared.activateFileViewerSelecting([dest]) }
            case .failure(let e):
                self.handle(e, title: "Extraction failed") { [weak self] in self?.extract(d) }
            }
        }
    }

    func view(_ row: Row) {
        guard let url = archiveURL, !row.isDir else { return }
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("ArchiveX-\(UUID().uuidString)")
        let pw = password
        Task { [weak self] in
            guard let self else { return }
            switch await self.run("Extracting \(row.name)…", { p in
                try AXCore.extract(url, selection: [(path: row.id, isDir: false)], to: tmp, overwrite: .all, keepPaths: true, password: pw, progress: p)
            }) {
            case .success: NSWorkspace.shared.open(tmp.appendingPathComponent(row.id))
            case .failure(let e): self.handle(e, title: "Can’t open file") { [weak self] in self?.view(row) }
            }
        }
    }

    // MARK: scratch files (previews, drag-out, clipboard)

    nonisolated private static let scratchRoot = FileManager.default.temporaryDirectory.appendingPathComponent("ArchiveX-Scratch")
    private static var scratchCleaned = false

    /// Removes preview / drag / clipboard files left over from earlier runs. Done once per launch, before any are created.
    static func cleanOldScratch() {
        guard !scratchCleaned else { return }
        scratchCleaned = true
        let fm = FileManager.default
        try? fm.removeItem(at: scratchRoot)
        for n in (try? fm.contentsOfDirectory(atPath: fm.temporaryDirectory.path)) ?? [] where n.hasPrefix("ArchiveX-") && n != "ArchiveX-Scratch" {
            try? fm.removeItem(at: fm.temporaryDirectory.appendingPathComponent(n))
        }
    }

    nonisolated private static func newScratch(_ label: String) -> URL {
        let d = scratchRoot.appendingPathComponent("\(label)-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    /// A preview folder that is specific to one archive (and its current contents), so two archives that both hold
    /// “readme.txt” never show each other's file.
    private func previewFolder(for archive: URL) -> URL {
        let attrs = try? FileManager.default.attributesOfItem(atPath: archive.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let digest = SHA256.hash(data: Data("\(archive.path)|\(size)|\(mtime)".utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
        let d = Self.scratchRoot.appendingPathComponent("QuickLook-\(digest)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    /// Unpacks one file for the inspector's preview without the busy overlay. The file lands in the same per-archive folder
    /// Quick Look uses, so pressing Space afterwards is instant.
    func extractForPreview(_ row: Row) async throws -> URL {
        guard let url = archiveURL else { throw CancellationError() }
        let dir = previewFolder(for: url)
        let out = dir.appendingPathComponent(row.id)
        if FileManager.default.fileExists(atPath: out.path) { return out }
        let pw = password
        try await Task.detached(priority: .utility) {
            try AXCore.extract(url, selection: [(path: row.id, isDir: false)], to: dir, overwrite: .all, keepPaths: true, password: pw, progress: { _ in })
        }.value
        return out
    }

    func quickLookSelected() {
        if quickLookURL != nil {
            quickLookURL = nil
            return
        }
        guard let url = archiveURL else { return }
        guard let target = selectedRows.first(where: { !$0.isDir }) ?? visibleRows.first(where: { selection.contains($0.id) && !$0.isDir }) else { return }

        let cacheDir = previewFolder(for: url)
        let outURL = cacheDir.appendingPathComponent(target.id)

        if FileManager.default.fileExists(atPath: outURL.path) {
            self.quickLookURL = outURL
            return
        }

        let pw = password
        Task { [weak self] in
            guard let self else { return }
            switch await self.run("Preparing preview…", { p in
                try AXCore.extract(url, selection: [(path: target.id, isDir: false)], to: cacheDir, overwrite: .all, keepPaths: true, password: pw, progress: p)
            }) {
            case .success:
                self.quickLookURL = outURL
            case .failure(let e):
                self.handle(e, title: "Preview failed") { [weak self] in self?.quickLookSelected() }
            }
        }
    }

    /// What a drag out of the table carries. The file is not extracted when the drag starts: the receiver (Finder, Mail, …)
    /// asks for it when it is dropped, and the extraction then runs on a background queue, so the window never freezes.
    func fileProvider(for row: Row) -> NSItemProvider {
        let provider = NSItemProvider()
        provider.suggestedName = (row.id as NSString).lastPathComponent
        guard let archive = archiveURL else { return provider }
        let pw = password
        let id = row.id, isDir = row.isDir
        let type = isDir ? UTType.folder : (UTType(filenameExtension: (id as NSString).pathExtension) ?? .data)
        provider.registerFileRepresentation(forTypeIdentifier: type.identifier, fileOptions: [], visibility: .all) { completion in
            let progress = Progress(totalUnitCount: 1)
            DispatchQueue.global(qos: .userInitiated).async {
                let dir = ArchiveModel.newScratch("Drag")
                do {
                    try AXCore.extract(archive, selection: [(path: id, isDir: isDir)], to: dir, overwrite: .all, keepPaths: true, password: pw, progress: { _ in })
                    let out = dir.appendingPathComponent(id)
                    guard FileManager.default.fileExists(atPath: out.path) else { throw AXError.io("The item could not be extracted.") }
                    progress.completedUnitCount = 1
                    completion(out, false, nil)
                } catch { completion(nil, false, error) }
            }
            return progress
        }
        return provider
    }

    func copySelection() {
        let rows = selectedRows
        guard let url = archiveURL, !rows.isEmpty else { return }
        let cacheDir = Self.newScratch("Clipboard")
        let sel = selectionPairs
        let pw = password
        Task { [weak self] in
            guard let self else { return }
            switch await self.run("Copying to pasteboard…", { p in
                try AXCore.extract(url, selection: sel, to: cacheDir, overwrite: .all, keepPaths: true, password: pw, progress: p)
            }) {
            case .success:
                let urls = rows.map { cacheDir.appendingPathComponent($0.id) }.filter { FileManager.default.fileExists(atPath: $0.path) }
                guard !urls.isEmpty else { return }
                let pb = NSPasteboard.general
                pb.clearContents()
                pb.writeObjects(urls as [NSURL])
            case .failure(let e):
                self.handle(e, title: "Copy failed") { [weak self] in self?.copySelection() }
            }
        }
    }

    func selectAll() {
        selection = Set(visibleRows.map(\.id))
    }

    func focusSearch() {
        searchFieldFocused = true
    }

    func showArchiveInfo() { showInspector.toggle() }

    func makeArchiveInfo() -> ArchiveInfo? {
        guard let url = archiveURL else { return nil }
        let fs = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
        let files = entries.filter { !$0.isDir }.count
        let dirs = entries.filter { $0.isDir }.count
        let unp = entries.reduce(Int64(0)) { $0 + ($1.isDir ? 0 : $1.size) }
        let pck = packedTotal ?? entries.reduce(Int64(0)) { $0 + ($1.isDir ? 0 : $1.packed) }
        let ratioStr: String
        if unp > 0 {
            let pct = max(0, min(100, Double(pck) / Double(unp) * 100))
            let factor = Double(unp) / max(1, Double(pck))
            ratioStr = String(format: "%.1f%% (%.1fx reduction)", pct, factor)
        } else {
            ratioStr = "—"
        }
        let isEnc = entries.contains { $0.encrypted }
        let encStr: String
        if !isEnc {
            encStr = "None"
        } else {
            let ext = url.pathExtension.lowercased()
            if ext == "rar" { encStr = "AES-256 (PBKDF2-HMAC-SHA256)" }
            else if ext == "7z" { encStr = "AES-256 (SHA-256 KDF)" }
            else { encStr = "AES-256 / ZipCrypto" }
        }
        let formatStr: String
        if let f = ArchiveFormat.forExisting(url) {
            formatStr = f.rawValue
        } else {
            formatStr = url.pathExtension.uppercased()
        }

        return ArchiveInfo(
            name: url.lastPathComponent,
            path: url.path,
            formatName: formatStr,
            fileSize: fs,
            fileCount: files,
            folderCount: dirs,
            totalUncompressed: unp,
            totalPacked: pck,
            compressionRatio: ratioStr,
            isSolid: packedPerFileUnknown,
            isEncrypted: isEnc,
            encryptionDetails: encStr,
            details: details,
            comment: archiveComment
        )
    }

    func calculateHashes(for targetRows: [Row] = []) {
        guard let url = archiveURL else { return }
        let rowsToHash = targetRows.isEmpty ? selectedRows.filter { !$0.isDir } : targetRows.filter { !$0.isDir }
        let pw = password

        Task { [weak self] in
            guard let self else { return }
            if rowsToHash.isEmpty {
                // Hash the archive container file itself
                switch await self.run("Calculating checksums of “\(url.lastPathComponent)”…", { p in
                    try ArchiveHasher.hash(file: url, displayName: url.lastPathComponent, progress: p)
                }) {
                case .success(let r):
                    self.hashResults = [r]
                case .failure(let e):
                    self.handle(e, title: "Checksum calculation failed") { [weak self] in self?.calculateHashes() }
                }
            } else {
                // Hash the selected entries
                let cacheDir = Self.newScratch("Hash")
                defer { try? FileManager.default.removeItem(at: cacheDir) }

                var results: [ArchiveHasher.Result] = []
                for (i, row) in rowsToHash.enumerated() {
                    let label = rowsToHash.count > 1 ? "Hashing \(i + 1) of \(rowsToHash.count)…" : "Hashing “\(row.name)”…"
                    let res = await self.run(label, { p in
                        try AXCore.extract(url, selection: [(path: row.id, isDir: false)], to: cacheDir, overwrite: .all, keepPaths: true, password: pw, progress: p)
                        let extracted = cacheDir.appendingPathComponent(row.id)
                        return try ArchiveHasher.hash(file: extracted, displayName: row.name)
                    })
                    switch res {
                    case .success(let h): results.append(h)
                    case .failure(let e):
                        self.handle(e, title: "Hashing failed") { }
                        return
                    }
                }
                self.hashResults = results
            }
        }
    }

    // MARK: test / delete

    func test() {
        guard let url = archiveURL else { return }
        let pw = password
        Task { [weak self] in
            guard let self else { return }
            switch await self.run("Testing archive…", { p in try AXCore.test(url, password: pw, progress: p) }) {
            case .success:
                self.alert = AlertInfo(title: "No errors found", message: "All \(self.fileCount) files in “\(url.lastPathComponent)” passed the integrity test.")
            case .failure(let e): self.handle(e, title: "Errors found") { [weak self] in self?.test() }
            }
        }
    }

    func confirmDelete() {
        let rows = selectedRows
        guard let url = archiveURL, !rows.isEmpty else { return }
        guard AXCore.canEdit(url) else {
            alert = AlertInfo(title: "Archive is read-only",
                              message: "ArchiveX can remove files from ZIP, 7z, RAR and TAR archives. This format can only be opened and extracted.")
            return
        }
        alert = AlertInfo(title: "Delete \(rows.count) item\(rows.count == 1 ? "" : "s") from the archive?",
                          message: "This modifies the archive file and cannot be undone.",
                          actionTitle: "Delete", isDestructive: true) { [weak self] in self?.deleteSelected() }
    }

    private func deleteSelected() {
        guard let url = archiveURL else { return }
        let sel = selectionPairs, pw = password
        Task {
            switch await run("Deleting…", { p in try AXCore.edit(url, remove: sel, add: [], level: 3, password: pw, legacy: false, progress: p) }) {
            case .success: refresh()
            case .failure(let e): handle(e, title: "Delete failed") { }
            }
        }
    }

    // MARK: add / create

    /// Opens the "Archive name and parameters" dialog. `toOpenArchive` adds into the archive on screen.
    func prepareAdd(files: [URL], toOpenArchive: Bool = false) {
        var format = Prefs.defaultFormat
            ?? UserDefaults.standard.string(forKey: "lastFormat").flatMap(ArchiveFormat.init(rawValue:)) ?? .sevenZ
        let suggestion: String
        if toOpenArchive, let existing = archiveURL {
            guard let f = ArchiveFormat.forExisting(existing), f.canUpdate else {
                alert = AlertInfo(title: "Can’t add to this archive",
                                  message: "ArchiveX can add files to ZIP, 7z, RAR and TAR archives. Other formats can only be opened and extracted.")
                return
            }
            format = f
            suggestion = existing.path
        } else if let first = files.first {
            let base = files.count == 1 ? first.deletingPathExtension().lastPathComponent
                                        : first.deletingLastPathComponent().lastPathComponent
            suggestion = first.deletingLastPathComponent().appendingPathComponent(base + "." + format.ext).path
        } else {
            suggestion = (NSHomeDirectory() as NSString).appendingPathComponent("Desktop/Archive." + format.ext)
        }
        var d = AddDraft(files: files, archivePath: suggestion)
        d.format = format
        if let level = Prefs.defaultLevel { d.level = level }
        d.updatingExisting = FileManager.default.fileExists(atPath: suggestion)
        addDraft = d
    }

    /// Final archive path: swap whatever extension the user typed for the chosen format's.
    private func finalPath(_ d: AddDraft) -> String {
        var p = d.archivePath
        let lower = p.lowercased()
        for f in ArchiveFormat.allCases.sorted(by: { $0.ext.count > $1.ext.count }) where lower.hasSuffix("." + f.ext) {
            p = String(p.dropLast(f.ext.count + 1)); break
        }
        return p + "." + d.format.ext
    }

    func create(_ d: AddDraft) {
        UserDefaults.standard.set(d.format.rawValue, forKey: "lastFormat")
        let archive = finalPath(d)
        let target = URL(fileURLWithPath: archive)
        let openAfter = archiveURL?.path == archive
        let exists = FileManager.default.fileExists(atPath: archive)
        let wanted: AXKind? = d.format == .zip ? .zip : d.format == .tar ? .tar : d.format == .sevenZ ? .sevenZ : d.format == .rar ? .rar : nil
        let edit = exists && AXCore.canEdit(target) && AXCore.kind(of: target) == wanted
        if exists && !edit && d.format.isTarCompressed {
            alert = AlertInfo(title: "File already exists", message: "“\(target.lastPathComponent)” already exists and compressed TAR archives can’t be added to. Choose another name.")
            return
        }
        let level = (d.format == .sevenZ || d.format == .rar) ? d.level : (d.level == 0 ? 0 : 6)
        let pw: String? = d.password.isEmpty || !d.format.password ? nil : d.password
        let files = d.files
        let volSize: UInt64? = d.splitPreset == .custom ? (UInt64(max(1, d.customSplitMB)) * 1024 * 1024) : d.splitPreset.bytes
        let trimmedComment = d.comment.trimmingCharacters(in: .whitespacesAndNewlines)
        let comment: String? = trimmedComment.isEmpty ? nil : trimmedComment
        Task {
            let res = await run("Compressing…") { p in
                if edit {
                    try AXCore.edit(target, remove: [], add: files, level: level, password: pw, legacy: d.legacyZipCrypto, progress: p)
                    if d.deleteAfter { try AXCore.test(target, password: pw, progress: { _ in }); for f in files { try? FileManager.default.removeItem(at: f) } }
                } else {
                    try AXCore.create(AXCreate(format: d.format, output: target, items: files, level: level, password: pw,
                                               legacyZipCrypto: d.legacyZipCrypto, deleteAfter: d.deleteAfter,
                                               solid: d.solid, encryptNames: d.encryptNames, comment: comment,
                                               splitVolumeSize: volSize), progress: p)
                }
                if d.test {
                    let firstPart = target.deletingLastPathComponent().appendingPathComponent(target.lastPathComponent + ".001")
                    let testTarget = (volSize != nil && FileManager.default.fileExists(atPath: firstPart.path)) ? firstPart : target
                    try AXCore.test(testTarget, password: pw, progress: { _ in })
                }
            }
            switch res {
            case .success:
                if openAfter {
                    refresh()
                } else {
                    let firstPart = target.deletingLastPathComponent().appendingPathComponent(target.lastPathComponent + ".001")
                    let selectTarget = (volSize != nil && FileManager.default.fileExists(atPath: firstPart.path)) ? firstPart : target
                    NSWorkspace.shared.activateFileViewerSelecting([selectTarget])
                }
            case .failure(let e): handle(e, title: "Compression failed") { }
            }
        }
    }

    // MARK: password

    func submitPassword(_ pw: String) {
        password = pw
        passwordPrompt = false
        let next = afterPassword
        afterPassword = nil
        next?()
    }

    func cancelPassword() { passwordPrompt = false; afterPassword = nil }
}
