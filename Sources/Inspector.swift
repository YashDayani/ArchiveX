import PDFKit
import SwiftUI

// The side panel (⌘I): a preview of the selected file, its details, and what the archive is.

// MARK: - Preview

enum PreviewKind: Equatable {
    case image, text, pdf, none

    private static let images: Set<String> = ["png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "heic", "heif", "webp", "ico", "icns"]
    private static let texts: Set<String> = [
        "txt", "md", "markdown", "json", "xml", "yaml", "yml", "csv", "tsv", "log", "ini", "toml", "plist", "html", "htm", "css",
        "js", "ts", "jsx", "tsx", "py", "rb", "sh", "zsh", "swift", "c", "h", "cpp", "hpp", "m", "java", "kt", "go", "rs", "php", "sql", "tex", "srt",
    ]

    static func of(_ name: String) -> PreviewKind {
        let ext = (name as NSString).pathExtension.lowercased()
        if images.contains(ext) { return .image }
        if texts.contains(ext) { return .text }
        if ext == "pdf" { return .pdf }
        return .none
    }

    /// Largest file that is unpacked just to be previewed.
    var limit: Int64 { self == .text ? 2_000_000 : 40_000_000 }
}

enum PreviewState {
    case none, loading
    case image(NSImage)
    case text(String, truncated: Bool)
    case notice(String)
}
extension PreviewState: @unchecked Sendable {}

@MainActor
final class PreviewLoader: ObservableObject {
    @Published var state: PreviewState = .none
    private var task: Task<Void, Never>?
    private var cache: [String: PreviewState] = [:]

    func reset() { task?.cancel(); cache.removeAll(); state = .none }

    func load(_ row: Row?, in model: ArchiveModel) {
        task?.cancel()
        guard let row, !row.isDir else { state = .none; return }
        let kind = PreviewKind.of(row.name)
        guard kind != .none else { state = .none; return }
        if row.size > kind.limit { state = .notice("Too large to preview here. Press Space for Quick Look."); return }
        if row.encrypted && model.password == nil { state = .notice("Locked. Open the file once and enter the password to preview it."); return }
        let key = "\(model.archiveURL?.path ?? "")|\(row.id)"
        if let hit = cache[key] { state = hit; return }
        state = .loading
        task = Task { [weak self] in
            // Moving through rows with the arrow keys must not unpack every file on the way.
            try? await Task.sleep(nanoseconds: 150_000_000)
            if Task.isCancelled { return }
            do {
                let file = try await model.extractForPreview(row)
                if Task.isCancelled { return }
                let result = await Task.detached(priority: .utility) { Self.render(file, kind) }.value
                if Task.isCancelled { return }
                guard let self else { return }
                if self.cache.count > 24 { self.cache.removeAll() }
                self.cache[key] = result
                self.state = result
            } catch {
                if !(error is CancellationError) { self?.state = .notice("No preview available.") }
            }
        }
    }

    nonisolated static func render(_ file: URL, _ kind: PreviewKind) -> PreviewState {
        switch kind {
        case .image:
            guard let src = CGImageSourceCreateWithURL(file as CFURL, nil) else { return .notice("This image can’t be previewed.") }
            let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceCreateThumbnailWithTransform: true,
                                         kCGImageSourceThumbnailMaxPixelSize: 900]
            guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return .notice("This image can’t be previewed.") }
            return .image(NSImage(cgImage: cg, size: .zero))
        case .pdf:
            guard let page = PDFDocument(url: file)?.page(at: 0) else { return .notice("This PDF can’t be previewed.") }
            return .image(page.thumbnail(of: CGSize(width: 800, height: 1100), for: .cropBox))
        case .text:
            guard let h = try? FileHandle(forReadingFrom: file) else { return .notice("No preview available.") }
            defer { try? h.close() }
            let data = (try? h.read(upToCount: 8192)) ?? Data()
            if data.contains(0) { return .notice("No preview available.") }
            let more = ((try? h.read(upToCount: 1)) ?? Data()).isEmpty == false
            return .text(String(decoding: data, as: UTF8.self), truncated: more)
        case .none:
            return .none
        }
    }
}

// MARK: - Panel

struct InspectorPanel: View {
    @EnvironmentObject var model: ArchiveModel
    @StateObject private var preview = PreviewLoader()
    @State private var info: ArchiveInfo?

    private var singleFile: Row? { model.selectedRows.count == 1 ? model.selectedRows.first(where: { !$0.isDir }) : nil }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                selection
                if let info { archive(info) }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(.background)
        .task(id: "\(model.archiveURL?.path ?? "")-\(model.entries.count)") {
            info = model.makeArchiveInfo()
            preview.reset()
            preview.load(singleFile, in: model)
        }
        .onChange(of: model.selection) { _ in preview.load(singleFile, in: model) }
    }

    // MARK: the selected item(s)

    @ViewBuilder private var selection: some View {
        let rows = model.selectedRows
        if rows.count == 1, let r = rows.first {
            VStack(alignment: .leading, spacing: 12) {
                previewView
                HStack(spacing: 10) {
                    Image(nsImage: Icons.icon(for: r)).resizable().frame(width: 40, height: 40)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(r.name).font(.headline).lineLimit(2).textSelection(.enabled)
                        Text(r.kind).font(.caption).foregroundStyle(.secondary)
                    }
                }
                fields([
                    r.isDir && r.size == 0 ? nil : ("Size", Fmt.bytes(r.size)),
                    r.hidePacked || r.packed == 0 ? nil : ("Packed", Fmt.bytes(r.packed)),
                    r.ratio.isEmpty ? nil : ("Ratio", r.ratio),
                    r.mtime.isEmpty ? nil : ("Modified", r.mtime),
                    r.crc.isEmpty ? nil : ("CRC32", r.crc),
                    r.encrypted ? ("Encrypted", "Yes") : nil,
                ])
                if !r.isDir {
                    HStack {
                        Button("Quick Look") { model.quickLookSelected() }
                        Button("Checksums…") { model.calculateHashes() }
                    }
                    .controlSize(.small).disabled(model.busy)
                }
            }
        } else if rows.count > 1 {
            VStack(alignment: .leading, spacing: 6) {
                Text("\(rows.count) items selected").font(.headline)
                Text(Fmt.bytes(rows.reduce(0) { $0 + $1.size })).font(.callout).foregroundStyle(.secondary)
            }
        } else {
            Text("Select a file to preview it and see its details.").font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var previewView: some View {
        switch preview.state {
        case .none:
            EmptyView()
        case .loading:
            ProgressView().controlSize(.small)
                .frame(maxWidth: .infinity, minHeight: 90)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.04)))
        case .image(let img):
            Image(nsImage: img).resizable().scaledToFit()
                .frame(maxWidth: .infinity, maxHeight: 260)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.12), lineWidth: 1))
                .onTapGesture(count: 2) { model.quickLookSelected() }
                .help("Double-click for a larger preview")
                .accessibilityLabel("Preview")
        case .text(let s, let truncated):
            VStack(alignment: .leading, spacing: 4) {
                Text(s).font(.system(size: 10.5, design: .monospaced)).lineLimit(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                if truncated { Text("…").font(.caption).foregroundStyle(.secondary) }
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
            .accessibilityLabel("Text preview")
        case .notice(let msg):
            Text(msg).font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: the archive

    private func archive(_ i: ArchiveInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Archive").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
            fields([
                ("Format", i.formatName),
                ("Size", Fmt.bytes(i.fileSize)),
                ("Contents", "\(i.fileCount) file\(i.fileCount == 1 ? "" : "s"), \(i.folderCount) folder\(i.folderCount == 1 ? "" : "s")"),
                ("Unpacked", Fmt.bytes(i.totalUncompressed)),
                ("Ratio", i.compressionRatio),
                ("Solid", i.isSolid ? "Yes" : "No"),
                ("Encryption", i.encryptionDetails),
            ])
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(i.path, forType: .string)
            }
            .controlSize(.small)
            if let c = i.comment, !c.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Comment").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                    Text(c).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.05)))
                }
            }
        }
    }

    private func fields(_ items: [(String, String)?]) -> some View {
        Grid(alignment: .topLeading, horizontalSpacing: 12, verticalSpacing: 6) {
            ForEach(Array(items.compactMap { $0 }.enumerated()), id: \.offset) { _, kv in
                GridRow {
                    Text(kv.0).foregroundStyle(.secondary)
                    Text(kv.1).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .font(.callout)
    }
}
