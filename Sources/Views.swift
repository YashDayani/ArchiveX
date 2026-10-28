import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var model: ArchiveModel
    @State private var dropTargeted = false

    var body: some View {
        VStack(spacing: 0) {
            ButtonBar()
            Divider()
            ZStack {
                if model.hasArchive {
                    VStack(spacing: 0) {
                        PathBar()
                        Divider()
                        FileTable()
                    }
                    // Subtle tint, confined to the file list, while something is dragged over it.
                    Rectangle()
                        .fill(Color.accentColor.opacity(dropTargeted ? 0.08 : 0))
                        .allowsHitTesting(false)
                        .animation(.easeOut(duration: 0.15), value: dropTargeted)
                } else {
                    WelcomeView(targeted: dropTargeted)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            StatusBar()
        }
        .navigationTitle(model.title)
        .overlay { if model.busy { BusyOverlay() } }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted, perform: handleDrop)
        .alert(item: $model.alert) { info in
            if let title = info.actionTitle, let action = info.action {
                return Alert(title: Text(info.title), message: Text(info.message),
                             primaryButton: info.isDestructive ? .destructive(Text(title), action: action) : .default(Text(title), action: action),
                             secondaryButton: .cancel())
            }
            return Alert(title: Text(info.title), message: Text(info.message), dismissButton: .default(Text("OK")))
        }
        .sheet(item: $model.addDraft) { AddSheet(draft: $0) }
        .sheet(item: $model.extractDraft) { ExtractSheet(draft: $0) }
        .sheet(isPresented: $model.passwordPrompt) { PasswordSheet() }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        var urls: [URL] = []
        let group = DispatchGroup()
        for p in providers {
            group.enter()
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                if let url { DispatchQueue.main.async { urls.append(url) } }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            guard !urls.isEmpty else { return }
            if urls.count == 1, ArchiveFormat.isArchive(urls[0]) {
                model.open(urls[0])
            } else {
                model.prepareAdd(files: urls, toOpenArchive: false)
            }
        }
        return true
    }
}

// MARK: - WinRAR-style button bar

struct ButtonBar: View {
    @EnvironmentObject var model: ArchiveModel

    var body: some View {
        HStack(spacing: 2) {
            BarButton("Open", "folder") { Panels.openArchive(model) }
            BarButton("New", "archivebox") { Panels.newArchive(model) }
            Divider().frame(height: 34).padding(.horizontal, 4)
            BarButton("Add", "plus.rectangle.on.folder", enabled: model.hasArchive) { Panels.addToOpen(model) }
            BarButton("Extract To", "arrow.down.doc", enabled: model.hasArchive) { model.prepareExtract() }
            BarButton("Test", "checkmark.shield", enabled: model.hasArchive) { model.test() }
            BarButton("View", "eye", enabled: model.selectedRows.contains { !$0.isDir }) {
                if let r = model.selectedRows.first(where: { !$0.isDir }) { model.view(r) }
            }
            BarButton("Delete", "trash", enabled: !model.selection.isEmpty) { model.confirmDelete() }
            Spacer()
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(.bar)
    }
}

struct BarButton: View {
    let title: String, symbol: String, enabled: Bool, action: () -> Void
    init(_ title: String, _ symbol: String, enabled: Bool = true, action: @escaping () -> Void) {
        self.title = title; self.symbol = symbol; self.enabled = enabled; self.action = action
    }
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 3) {
                Image(systemName: symbol).font(.system(size: 20, weight: .regular)).frame(height: 24)
                Text(title).font(.system(size: 11))
            }
            .frame(width: 66, height: 46)
            .background(RoundedRectangle(cornerRadius: 6).fill(hover && enabled ? Color.primary.opacity(0.08) : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.35)
        .onHover { hover = $0 }
        .help(title)
    }
}

// MARK: - Path bar

struct PathBar: View {
    @EnvironmentObject var model: ArchiveModel

    var body: some View {
        HStack(spacing: 8) {
            Button { model.goUp() } label: { Image(systemName: "arrow.turn.left.up") }
                .disabled(model.currentDir.isEmpty).help("Up one level")
            Image(systemName: "doc.zipper").foregroundStyle(.secondary)
            Text(model.archiveURL?.lastPathComponent ?? "")
                .fontWeight(.medium)
            if !model.currentDir.isEmpty {
                Text("›").foregroundStyle(.secondary)
                Text(model.currentDir.replacingOccurrences(of: "/", with: "  ›  "))
            }
            Spacer()
            if !model.details.isEmpty {
                Text(model.details).font(.caption).foregroundStyle(.secondary)
            }
        }
        .lineLimit(1)
        .padding(.horizontal, 10).padding(.vertical, 6)
    }
}

// MARK: - File table

struct FileTable: View {
    @EnvironmentObject var model: ArchiveModel
    @State private var sort = [KeyPathComparator(\Row.name)]

    private var sorted: [Row] {
        let rows = model.visibleRows.sorted(using: sort)
        return rows.filter { $0.isDir } + rows.filter { !$0.isDir }
    }

    var body: some View {
        Table(sorted, selection: $model.selection, sortOrder: $sort) {
            TableColumn("Name", value: \.name) { r in
                HStack(spacing: 6) {
                    Image(nsImage: Icons.icon(for: r)).resizable().frame(width: 18, height: 18)
                    Text(r.name).lineLimit(1)
                    if r.encrypted { Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.secondary) }
                }
            }.width(min: 180, ideal: 300)
            TableColumn("Size", value: \.size) { Text($0.sizeText).monospacedDigit() }
                .width(min: 70, ideal: 90)
            TableColumn("Packed", value: \.packed) { Text($0.packedText).monospacedDigit() }
                .width(min: 70, ideal: 90)
            TableColumn("Ratio", value: \.ratio) { Text($0.ratio).monospacedDigit() }
                .width(min: 50, ideal: 60)
            TableColumn("Type", value: \.kind) { Text($0.kind) }
                .width(min: 80, ideal: 110)
            TableColumn("Modified", value: \.mtime) { Text($0.mtime).monospacedDigit() }
                .width(min: 120, ideal: 140)
            TableColumn("CRC32", value: \.crc) { Text($0.crc).font(.system(.body, design: .monospaced)) }
                .width(min: 70, ideal: 90)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            if !ids.isEmpty {
                Button("Extract Selected To…") { model.prepareExtract() }
                if let r = model.visibleRows.first(where: { ids.contains($0.id) }), !r.isDir {
                    Button("View") { model.view(r) }
                }
                Divider()
                Button("Delete from Archive", role: .destructive) { model.confirmDelete() }
            }
        } primaryAction: { ids in
            if let r = model.visibleRows.first(where: { ids.contains($0.id) }) { model.enter(r) }
        }
    }
}

enum Icons {
    private static var cache: [String: NSImage] = [:]
    @MainActor static func icon(for r: Row) -> NSImage {
        let key = r.isDir ? "/dir" : (r.name as NSString).pathExtension.lowercased()
        if let c = cache[key] { return c }
        let img = r.isDir ? NSWorkspace.shared.icon(for: .folder)
                          : NSWorkspace.shared.icon(for: UTType(filenameExtension: key) ?? .data)
        cache[key] = img
        return img
    }
}

// MARK: - Welcome / status / busy

struct WelcomeView: View {
    @EnvironmentObject var model: ArchiveModel
    @Environment(\.colorScheme) private var scheme
    let targeted: Bool

    private let formats = ["ZIP", "7z", "RAR", "TAR", "GZ", "BZ2", "XZ", "ISO", "CPIO"]

    var body: some View {
        VStack(spacing: 14) {
            logo
                .frame(width: 96, height: 96)
                .scaleEffect(targeted ? 1.08 : 1)
            VStack(spacing: 6) {
                Text(targeted ? "Release to continue" : "Drop an archive here")
                    .font(.title2.weight(.semibold))
                Text(targeted ? "Archives open · other files are compressed"
                              : "to open it — or drop files and folders to compress them")
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 10) {
                Button("Open Archive…") { Panels.openArchive(model) }
                    .buttonStyle(.borderedProminent)
                Button("New Archive…") { Panels.newArchive(model) }
            }
            .controlSize(.large)
            .padding(.top, 2)
            HStack(spacing: 6) {
                ForEach(formats, id: \.self) { f in
                    Text(f)
                        .font(.system(size: 10, weight: .semibold, design: .rounded))
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(Capsule().fill(Color.primary.opacity(0.07)))
                }
                            }
            .foregroundStyle(.secondary)
            .padding(.top, 4)
        }
        .padding(.horizontal, 40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Color.accentColor.opacity(targeted ? 0.10 : 0.0))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(Color.accentColor.opacity(targeted ? 1 : 0),      // only while dragging over
                              style: StrokeStyle(lineWidth: 2.5, dash: [9, 7]))
        )
        .padding(24)
        .animation(.spring(response: 0.3, dampingFraction: 0.75), value: targeted)
    }

    @ViewBuilder private var logo: some View {
        if let url = Bundle.main.url(forResource: "logo", withExtension: "svg"), let img = NSImage(contentsOf: url) {
            Image(nsImage: img).resizable().scaledToFit()
                .colorInvert(if: scheme == .dark)      // the mark is black; flip it on dark backgrounds
        } else {
            Image(systemName: "archivebox.fill").resizable().scaledToFit().foregroundStyle(.tint)
        }
    }
}

extension View {
    @ViewBuilder func colorInvert(if condition: Bool) -> some View {
        if condition { self.colorInvert() } else { self }
    }
}

struct StatusBar: View {
    @EnvironmentObject var model: ArchiveModel

    var body: some View {
        HStack {
            if model.hasArchive {
                let sel = model.selectedRows
                if sel.isEmpty {
                    Text("Total \(model.fileCount) files, \(Fmt.bytes(model.totalSize)) (packed \(Fmt.bytes(model.totalPacked)))")
                } else {
                    let folders = sel.filter { $0.isDir }.count
                    Text("Selected \(sel.count - folders) files, \(folders) folders, \(Fmt.bytes(sel.reduce(0) { $0 + $1.size }))")
                }
            } else {
                Text("Ready")
            }
            Spacer()
        }
        .font(.caption).foregroundStyle(.secondary)
        .padding(.horizontal, 10).padding(.vertical, 4)
        .background(.bar)
    }
}

struct BusyOverlay: View {
    @EnvironmentObject var model: ArchiveModel

    var body: some View {
        ZStack {
            Color.black.opacity(0.15)
            VStack(spacing: 12) {
                Text(model.busyLabel).font(.headline)
                if let p = model.progress {
                    ProgressView(value: p).frame(width: 260)
                    Text("\(Int(p * 100))%").font(.caption).foregroundStyle(.secondary)
                } else {
                    ProgressView().controlSize(.large)
                }
                Button("Cancel") { model.cancel() }
            }
            .padding(24)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .shadow(radius: 12)
        }
    }
}
