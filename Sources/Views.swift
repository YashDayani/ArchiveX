import SwiftUI
import QuickLook
import UniformTypeIdentifiers

struct ContentView: View {
    @ObservedObject private var updater = Updater.shared
    @EnvironmentObject var model: ArchiveModel
    @State private var dropTargeted = false

    var body: some View {
        VStack(spacing: 0) {
            ButtonBar()
            Divider()
            HStack(spacing: 0) {
                VStack(spacing: 0) {
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
                if model.hasArchive && model.showInspector {
                    Divider()
                    InspectorPanel().frame(width: 300)
                }
            }
        }
        .navigationTitle(model.title)
        .overlay { if model.busy { BusyOverlay() } }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted, perform: handleDrop)
        .quickLookPreview($model.quickLookURL)
        .onAppear {
            ArchiveModel.cleanOldScratch()
            KeyEvents.install(model)
            FinderActions.shared.attach(model)
            Updater.shared.checkOnLaunch()
        }
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
        .sheet(isPresented: $updater.sheetVisible) { UpdateSheet() }
        .sheet(isPresented: Binding(get: { model.hashResults != nil }, set: { if !$0 { model.hashResults = nil } })) {
            if let results = model.hashResults { HashSheet(results: results) }
        }
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
            BarButton("Inspector", "sidebar.trailing", enabled: model.hasArchive) { model.showInspector.toggle() }
            BarButton("Hashes", "number.square", enabled: model.hasArchive) { model.calculateHashes() }
            BarButton("Quick Look", "eye.circle", enabled: model.selectedRows.contains { !$0.isDir }) {
                model.quickLookSelected()
            }
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
        .accessibilityLabel(title)
    }
}

// MARK: - Path bar

struct PathBar: View {
    @EnvironmentObject var model: ArchiveModel
    @FocusState private var isSearchFocused: Bool

    var body: some View {
        HStack(spacing: 8) {
            Button { model.goUp() } label: { Image(systemName: "arrow.turn.left.up") }
                .disabled(model.currentDir.isEmpty || !model.searchQuery.isEmpty).help("Up one level (⌘↑)")
                .accessibilityLabel("Up one level")
            Image(systemName: "doc.zipper").foregroundStyle(.secondary)
            Text(model.archiveURL?.lastPathComponent ?? "")
                .fontWeight(.medium)
            if !model.currentDir.isEmpty && model.searchQuery.isEmpty {
                Text("›").foregroundStyle(.secondary)
                Text(model.currentDir.replacingOccurrences(of: "/", with: "  ›  "))
            }
            if !model.searchQuery.isEmpty {
                Text("›").foregroundStyle(.secondary)
                Text("Search: “\(model.searchQuery)” (\(model.visibleRows.count) found)")
                    .foregroundStyle(.secondary)
            }
            Spacer()

            // Search bar
            HStack(spacing: 4) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                TextField("Search (⌘F)…", text: $model.searchQuery)
                    .textFieldStyle(.plain)
                    .font(.system(size: 11))
                    .frame(width: 120)
                    .focused($isSearchFocused)
                    .onChange(of: model.searchFieldFocused) { focused in
                        if focused {
                            isSearchFocused = true
                            model.searchFieldFocused = false
                        }
                    }
                if !model.searchQuery.isEmpty {
                    Button { model.searchQuery = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.06)))

            if !model.details.isEmpty && model.searchQuery.isEmpty {
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
                    if r.encrypted { Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel("Encrypted") }
                }
                .accessibilityElement(children: .combine)
                .contentShape(Rectangle())
                .onDrag { model.fileProvider(for: r) }
            }.width(min: 150, ideal: 190)
            TableColumn("Size", value: \.size) { Text($0.sizeText).monospacedDigit() }
                .width(min: 60, ideal: 70)
            TableColumn("Packed", value: \.packed) { Text($0.packedText).monospacedDigit() }
                .width(min: 60, ideal: 70)
            TableColumn("Ratio", value: \.ratio) { Text($0.ratio).monospacedDigit() }
                .width(min: 45, ideal: 50)
            TableColumn("Type", value: \.kind) { Text($0.kind) }
                .width(min: 70, ideal: 80)
            TableColumn("Modified", value: \.mtime) { Text($0.mtime).monospacedDigit() }
                .width(min: 115, ideal: 125)
            TableColumn("CRC32", value: \.crc) { Text($0.crc).font(.system(.body, design: .monospaced)) }
                .width(min: 60, ideal: 70)
        }
        // The standard Copy command (⌘C) copies the selected items while the table has focus; in a text field it still copies text.
        .onCopyCommand { model.copySelection(); return [] }
        .contextMenu(forSelectionType: String.self) { ids in
            if !ids.isEmpty {
                if let r = model.visibleRows.first(where: { ids.contains($0.id) }), !r.isDir {
                    Button("Quick Look (Space)") { model.quickLookSelected() }
                    Button("View") { model.view(r) }
                    Divider()
                }
                Button("Calculate Checksums…") { model.calculateHashes() }
                Button("Show in Inspector (⌘I)") { model.showInspector = true }
                Button("Copy (⌘C)") { model.copySelection() }
                Button("Extract Selected To…") { model.prepareExtract() }
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
    @State private var recents: [RecentArchive] = []

    var body: some View {
        // Scrolls when the window is too short for everything, and stays centred when there is room.
        GeometryReader { geo in
            ScrollView(showsIndicators: false) {
                content.frame(minHeight: geo.size.height)
            }
        }
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
        .onAppear { recents = Recents.current }
    }

    private var content: some View {
        VStack(spacing: 14) {
            Spacer(minLength: 12)
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
            if !recents.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Recent").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                        Spacer()
                        Button("Clear") { NSDocumentController.shared.clearRecentDocuments(nil); recents = [] }
                            .buttonStyle(.link).font(.caption)
                    }
                    VStack(spacing: 8) {
                        ForEach(recents) { RecentCard(item: $0) }
                    }
                }
                .frame(maxWidth: 400)
                .padding(.top, 20)
            }
            Spacer(minLength: 12)
        }
        .padding(.horizontal, 40)
        .frame(maxWidth: .infinity)
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
                    ProgressView(value: p).frame(width: 280)
                        .accessibilityLabel(model.busyLabel).accessibilityValue("\(Int(p * 100)) percent")
                    Text("\(Int(p * 100))%").font(.callout.monospacedDigit())
                } else {
                    ProgressView().controlSize(.large).accessibilityLabel(model.busyLabel)
                }
                if let detail = model.progressDetail {
                    Text(detail).font(.caption).foregroundStyle(.secondary)
                }
                Button("Cancel") { model.cancel() }.keyboardShortcut(.cancelAction)
            }
            .padding(24)
            .frame(minWidth: 320)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .shadow(radius: 12)
        }
    }
}

enum Panels {
    @MainActor static func openArchive(_ model: ArchiveModel) {
        let p = NSOpenPanel()
        p.allowsMultipleSelection = false
        p.canChooseDirectories = false
        p.message = "Choose an archive (RAR, 7z, ZIP, TAR, ISO, …)"
        if p.runModal() == .OK, let u = p.url { model.open(u) }
    }

    @MainActor static func newArchive(_ model: ArchiveModel) {
        let p = NSOpenPanel()
        p.allowsMultipleSelection = true
        p.canChooseDirectories = true
        p.canChooseFiles = true
        p.prompt = "Add"
        p.message = "Choose files and folders to compress"
        if p.runModal() == .OK, !p.urls.isEmpty { model.prepareAdd(files: p.urls) }
    }

    @MainActor static func addToOpen(_ model: ArchiveModel) {
        let p = NSOpenPanel()
        p.allowsMultipleSelection = true
        p.canChooseDirectories = true
        p.prompt = "Add"
        p.message = "Choose files to add to “\(model.title)”"
        if p.runModal() == .OK, !p.urls.isEmpty { model.prepareAdd(files: p.urls, toOpenArchive: true) }
    }

    @MainActor static func chooseFolder(start: String) -> String? {
        let p = NSOpenPanel()
        p.canChooseFiles = false
        p.canChooseDirectories = true
        p.canCreateDirectories = true
        p.prompt = "Select"
        p.directoryURL = URL(fileURLWithPath: start).deletingLastPathComponent()
        return p.runModal() == .OK ? p.url?.path : nil
    }

    @MainActor static func chooseSaveLocation(current: String) -> String? {
        let p = NSSavePanel()
        p.nameFieldStringValue = (current as NSString).lastPathComponent
        p.allowsOtherFileTypes = true
        p.directoryURL = URL(fileURLWithPath: current).deletingLastPathComponent()
        p.canCreateDirectories = true
        return p.runModal() == .OK ? p.url?.path : nil
    }
}


// MARK: - Space and Delete

/// Space (Quick Look) and Delete work on the file table, but must never steal the key from a text field (the search box,
/// the password and path fields in sheets) or from a sheet, alert or the Quick Look panel itself. Menu shortcuts without a
/// modifier cannot make that distinction, so these two keys are handled here, only when no text is being edited.
@MainActor
enum KeyEvents {
    private static var monitor: Any?

    static func install(_ model: ArchiveModel) {
        guard monitor == nil else { return }
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            guard event.modifierFlags.intersection([.command, .control, .option]).isEmpty,
                  let w = NSApp.keyWindow, !(w is NSPanel), w.attachedSheet == nil,
                  !(w.firstResponder is NSTextView), !(w.firstResponder is NSTextField),
                  model.hasArchive, !model.busy else { return event }
            switch event.keyCode {
            case 49 where !model.selection.isEmpty: model.quickLookSelected(); return nil      // space
            case 51, 117 where !model.selection.isEmpty: model.confirmDelete(); return nil     // delete, forward delete
            case 36, 76 where !model.selection.isEmpty: model.openSelected(); return nil       // return, enter
            case 53 where !model.searchQuery.isEmpty: model.searchQuery = ""; return nil       // escape clears the search
            default:
                // type-to-select: plain letters and digits jump to the matching name
                if let c = event.charactersIgnoringModifiers, c.count == 1, c.first!.isLetter || c.first!.isNumber,
                   model.typeahead(c) { return nil }
                return event
            }
        }
    }
}
