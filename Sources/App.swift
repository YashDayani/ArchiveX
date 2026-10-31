import SwiftUI
import UniformTypeIdentifiers

@main
struct ArchiveXApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            WindowRoot()
        }
        .defaultSize(width: 1080, height: 640)
        .commands { MenuCommands() }
        Settings { SettingsView() }
    }
}

/// One archive per window or tab: each gets its own model, so a new tab starts on the welcome screen.
struct WindowRoot: View {
    @StateObject private var model = ArchiveModel()

    var body: some View {
        ContentView()
            .environmentObject(model)
            .focusedSceneObject(model)
            .background(WindowTracker(model: model))
            // Wide enough for all seven table columns next to the 300 pt inspector, and tall enough for the welcome screen.
            .frame(minWidth: 1080, minHeight: 600)
            .onOpenURL { url in
                if url.scheme == "archivex" { FinderActions.shared.handle(link: url) } else { model.open(url) }
            }
    }
}

/// Tells the app which window's model is the active one (key handling and Finder actions follow it).
struct WindowTracker: NSViewRepresentable {
    let model: ArchiveModel

    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        let c = context.coordinator
        DispatchQueue.main.async { [weak v] in
            guard let w = v?.window else { return }
            c.observe(w, model)
        }
        return v
    }
    func updateNSView(_ nsView: NSView, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator() }

    @MainActor final class Coordinator {
        private var token: NSObjectProtocol?
        func observe(_ window: NSWindow, _ model: ArchiveModel) {
            if window.isKeyWindow { ArchiveModel.active = model; FinderActions.shared.attach(model) }
            token = NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main) { _ in
                MainActor.assumeIsolated { ArchiveModel.active = model; FinderActions.shared.attach(model) }
            }
        }
        deinit { if let token { NotificationCenter.default.removeObserver(token) } }
    }
}

struct MenuCommands: Commands {
    @AppStorage(Updater.autoCheckKey) private var autoCheckUpdates = true
    @FocusedObject private var focused: ArchiveModel?

    var body: some Commands {
        let model = focused ?? ArchiveModel.placeholder
        CommandGroup(replacing: .appInfo) {
            Button("About ArchiveX") {
                AboutPanel.show()
            }
        }
        CommandGroup(replacing: .newItem) {
            Button("Open Archive…") { Panels.openArchive(model) }.keyboardShortcut("o")
            Button("New Archive…") { Panels.newArchive(model) }.keyboardShortcut("n")
            Button("Join Split Archive…") { Panels.joinSplit(model) }
            Divider()
            Button("Close Archive") { model.close() }
                .keyboardShortcut("w").disabled(!model.hasArchive)
        }
        CommandGroup(replacing: .pasteboard) {
            Button("Find in Archive…") { model.focusSearch() }.keyboardShortcut("f")
            Button("Select All") { model.selectAll() }.keyboardShortcut("a").disabled(!model.hasArchive)
            Button("Copy") { model.copySelection() }.keyboardShortcut("c").disabled(model.selection.isEmpty)
        }
        CommandGroup(replacing: .help) {
            Button("Features & Shortcuts") { NSWorkspace.shared.open(Feedback.featuresPage) }
            Divider()
            Button("Report a Bug…") { Feedback.open(.bug) }
            Button("Request a Feature…") { Feedback.open(.feature) }
            Divider()
            Button("ArchiveX on GitHub") { NSWorkspace.shared.open(Feedback.repoPage) }
            Button("Known Issues") { NSWorkspace.shared.open(Feedback.issuesPage) }
        }
        CommandGroup(after: .appInfo) {
            Button("Check for Updates…") { Updater.shared.checkNow() }
            Toggle("Check for Updates Automatically", isOn: $autoCheckUpdates)
            Divider()
            if FinderActions.quickActionsInstalled {
                Button("Remove Finder Quick Actions") {
                    FinderActions.removeQuickActions()
                    model.alert = AlertInfo(title: "Quick Actions removed", message: "“Compress / Extract / Test with ArchiveX” are gone from Finder’s Quick Actions menu.")
                }
            } else {
                Button("Install Finder Quick Actions…") {
                    do {
                        try FinderActions.installQuickActions()
                        model.alert = AlertInfo(title: "Quick Actions installed",
                                                message: "Right-click files in Finder → Quick Actions → Compress / Extract / Test with ArchiveX. If they do not show up yet, open System Settings → Privacy & Security → Extensions → Finder and make sure they are ticked.")
                    } catch { model.alert = AlertInfo(title: "Couldn’t install Quick Actions", message: error.localizedDescription) }
                }
            }
        }
        CommandMenu("Commands") {
            Button("Enclosing Folder") { model.goUp() }
                .keyboardShortcut(.upArrow, modifiers: .command).disabled(model.currentDir.isEmpty || !model.searchQuery.isEmpty)
            Button("Open Selected") { model.openSelected() }
                .keyboardShortcut(.downArrow, modifiers: .command).disabled(model.selectedRows.count != 1)
            Divider()
            Button(model.showInspector ? "Hide Inspector" : "Show Inspector") { model.showInspector.toggle() }
                .keyboardShortcut("i").disabled(!model.hasArchive)
            Button("Calculate Checksums…") { model.calculateHashes() }
                .keyboardShortcut("k", modifiers: [.command, .shift]).disabled(!model.hasArchive)
            Divider()
            Button("Quick Look (Space)") { model.quickLookSelected() }
                .disabled(model.selection.isEmpty)
            Button("View") {
                if let r = model.selectedRows.first(where: { !$0.isDir }) { model.view(r) }
            }
            .keyboardShortcut("v", modifiers: [.command, .shift]).disabled(model.selectedRows.allSatisfy(\.isDir))
            Divider()
            Button("Add Files to Archive…") { Panels.addToOpen(model) }
                .keyboardShortcut("a", modifiers: [.command, .shift]).disabled(!model.hasArchive)
            Button("Extract To…") { model.prepareExtract() }
                .keyboardShortcut("e").disabled(!model.hasArchive)
            Button("Extract Here") { model.quickExtract(toSubfolder: false) }
                .keyboardShortcut("e", modifiers: [.command, .shift]).disabled(!model.hasArchive)
            Button("Extract to Subfolder") { model.quickExtract(toSubfolder: true) }
                .keyboardShortcut("e", modifiers: [.command, .option]).disabled(!model.hasArchive)
            Divider()
            Button("Test Archive") { model.test() }
                .keyboardShortcut("t").disabled(!model.hasArchive)
            Button("Delete Selected from Archive (Delete)") { model.confirmDelete() }
                .keyboardShortcut(.delete, modifiers: .command).disabled(model.selection.isEmpty)
        }
    }
}

enum AboutPanel {
    @MainActor
    static func show() {
        let pStyle = NSMutableParagraphStyle()
        pStyle.alignment = .center

        let normalAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .foregroundColor: NSColor.secondaryLabelColor,
            .paragraphStyle: pStyle
        ]

        let linkAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .link: URL(string: "https://github.com/YashDayani")!,
            .paragraphStyle: pStyle
        ]

        let credits = NSMutableAttributedString()
        credits.append(NSAttributedString(string: "Created by ", attributes: normalAttrs))
        credits.append(NSAttributedString(string: "Yash Dayani", attributes: linkAttrs))

        NSApp.orderFrontStandardAboutPanel(options: [
            .credits: credits
        ])
    }
}
