import SwiftUI
import UniformTypeIdentifiers

@main
struct ArchiveXApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = ArchiveModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 760, minHeight: 460)
                .onOpenURL { url in
                    if url.scheme == "archivex" { FinderActions.shared.handle(link: url) } else { model.open(url) }
                }
        }
        .defaultSize(width: 980, height: 600)
        .commands { MenuCommands(model: model) }
    }
}

struct MenuCommands: Commands {
    @AppStorage(Updater.autoCheckKey) private var autoCheckUpdates = true
    @ObservedObject var model: ArchiveModel

    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About ArchiveX") {
                AboutPanel.show()
            }
        }
        CommandGroup(replacing: .newItem) {
            Button("Open Archive…") { Panels.openArchive(model) }.keyboardShortcut("o")
            Button("New Archive…") { Panels.newArchive(model) }.keyboardShortcut("n")
            Divider()
            Button("Close Archive") { model.close() }
                .keyboardShortcut("w").disabled(!model.hasArchive)
        }
        CommandGroup(replacing: .pasteboard) {
            Button("Find in Archive…") { model.focusSearch() }.keyboardShortcut("f")
            Button("Select All") { model.selectAll() }.keyboardShortcut("a").disabled(!model.hasArchive)
            Button("Copy") { model.copySelection() }.keyboardShortcut("c").disabled(model.selection.isEmpty)
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
            Button("Get Info") { model.showArchiveInfo() }
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
                .disabled(model.selection.isEmpty)
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
