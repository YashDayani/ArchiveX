import SwiftUI
import UniformTypeIdentifiers

@main
struct ArchiveXApp: App {
    @StateObject private var model = ArchiveModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 760, minHeight: 460)
                .onOpenURL { model.open($0) }
        }
        .defaultSize(width: 980, height: 600)
        .commands { MenuCommands(model: model) }
    }
}

struct MenuCommands: Commands {
    @ObservedObject var model: ArchiveModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Open Archive…") { Panels.openArchive(model) }.keyboardShortcut("o")
            Button("New Archive…") { Panels.newArchive(model) }.keyboardShortcut("n")
            Divider()
            Button("Close Archive") { model.close() }
                .keyboardShortcut("w").disabled(!model.hasArchive)
        }
        CommandMenu("Commands") {
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
