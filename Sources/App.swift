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
            Button("Delete Selected from Archive") { model.confirmDelete() }
                .keyboardShortcut(.delete).disabled(model.selection.isEmpty)
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
