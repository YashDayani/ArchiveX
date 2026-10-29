import AppKit
import SwiftUI

// Finder integration: "Compress with ArchiveX", "Extract with ArchiveX" and "Test with ArchiveX" in Finder's right-click
// menu. Two routes lead to the same code:
//   • macOS Services declared in Info.plist (Finder → right-click → Services), no setup needed;
//   • Quick Actions (Finder → right-click → Quick Actions), small workflows that the app installs on request into
//     ~/Library/Services. They hand the selected files to the app through an archivex:// link.

enum FinderAction: String, CaseIterable {
    case compress, extract, test

    var title: String {
        switch self {
        case .compress: return "Compress with ArchiveX"
        case .extract: return "Extract with ArchiveX"
        case .test: return "Test with ArchiveX"
        }
    }
}

@MainActor
final class FinderActions {
    static let shared = FinderActions()
    weak var model: ArchiveModel?
    private var pending: [(FinderAction, [URL], Bool)] = []
    let servicesProvider = ServicesProvider()

    /// The model registers itself when the window appears; anything that arrived earlier (the app was launched by the
    /// action) runs now.
    func attach(_ model: ArchiveModel) {
        self.model = model
        let queued = pending
        pending = []
        for (a, urls, confirm) in queued { run(a, urls, confirmFirst: confirm) }
    }

    func run(_ action: FinderAction, _ urls: [URL], confirmFirst: Bool = false) {
        guard let model else { pending.append((action, urls, confirmFirst)); return }
        let files = urls.filter { FileManager.default.fileExists(atPath: $0.path) }
        guard !files.isEmpty else { return }
        NSApp.activate(ignoringOtherApps: true)
        switch action {
        case .compress:
            model.prepareAdd(files: files)
        case .extract:
            let archives = files.filter { AXCore.handles($0) }
            guard !archives.isEmpty else {
                model.alert = AlertInfo(title: "Nothing to extract", message: "None of the selected items is an archive ArchiveX can open.")
                return
            }
            let go = { Task { await model.extractArchivesNextToOriginals(archives) } }
            if confirmFirst {
                model.alert = AlertInfo(title: "Extract \(archives.count) archive\(archives.count == 1 ? "" : "s")?",
                                        message: "Each one is extracted into a folder next to it.",
                                        actionTitle: "Extract", action: { _ = go() })
            } else { _ = go() }
        case .test:
            guard let first = files.first(where: { AXCore.handles($0) }) else {
                model.alert = AlertInfo(title: "Nothing to test", message: "None of the selected items is an archive ArchiveX can open.")
                return
            }
            Task { await model.openAndTest(first) }
        }
    }

    // MARK: archivex:// links (used by the Quick Actions)

    /// archivex://compress?list=/path/to/file — the file holds one path per line. The list must be a fresh file of this user's
    /// in the temporary folder, so a link on a web page cannot point the app at arbitrary lists.
    func handle(link url: URL) {
        guard url.scheme == "archivex", let action = FinderAction(rawValue: url.host ?? ""),
              let list = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "list" })?.value else { return }
        let listURL = URL(fileURLWithPath: list)
        let tmp = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().path + "/"
        let real = listURL.resolvingSymlinksInPath()
        guard real.path.hasPrefix(tmp) || real.path.hasPrefix("/private/tmp/") || real.path.hasPrefix("/tmp/"),
              let attrs = try? FileManager.default.attributesOfItem(atPath: real.path),
              (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let made = attrs[.creationDate] as? Date, Date().timeIntervalSince(made) < 120,
              let text = try? String(contentsOf: real, encoding: .utf8) else { return }
        try? FileManager.default.removeItem(at: real)
        let urls = text.split(separator: "\n").map { URL(fileURLWithPath: String($0)) }
        run(action, urls, confirmFirst: action == .extract)
    }

    // MARK: Quick Action workflows

    static var servicesFolder: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Services")
    }
    static func workflowURL(_ a: FinderAction) -> URL { servicesFolder.appendingPathComponent("\(a.title).workflow") }
    static var quickActionsInstalled: Bool { FinderAction.allCases.allSatisfy { FileManager.default.fileExists(atPath: workflowURL($0).path) } }

    /// The shell script a Quick Action runs: it writes the selected paths to a temporary list and opens an archivex:// link.
    static func script(for a: FinderAction) -> String {
        """
        f="$(mktemp "${TMPDIR:-/tmp}/archivex.XXXXXX")"
        printf '%s\\n' "$@" > "$f"
        open "archivex://\(a.rawValue)?list=$f"
        """
    }

    /// The two property lists that make up an Automator "Quick Action" workflow.
    nonisolated static func workflowPlists(title: String, script: String) -> (info: Data, document: Data) {
        let uuid = { UUID().uuidString }
        let info: [String: Any] = [
            "NSServices": [[
                "NSBackgroundColorName": "background",
                "NSIconName": "NSActionTemplate",
                "NSMenuItem": ["default": title],
                "NSMessage": "runWorkflowAsService",
                "NSRequiredContext": ["NSApplicationIdentifier": "com.apple.finder"],
                "NSSendFileTypes": ["public.item"],
            ] as [String: Any]]
        ]
        let action: [String: Any] = [
            "AMAccepts": ["Container": "List", "Optional": true, "Types": ["com.apple.cocoa.string"]] as [String: Any],
            "AMActionVersion": "2.0.3",
            "AMApplication": ["Automator"],
            "AMParameterProperties": ["COMMAND_STRING": [String: Any](), "CheckedForUserDefaultShell": [String: Any](), "inputMethod": [String: Any](),
                                      "shell": [String: Any](), "source": [String: Any]()],
            "AMProvides": ["Container": "List", "Types": ["com.apple.cocoa.string"]] as [String: Any],
            "ActionBundlePath": "/System/Library/Automator/Run Shell Script.action",
            "ActionName": "Run Shell Script",
            "ActionParameters": ["COMMAND_STRING": script, "CheckedForUserDefaultShell": true, "inputMethod": 1, "shell": "/bin/zsh", "source": ""] as [String: Any],
            "BundleIdentifier": "com.apple.RunShellScript",
            "CFBundleVersion": "2.0.3",
            "CanShowSelectedItemsWhenRun": false,
            "CanShowWhenRun": true,
            "Category": ["AMCategoryUtilities"],
            "Class Name": "RunShellScriptAction",
            "InputUUID": uuid(),
            "Keywords": ["Shell", "Script", "Command", "Run", "Unix"],
            "OutputUUID": uuid(),
            "UUID": uuid(),
            "UnlocalizedApplications": ["Automator"],
            "arguments": [String: Any](),
            "isViewVisible": 1,
            "location": "309.000000:253.000000",
            "nibPath": "/System/Library/Automator/Run Shell Script.action/Contents/Resources/Base.lproj/main.nib",
        ]
        let doc: [String: Any] = [
            "AMApplicationBuild": "523",
            "AMApplicationVersion": "2.10",
            "AMDocumentVersion": "2",
            "actions": [["action": action] as [String: Any]],
            "connectors": [String: Any](),
            "workflowMetaData": [
                "applicationBundleIDsByPath": [String: Any](),
                "applicationPaths": [String](),
                "inputTypeIdentifier": "com.apple.Automator.fileSystemObject",
                "outputTypeIdentifier": "com.apple.Automator.nothing",
                "presentationMode": 15,
                "processesInput": 0,
                "serviceInputTypeIdentifier": "com.apple.Automator.fileSystemObject",
                "serviceOutputTypeIdentifier": "com.apple.Automator.nothing",
                "serviceProcessesInput": 0,
                "systemImageName": "NSActionTemplate",
                "useAutomaticInputType": 0,
                "workflowTypeIdentifier": "com.apple.Automator.servicesMenu",
            ] as [String: Any],
        ]
        let enc = { (d: [String: Any]) in try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) }
        return (enc(info), enc(doc))
    }

    /// Writes the three workflows into ~/Library/Services and asks macOS to refresh its menus.
    static func installQuickActions() throws {
        let fm = FileManager.default
        for a in FinderAction.allCases {
            let wf = workflowURL(a)
            try? fm.removeItem(at: wf)
            try fm.createDirectory(at: wf.appendingPathComponent("Contents"), withIntermediateDirectories: true)
            let p = workflowPlists(title: a.title, script: script(for: a))
            try p.info.write(to: wf.appendingPathComponent("Contents/Info.plist"))
            try p.document.write(to: wf.appendingPathComponent("Contents/document.wflow"))
        }
        NSUpdateDynamicServices()
    }

    static func removeQuickActions() {
        for a in FinderAction.allCases { try? FileManager.default.removeItem(at: workflowURL(a)) }
        NSUpdateDynamicServices()
    }
}

/// Receiver for the Services declared in Info.plist (NSMessage names are the method names below).
final class ServicesProvider: NSObject {
    private func urls(_ pboard: NSPasteboard) -> [URL] {
        (pboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL]) ?? []
    }
    @objc func compressFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        let u = urls(pboard); Task { @MainActor in FinderActions.shared.run(.compress, u) }
    }
    @objc func extractFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        let u = urls(pboard); Task { @MainActor in FinderActions.shared.run(.extract, u) }
    }
    @objc func testFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        let u = urls(pboard); Task { @MainActor in FinderActions.shared.run(.test, u) }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    @MainActor func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.servicesProvider = FinderActions.shared.servicesProvider
        NSUpdateDynamicServices()
    }
}

extension ArchiveModel {
    /// Opens each archive in turn and extracts it into a folder next to it.
    func extractArchivesNextToOriginals(_ urls: [URL]) async {
        for u in urls {
            open(u)
            await waitUntilIdle()
            guard archiveURL == u else { continue }           // it did not open (password prompt, error alert)
            quickExtract(toSubfolder: true)
            await waitUntilIdle()
        }
    }

    func openAndTest(_ url: URL) async {
        open(url)
        await waitUntilIdle()
        guard archiveURL == url else { return }
        test()
    }

    private func waitUntilIdle() async {
        try? await Task.sleep(nanoseconds: 250_000_000)
        while busy { try? await Task.sleep(nanoseconds: 150_000_000) }
        try? await Task.sleep(nanoseconds: 150_000_000)
    }
}
