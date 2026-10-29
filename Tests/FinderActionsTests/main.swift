import AppKit
import Foundation

// Checks for the Finder integration: the Quick Action workflow files really run in macOS's own Automator runner and hand over
// the selected paths, and archivex:// links are accepted only from fresh temporary list files.
//   swiftc -O -swift-version 5 $(ls Sources/*.swift | grep -v App.swift) Sources/Core/*.swift Tests/FinderActionsTests/main.swift -o /tmp/FinderActionsTests
//   /tmp/FinderActionsTests <work-dir>

setvbuf(stdout, nil, _IOLBF, 0)
_ = NSApplication.shared          // the code under test activates the app, which needs an NSApplication
var pass = 0, fail = 0
func check(_ n: String, _ ok: Bool, _ note: String = "") { if ok { pass += 1; print("PASS", n) } else { fail += 1; print("FAIL", n, note) } }
let fm = FileManager.default
let work = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("fa-\(Int(Date().timeIntervalSince1970))")
try! fm.createDirectory(at: work, withIntermediateDirectories: true)

@MainActor func run() async {
    // 1. a generated workflow executes and receives the file paths as arguments
    let out = work.appendingPathComponent("args.txt")
    let wf = work.appendingPathComponent("Test Action.workflow")
    try! fm.createDirectory(at: wf.appendingPathComponent("Contents"), withIntermediateDirectories: true)
    let p = FinderActions.workflowPlists(title: "Test Action", script: "printf '%s\\n' \"$@\" > '\(out.path)'")
    try! p.info.write(to: wf.appendingPathComponent("Contents/Info.plist"))
    try! p.document.write(to: wf.appendingPathComponent("Contents/document.wflow"))
    let a = work.appendingPathComponent("one file.txt"), b = work.appendingPathComponent("résumé ✓.txt")
    try! "1".write(to: a, atomically: true, encoding: .utf8); try! "2".write(to: b, atomically: true, encoding: .utf8)
    func runAutomator(_ file: URL) -> (status: Int32, args: String) {
        try? fm.removeItem(at: out)
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: "/usr/bin/automator")
        proc.arguments = ["-i", file.path, wf.path]          // the command-line runner takes one input per run
        proc.standardOutput = FileHandle.nullDevice; proc.standardError = FileHandle.nullDevice
        try? proc.run(); proc.waitUntilExit()
        return (proc.terminationStatus, (try? String(contentsOf: out)) ?? "")
    }
    let r1 = runAutomator(a), r2 = runAutomator(b)
    check("Automator runs the generated Quick Action", r1.status == 0 && r2.status == 0, "exit \(r1.status) \(r2.status)")
    check("the shell script receives the selected path (spaces intact)", r1.args.trimmingCharacters(in: .newlines) == a.path, r1.args)
    check("the shell script receives the selected path (Unicode intact)", r2.args.trimmingCharacters(in: .newlines) == b.path, r2.args)
    let info = try! PropertyListSerialization.propertyList(from: p.info, format: nil) as! [String: Any]
    let svc = (info["NSServices"] as! [[String: Any]])[0]
    check("the Quick Action is offered for files in Finder", (svc["NSRequiredContext"] as? [String: String])?["NSApplicationIdentifier"] == "com.apple.finder"
          && (svc["NSSendFileTypes"] as? [String]) == ["public.item"] && ((svc["NSMenuItem"] as? [String: String])?["default"] == "Test Action"))
    check("the script hands over a list file through an archivex:// link", FinderActions.script(for: .compress).contains("archivex://compress?list=$f"))

    // 2. archivex:// links
    let model = ArchiveModel()
    FinderActions.shared.attach(model)
    func list(_ lines: [URL], name: String = "archivex.test", age: TimeInterval = 0) -> URL {
        let f = fm.temporaryDirectory.appendingPathComponent("\(name).\(UUID().uuidString.prefix(6))")
        try! lines.map(\.path).joined(separator: "\n").write(to: f, atomically: true, encoding: .utf8)
        if age > 0 { try! fm.setAttributes([.creationDate: Date().addingTimeInterval(-age)], ofItemAtPath: f.path) }
        return f
    }
    func link(_ action: String, _ l: URL) -> URL { URL(string: "archivex://\(action)?list=\(l.path)")! }

    FinderActions.shared.handle(link: link("compress", list([a, b])))
    try? await Task.sleep(nanoseconds: 200_000_000)
    check("a fresh list opens the Create Archive sheet with those files", model.addDraft?.files.count == 2, "\(String(describing: model.addDraft?.files))")
    model.addDraft = nil

    let hosts = URL(fileURLWithPath: "/etc/hosts")
    FinderActions.shared.handle(link: link("compress", hosts))
    check("a link pointing at a file outside the temporary folder is ignored", model.addDraft == nil)

    FinderActions.shared.handle(link: link("compress", list([a], age: 600)))
    check("a stale list file is ignored", model.addDraft == nil)

    let l3 = list([a])
    FinderActions.shared.handle(link: link("compress", l3))
    model.addDraft = nil
    check("a list is deleted after it is read", !fm.fileExists(atPath: l3.path))

    FinderActions.shared.handle(link: URL(string: "archivex://format-everything?list=/tmp/x")!)
    check("unknown actions are ignored", model.addDraft == nil)

    // an extract link must ask before it touches the disk
    let zip = work.appendingPathComponent("t.zip")
    let proc2 = Process(); proc2.executableURL = URL(fileURLWithPath: "/usr/bin/zip"); proc2.arguments = ["-q", zip.path, "one file.txt"]; proc2.currentDirectoryURL = work
    try? proc2.run(); proc2.waitUntilExit()
    FinderActions.shared.handle(link: link("extract", list([zip])))
    check("an extract link asks for confirmation instead of extracting at once", model.alert?.actionTitle == "Extract" && !fm.fileExists(atPath: work.appendingPathComponent("t").path))
    model.alert?.action?()
    try? await Task.sleep(nanoseconds: 2_500_000_000)
    check("confirming extracts the archive into a folder next to it", fm.fileExists(atPath: work.appendingPathComponent("t/one file.txt").path))

    print("\nRESULT: \(pass) passed, \(fail) failed")
    exit(fail == 0 ? 0 : 1)
}
Task { @MainActor in await run() }
RunLoop.main.run()
