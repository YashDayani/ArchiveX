import AppKit
import SwiftUI
import UniformTypeIdentifiers

// Headless checks of the window model's Quick Look cache, drag-out provider and search filter.
//   swiftc -O -swift-version 5 $(ls Sources/*.swift | grep -v App.swift) Sources/Core/*.swift Tests/ModelTests/main.swift -o /tmp/ModelTests
//   /tmp/ModelTests <work-dir>     (needs only /usr/bin/zip)

@MainActor func settle(_ m: ArchiveModel) async {
    try? await Task.sleep(nanoseconds: 200_000_000)
    while m.busy { try? await Task.sleep(nanoseconds: 100_000_000) }
    try? await Task.sleep(nanoseconds: 200_000_000)
}
var pass = 0, fail = 0
func check(_ n: String, _ ok: Bool, _ note: String = "") { if ok { pass += 1; print("PASS", n) } else { fail += 1; print("FAIL", n, note) } }

@MainActor func run() async {
    let dir = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("mt-\(Int(Date().timeIntervalSince1970))")
    let fm = FileManager.default
    try! fm.createDirectory(at: dir.appendingPathComponent("a"), withIntermediateDirectories: true)
    try! fm.createDirectory(at: dir.appendingPathComponent("b"), withIntermediateDirectories: true)
    try! "FROM-ARCHIVE-A\n".write(to: dir.appendingPathComponent("a/readme.txt"), atomically: true, encoding: .utf8)
    try! "FROM-ARCHIVE-B\n".write(to: dir.appendingPathComponent("b/readme.txt"), atomically: true, encoding: .utf8)
    try! Data((0..<4000).flatMap { _ in (0..<256).map { UInt8($0) } }).write(to: dir.appendingPathComponent("a/big.bin"))
    for n in ["a", "b"] {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/zip"); p.arguments = ["-qr", "../\(n).zip", "."]
        p.currentDirectoryURL = dir.appendingPathComponent(n); try! p.run(); p.waitUntilExit()
    }
    let m = ArchiveModel()
    m.open(dir.appendingPathComponent("a.zip")); await settle(m)
    check("archive A opened", m.hasArchive)

    // 1. Quick Look: archive A, then archive B with the same inner name must not show A's file
    m.selection = ["readme.txt"]; m.quickLookSelected(); await settle(m)
    let qa = m.quickLookURL.flatMap { try? String(contentsOf: $0) }
    check("quick look shows archive A's file", qa == "FROM-ARCHIVE-A\n", "\(qa ?? "nil")")
    m.quickLookURL = nil
    m.open(dir.appendingPathComponent("b.zip")); await settle(m)
    m.selection = ["readme.txt"]; m.quickLookSelected(); await settle(m)
    let qb = m.quickLookURL.flatMap { try? String(contentsOf: $0) }
    check("quick look in archive B does not reuse archive A's preview", qb == "FROM-ARCHIVE-B\n", "\(qb ?? "nil")")
    m.quickLookURL = nil

    // 2. Drag-out: the provider extracts lazily, off the main thread, when the receiver asks for the file
    m.open(dir.appendingPathComponent("a.zip")); await settle(m)
    let row = m.visibleRows.first { $0.name == "big.bin" }!
    let t0 = Date()
    let provider = m.fileProvider(for: row)
    check("creating the drag provider is instant (no extraction yet)", Date().timeIntervalSince(t0) < 0.05)
    check("provider suggests the file name", provider.suggestedName == "big.bin", "\(provider.suggestedName ?? "nil")")
    let type = (UTType(filenameExtension: "bin") ?? .data).identifier
    let got: Data? = await withCheckedContinuation { cont in
        provider.loadFileRepresentation(forTypeIdentifier: type) { url, err in
            cont.resume(returning: url.flatMap { try? Data(contentsOf: $0) })
        }
    }
    check("the dropped file has the right bytes", got == Data((0..<4000).flatMap { _ in (0..<256).map { UInt8($0) } }), "\(got?.count ?? -1) bytes")
    let folderProvider = m.fileProvider(for: m.visibleRows.first { $0.name == "readme.txt" }!)
    let txt: Data? = await withCheckedContinuation { cont in
        folderProvider.loadFileRepresentation(forTypeIdentifier: UTType.plainText.identifier) { url, _ in cont.resume(returning: url.flatMap { try? Data(contentsOf: $0) }) }
    }
    check("a text file drops with its content", txt == Data("FROM-ARCHIVE-A\n".utf8))

    // 3. Search filter
    m.searchQuery = "readme"
    check("search finds by name", m.visibleRows.map(\.name) == ["readme.txt"], "\(m.visibleRows.map(\.name))")
    m.searchQuery = ".bin"
    check("search by extension", m.visibleRows.map(\.name) == ["big.bin"], "\(m.visibleRows.map(\.name))")
    m.searchQuery = "zzz"
    check("search with no match is empty", m.visibleRows.isEmpty)
    m.searchQuery = ""

    // 3b. type-to-select
    m.selection = []
    check("typing b selects big.bin", m.typeahead("b") && m.selection == ["big.bin"], "\(m.selection)")
    check("a letter that matches nothing does not move the selection", !m.typeahead("z") && m.selection == ["big.bin"], "\(m.selection)")
    try? await Task.sleep(nanoseconds: 1_100_000_000)
    check("after a pause typing starts a new word", m.typeahead("r") && m.selection == ["readme.txt"], "\(m.selection)")

    // 3c. time remaining
    check("no estimate before enough progress", JobTime.remaining(elapsed: 1, fraction: 0.5) == nil && JobTime.remaining(elapsed: 10, fraction: 0.01) == nil)
    check("estimate from elapsed time and progress", JobTime.remaining(elapsed: 30, fraction: 0.25) == 90)
    check("estimate wording", JobTime.text(remaining: 4) == "A few seconds left" && JobTime.text(remaining: 42) == "About 40 seconds left"
          && JobTime.text(remaining: 90) == "About 2 minutes left" && JobTime.text(remaining: 60) == "About 1 minute left", "\(JobTime.text(remaining: 90))")
    check("elapsed wording", JobTime.elapsed(9) == "9 s" && JobTime.elapsed(125) == "2:05")

    // 3d. plain-language errors
    check("an early end of file explains the likely cause", FriendlyError.describe(AXError.corrupt("unexpected end of file")).contains("incomplete download"))
    check("a wrong password says what to do", FriendlyError.describe(AXError.wrongPassword).contains("case-sensitive"))
    check("a full disk is explained", FriendlyError.describe(NSError(domain: NSCocoaErrorDomain, code: NSFileWriteOutOfSpaceError)).contains("free space"))
    check("a missing permission is explained", FriendlyError.describe(NSError(domain: NSPOSIXErrorDomain, code: Int(EACCES))).contains("isn’t allowed"))
    check("an unknown error keeps its own text", FriendlyError.describe(NSError(domain: "x", code: 1, userInfo: [NSLocalizedDescriptionKey: "Boom"])) == "Boom")

    // 3e. preferences feed the defaults
    let ud = UserDefaults.standard
    ud.set(5, forKey: Prefs.defaultLevelKey); ud.set("ZIP", forKey: Prefs.defaultFormatKey)
    ud.set(ExtractDraft.Overwrite.skip.rawValue, forKey: Prefs.overwriteKey); ud.set(false, forKey: Prefs.revealKey)
    check("default level and format preferences are read", Prefs.defaultLevel == 5 && Prefs.defaultFormat?.rawValue == "ZIP", "\(String(describing: Prefs.defaultFormat))")
    let ed = ExtractDraft(destination: "/tmp/x", onlySelected: false, hasSelection: false)
    check("extract defaults follow the preferences", ed.overwrite == .skip && ed.openAfter == false)
    for k in [Prefs.defaultLevelKey, Prefs.defaultFormatKey, Prefs.overwriteKey, Prefs.revealKey] { ud.removeObject(forKey: k) }
    check("without preferences the built-in defaults apply", Prefs.defaultLevel == nil && Prefs.defaultFormat == nil && Prefs.overwrite == .all && Prefs.reveal)

    // 3f. Help → Report a Bug…
    let bug = Feedback.url(.bug, version: "1.4.1", macOS: "macOS 15.1", chip: "Apple Silicon (arm64)")
    let q = Dictionary(uniqueKeysWithValues: (URLComponents(url: bug, resolvingAgainstBaseURL: false)?.queryItems ?? []).map { ($0.name, $0.value ?? "") })
    check("the bug report opens a new issue on the project's GitHub page", bug.host == "github.com" && bug.path == "/YashDayani/ArchiveX/issues/new", bug.absoluteString)
    check("the bug report form is prefilled with version, macOS and chip",
          q["template"] == "bug_report.yml" && q["version"] == "1.4.1" && q["macos"] == "macOS 15.1" && q["chip"] == "Apple Silicon (arm64)", "\(q)")
    check("the feature request uses its own form", Feedback.url(.feature).absoluteString.contains("template=feature_request.yml"))
    check("nothing about the user's files or home folder is sent", !Feedback.url(.bug).absoluteString.contains(NSHomeDirectory()) && !Feedback.url(.bug).absoluteString.contains(NSUserName()))
    let tpl = (try? String(contentsOfFile: "\(fm.currentDirectoryPath)/.github/ISSUE_TEMPLATE/bug_report.yml")) ?? ""
    if !tpl.isEmpty { check("every prefilled field exists in the issue form", ["id: version", "id: macos", "id: chip"].allSatisfy { tpl.contains($0) }) }

    // 3h. recent archives on the welcome screen
    let ra = URL(fileURLWithPath: "/x/a.zip"), rb = URL(fileURLWithPath: "/x/b.7z"), rc = URL(fileURLWithPath: "/y/c.rar"), rd = URL(fileURLWithPath: "/x/d.tar"), gone = URL(fileURLWithPath: "/x/gone.zip")
    let recent = Recents.list(from: [ra, rb, ra, gone, rc, rd], limit: 3, exists: { $0 != gone }, size: { _ in 2048 })
    check("recents keep order, drop duplicates and missing files, and stop at the limit", recent.map(\.url) == [ra, rb, rc], "\(recent.map(\.name))")
    check("a recent shows its name, folder and size", recent[2].name == "c.rar" && recent[2].place == "y" && recent[2].size == Fmt.bytes(2048))
    check("the welcome screen shows three recents at most", Recents.list(from: [ra, rb, rc, rd], exists: { _ in true }, size: { _ in 1 }).count == 3)

    // 3j. inspector previews
    check("preview kinds follow the file type", PreviewKind.of("a.PNG") == .image && PreviewKind.of("notes.md") == .text
          && PreviewKind.of("x.pdf") == .pdf && PreviewKind.of("movie.mov") == .none && PreviewKind.of("noext") == .none)
    let pv = dir.appendingPathComponent("pv")
    try! fm.createDirectory(at: pv, withIntermediateDirectories: true)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 40, pixelsHigh: 20, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                               isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    try! rep.representation(using: .png, properties: [:])!.write(to: pv.appendingPathComponent("pic.png"))
    try! "hello preview\n".write(to: pv.appendingPathComponent("note.txt"), atomically: true, encoding: .utf8)
    try! Data([0, 1, 2, 3]).write(to: pv.appendingPathComponent("data.bin"))
    do {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/zip"); p.arguments = ["-qr", "../pv.zip", "."]
        p.currentDirectoryURL = pv; try! p.run(); p.waitUntilExit()
    }
    let m2 = ArchiveModel()
    m2.open(dir.appendingPathComponent("pv.zip")); await settle(m2)
    let loader = PreviewLoader()
    func settled() async {
        for _ in 0..<60 { if case .loading = loader.state { try? await Task.sleep(nanoseconds: 100_000_000) } else { break } }
    }
    let pic = m2.visibleRows.first { $0.name == "pic.png" }!, note = m2.visibleRows.first { $0.name == "note.txt" }!, bin = m2.visibleRows.first { $0.name == "data.bin" }!
    loader.load(pic, in: m2); await settled()
    if case .image(let img) = loader.state { check("an image in the archive is previewed", img.size.width == 40 && img.size.height == 20, "\(img.size)") }
    else { check("an image in the archive is previewed", false, "\(loader.state)") }
    loader.load(note, in: m2); await settled()
    if case .text(let s, let cut) = loader.state { check("a text file is previewed", s == "hello preview\n" && !cut, s) }
    else { check("a text file is previewed", false, "\(loader.state)") }
    loader.load(bin, in: m2)
    if case .none = loader.state { check("a file type without a preview shows none", true) } else { check("a file type without a preview shows none", false, "\(loader.state)") }
    var big = pic; big.size = 50_000_000
    loader.load(big, in: m2)
    if case .notice(let n) = loader.state { check("a very large file is not unpacked for a preview", n.contains("Too large"), n) }
    else { check("a very large file is not unpacked for a preview", false, "\(loader.state)") }
    loader.load(nil, in: m2)
    if case .none = loader.state { check("no selection clears the preview", true) } else { check("no selection clears the preview", false, "\(loader.state)") }

    // 4. leftovers: only the scratch root, which is wiped at the next launch
    ArchiveModel.cleanOldScratch()
    print("\nRESULT: \(pass) passed, \(fail) failed")
    exit(fail == 0 ? 0 : 1)
}
Task { @MainActor in await run() }
RunLoop.main.run()
