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

    // 4. leftovers: only the scratch root, which is wiped at the next launch
    ArchiveModel.cleanOldScratch()
    print("\nRESULT: \(pass) passed, \(fail) failed")
    exit(fail == 0 ? 0 : 1)
}
Task { @MainActor in await run() }
RunLoop.main.run()
