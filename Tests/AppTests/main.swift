import Foundation
import AppKit

let fm = FileManager.default
let root = URL(fileURLWithPath: CommandLine.arguments[1])
let src = root.appendingPathComponent("src")
let work = root.appendingPathComponent("work-\(Int(Date().timeIntervalSince1970))")
try! fm.createDirectory(at: work, withIntermediateDirectories: true)
var pass = 0, fail = 0
var currentPW = ""
func report(_ name: String, _ ok: Bool, _ note: String = "") {
    if ok { pass += 1; print("PASS \(name)") } else { fail += 1; print("FAIL \(name) \(note)") }
}
func same(_ a: URL, _ b: URL) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/diff"); p.arguments = ["-r", a.path, b.path]
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    try? p.run(); p.waitUntilExit(); return p.terminationStatus == 0
}

@MainActor func settle(_ m: ArchiveModel, _ secs: Double = 60) async {
    try? await Task.sleep(nanoseconds: 150_000_000)
    let end = Date().addingTimeInterval(secs)
    while m.busy && Date() < end { try? await Task.sleep(nanoseconds: 100_000_000) }
    try? await Task.sleep(nanoseconds: 150_000_000)
    if m.passwordPrompt, !currentPW.isEmpty { m.submitPassword(currentPW); await settle(m) }
}

@MainActor func run() async {
    let files = [src.appendingPathComponent("a.txt"), src.appendingPathComponent("sub")]
    struct Case { var name: String; var fmt: ArchiveFormat; var pw = ""; var names = false; var level = 3; var solid = false }
    let allCases: [Case] = [
        Case(name: "7z", fmt: .sevenZ), Case(name: "7z-solid-best", fmt: .sevenZ, level: 5, solid: true),
        Case(name: "7z-enc", fmt: .sevenZ, pw: "pw1", names: true), Case(name: "7z-store", fmt: .sevenZ, level: 0),
        Case(name: "zip", fmt: .zip), Case(name: "zip-enc", fmt: .zip, pw: "pw1"),
        Case(name: "tar", fmt: .tar), Case(name: "tgz", fmt: .tgz), Case(name: "tbz2", fmt: .tbz2), Case(name: "txz", fmt: .txz),
    ]
    let cases = allCases
    var made: [(Case, URL)] = []
    for c in cases {
        let m = ArchiveModel()
        var d = AddDraft(files: files, archivePath: work.appendingPathComponent("c-\(c.name)").path)
        d.format = c.fmt; d.level = c.level; d.solid = c.solid; d.password = c.pw; d.confirm = c.pw; d.encryptNames = c.names
        d.test = true
        m.create(d); await settle(m)
        let out = work.appendingPathComponent("c-\(c.name)." + c.fmt.ext)
        let exists = fm.fileExists(atPath: out.path)
        report("create \(c.name)", exists && m.alert == nil, m.alert?.message ?? "no file")
        if exists { made.append((c, out)) }
    }
    for (c, url) in made {
        currentPW = c.pw
        let m = ArchiveModel()
        m.open(url); await settle(m)
        if m.passwordPrompt { m.submitPassword(c.pw); await settle(m) }
        let names = Set(m.entries.map { $0.path })
        report("open+list \(c.name)", m.archiveURL == url && names.contains("a.txt") && names.contains("sub/b.txt") && names.contains("sub/rand.bin"), "entries=\(names.sorted())")
        let rows = m.visibleRows.map { $0.name }.sorted()
        report("rows \(c.name)", rows == ["a.txt", "sub"], "\(rows)")
        m.test(); await settle(m)
        report("test \(c.name)", m.alert?.title == "No errors found", m.alert?.title ?? "nil")
        m.alert = nil
        let dest = work.appendingPathComponent("x-\(c.name)")
        m.extract(ExtractDraft(destination: dest.path, onlySelected: false, openAfter: false, hasSelection: false)); await settle(m)
        report("extract all \(c.name)", same(dest.appendingPathComponent("a.txt"), src.appendingPathComponent("a.txt")) && same(dest.appendingPathComponent("sub"), src.appendingPathComponent("sub")), m.alert?.message ?? "")
        // selected folder only
        m.currentDir = ""; m.selection = ["sub"]
        let dest2 = work.appendingPathComponent("xs-\(c.name)")
        m.extract(ExtractDraft(destination: dest2.path, onlySelected: true, openAfter: false, hasSelection: true)); await settle(m)
        report("extract selected folder \(c.name)", same(dest2.appendingPathComponent("sub"), src.appendingPathComponent("sub")) && !fm.fileExists(atPath: dest2.appendingPathComponent("a.txt").path), m.alert?.message ?? "")
        // no-paths extract
        let dest3 = work.appendingPathComponent("xe-\(c.name)")
        m.extract(ExtractDraft(destination: dest3.path, onlySelected: false, keepPaths: false, openAfter: false, hasSelection: false)); await settle(m)
        report("extract flat \(c.name)", fm.fileExists(atPath: dest3.appendingPathComponent("b.txt").path), "")
        // wrong password handling
        if c.name == "zip-enc" {
            currentPW = ""; let w = ArchiveModel(); w.open(url); await settle(w); w.password = "nope"
            let dd = work.appendingPathComponent("wrongpw"); w.extract(ExtractDraft(destination: dd.path, onlySelected: false, openAfter: false, hasSelection: false)); await settle(w)
            report("wrong password rejected zip-enc", w.passwordPrompt || w.alert != nil, ""); currentPW = c.pw
        } else if !c.pw.isEmpty {
            currentPW = ""; let w = ArchiveModel(); w.password = "nope"; w.open(url); await settle(w); currentPW = c.pw
            report("wrong password rejected \(c.name)", w.alert != nil || w.passwordPrompt || w.entries.isEmpty, "")
        }
    }
    // modify: add / delete on formats that support it
    currentPW = ""
    for c in cases where c.fmt.canUpdate && c.pw.isEmpty {
        let url = work.appendingPathComponent("c-\(c.name)." + c.fmt.ext)
        let extra = work.appendingPathComponent("extra-\(c.name).txt"); try! "extra".write(to: extra, atomically: true, encoding: .utf8)
        let m = ArchiveModel(); m.open(url); await settle(m)
        m.prepareAdd(files: [extra], toOpenArchive: true)
        guard var d = m.addDraft else { report("add \(c.name)", false, "no draft: \(m.alert?.message ?? "")"); continue }
        d.format = c.fmt
        m.addDraft = nil; m.create(d); await settle(m); await settle(m)
        m.refresh(); await settle(m)
        report("add to existing \(c.name)", m.entries.contains { $0.path == "extra-\(c.name).txt" }, m.alert?.message ?? "\(m.entries.map{$0.path})")
        m.selection = ["extra-\(c.name).txt"]
        m.confirmDelete(); m.alert?.action?(); m.alert = nil; await settle(m); await settle(m)
        report("delete from \(c.name)", !m.entries.contains { $0.path == "extra-\(c.name).txt" } && m.entries.contains { $0.path == "a.txt" }, m.alert?.message ?? "")
    }
    // view a file
    do {
        let m = ArchiveModel(); m.open(work.appendingPathComponent("c-7z.7z")); await settle(m)
        report("view/openEntry no error", { m.view(m.visibleRows.first { !$0.isDir }!); return true }())
        await settle(m); report("view no alert", m.alert == nil, m.alert?.message ?? "")
    }
    // read-only / foreign formats (created by other tools)
    let fx = root.appendingPathComponent("foreign")
    for name in (try! fm.contentsOfDirectory(atPath: fx.path)).sorted() {
        let url = fx.appendingPathComponent(name)
        let m = ArchiveModel(); m.open(url); await settle(m)
        let found = m.entries.contains { $0.path.hasSuffix("a.txt") || $0.path.hasSuffix("b.txt") || $0.path.hasSuffix("hello.txt") }
        report("foreign open \(name)", m.archiveURL == url && found, m.alert?.message ?? "entries=\(m.entries.map{$0.path}.prefix(5))")
        if found {
            let dest = work.appendingPathComponent("f-\(name)")
            m.extract(ExtractDraft(destination: dest.path, onlySelected: false, openAfter: false, hasSelection: false)); await settle(m)
            let got = (fm.enumerator(atPath: dest.path)?.allObjects as? [String] ?? []).contains { $0.hasSuffix("a.txt") || $0.hasSuffix("b.txt") || $0.hasSuffix("hello.txt") }
            report("foreign extract \(name)", got, m.alert?.message ?? "")
        }
    }
    print("\nRESULT: \(pass) passed, \(fail) failed")
    exit(fail == 0 ? 0 : 1)
}
Task { @MainActor in await run() }
RunLoop.main.run()
