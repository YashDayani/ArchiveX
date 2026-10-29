import Foundation
import CryptoKit

// Tests for ArchiveX's own RAR 5 writer (store method, optional AES-256). Needs only macOS's bsdtar as an independent
// reader; no RARLAB tool is involved.
//   swiftc -O -swift-version 5 Sources/Engine.swift Sources/Core/*.swift Tests/RarWriteTests/main.swift -o /tmp/RarWriteTests
//   /tmp/RarWriteTests <work-dir>

let fm = FileManager.default
let work = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("rw-\(Int(Date().timeIntervalSince1970))")
try! fm.createDirectory(at: work, withIntermediateDirectories: true)
var passed = 0, failed = 0
func check(_ name: String, _ ok: Bool, _ note: String = "") {
    if ok { passed += 1; print("PASS \(name)") } else { failed += 1; print("FAIL \(name) \(note)") }
}
@discardableResult func sh(_ cmd: String, cwd: URL? = nil) -> (status: Int32, out: String) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = ["-c", cmd]
    if let c = cwd { p.currentDirectoryURL = c }
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe; p.standardInput = FileHandle.nullDevice
    try? p.run(); let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return (p.terminationStatus, String(decoding: d, as: UTF8.self))
}
func q(_ u: URL) -> String { "'" + u.path.replacingOccurrences(of: "'", with: "'\\''") + "'" }
func tree(_ root: URL) -> [String: String] {
    var out: [String: String] = [:]
    guard let en = fm.enumerator(atPath: root.path) else { return out }
    for case let rel as String in en {
        let u = root.appendingPathComponent(rel)
        var st = stat(); lstat(u.path, &st)
        switch st.st_mode & S_IFMT {
        case S_IFLNK: out[rel] = "link→" + ((try? fm.destinationOfSymbolicLink(atPath: u.path)) ?? "?")
        case S_IFDIR: out[rel] = "dir"
        default: out[rel] = "file:" + (try! Data(contentsOf: u)).sha256Hex
        }
    }
    return out
}
extension Data { var sha256Hex: String { SHA256.hash(data: self).map { String(format: "%02x", $0) }.joined() } }

// MARK: fixtures

let src = work.appendingPathComponent("src"); try! fm.createDirectory(at: src.appendingPathComponent("a/sub/deeper"), withIntermediateDirectories: true)
try! fm.createDirectory(at: src.appendingPathComponent("b/empty-dir"), withIntermediateDirectories: true)
try! "hello\n".write(to: src.appendingPathComponent("a/one.txt"), atomically: true, encoding: .utf8)
try! "deep\n".write(to: src.appendingPathComponent("a/sub/deeper/two.txt"), atomically: true, encoding: .utf8)
try! Data().write(to: src.appendingPathComponent("a/empty.txt"))
try! "unicode\n".write(to: src.appendingPathComponent("b/résumé 日本語 ✓.txt"), atomically: true, encoding: .utf8)
try! Data((0..<300_000).map { _ in UInt8.random(in: 0...255) }).write(to: src.appendingPathComponent("b/random.bin"))
try! Data((1...80_000).map { "line \($0)\n" }.joined().utf8).write(to: src.appendingPathComponent("b/text.txt"))
try! Data(repeating: 7, count: 4096).write(to: src.appendingPathComponent("b/exactly-4096-aligned.bin"))     // multiple of the AES block
try! fm.createSymbolicLink(atPath: src.appendingPathComponent("a/link").path, withDestinationPath: "one.txt")
let roots = [src.appendingPathComponent("a"), src.appendingPathComponent("b")]
let pw = "s3cret-\u{e9}"

func make(_ name: String, level: Int = 3, password: String? = nil, items: [URL] = roots) throws -> URL {
    let out = work.appendingPathComponent(name)
    try AXCore.create(AXCreate(format: .rar, output: out, items: items, level: level, password: password), progress: { _ in })
    return out
}
func extract(_ a: URL, _ name: String, password: String? = nil) throws -> URL {
    let d = work.appendingPathComponent(name)
    try AXCore.extract(a, selection: [], to: d, overwrite: .all, keepPaths: true, password: password, progress: { _ in })
    return d
}

// MARK: plain archives

do {
    let a = try make("plain.rar")
    let ours = try extract(a, "own-plain")
    check("plain: ArchiveX reads its own archive back identically", tree(ours) == tree(src), "\(Set(tree(ours).keys).symmetricDifference(Set(tree(src).keys)))")
    try AXCore.test(a, password: nil, progress: { _ in })
    check("plain: integrity test passes", true)
    // an independent reader (libarchive) must accept folders, symlinks, empty files and Unicode names too
    let ref = work.appendingPathComponent("bsdtar-plain"); try fm.createDirectory(at: ref, withIntermediateDirectories: true)
    let r = sh("/usr/bin/bsdtar -xf \(q(a)) -C \(q(ref))")
    check("plain: bsdtar accepts the archive", r.status == 0, r.out)
    check("plain: bsdtar extracts identical files, folders and symlinks", tree(ref) == tree(src), "\(Set(tree(ref).keys).symmetricDifference(Set(tree(src).keys)))")
    let l = try AXCore.list(a, password: nil)
    check("plain: listing names and sizes", l.entries.contains { $0.path == "b/random.bin" && $0.size == 300_000 } && l.entries.contains { $0.isDir && $0.path == "b/empty-dir" })
} catch { check("plain", false, "\(error)") }

// items from different folders keep their own names
do {
    let x = work.appendingPathComponent("x"), y = work.appendingPathComponent("y")
    try fm.createDirectory(at: x, withIntermediateDirectories: true); try fm.createDirectory(at: y, withIntermediateDirectories: true)
    try "1".write(to: x.appendingPathComponent("f1.txt"), atomically: true, encoding: .utf8); try "2".write(to: y.appendingPathComponent("f2.txt"), atomically: true, encoding: .utf8)
    let a = try make("multi-parent.rar", items: [x.appendingPathComponent("f1.txt"), y.appendingPathComponent("f2.txt")])
    let names = try AXCore.list(a, password: nil).entries.map(\.path).sorted()
    check("items from different folders are stored under their own names", names == ["f1.txt", "f2.txt"], "\(names)")
} catch { check("multi-parent", false, "\(error)") }

// MARK: encryption

do {
    let a = try make("enc.rar", password: pw)
    check("encrypted: ArchiveX decrypts its own archive", tree(try extract(a, "own-enc", password: pw)) == tree(src))
    try AXCore.test(a, password: pw, progress: { _ in })
    check("encrypted: integrity test passes", true)
    do { _ = try extract(a, "enc-none"); check("encrypted: missing password reported", false) }
    catch AXError.passwordRequired { check("encrypted: missing password reported", true) } catch { check("encrypted: missing password reported", false, "\(error)") }
    do { _ = try extract(a, "enc-bad", password: "wrong"); check("encrypted: wrong password rejected", false) }
    catch AXError.wrongPassword { check("encrypted: wrong password rejected", true) } catch { check("encrypted: wrong password rejected", false, "\(error)") }
    // the data on disk really is ciphertext, and the password check value has the layout real RAR writes
    let raw = try Data(contentsOf: a)
    check("encrypted: file contents do not appear in the archive", raw.range(of: Data("line 4242\n".utf8)) == nil && raw.range(of: Data("hello\n".utf8)) == nil)
    var okCheck = false
    for i in 0..<(raw.count - 12) where i % 1 == 0 && i < 4000 {            // header area only
        if SHA256.hash(data: raw[i..<i + 8]).prefix(4).elementsEqual(raw[i + 8..<i + 12]) { okCheck = true; break }
    }
    check("encrypted: password check value = 8 bytes + first 4 bytes of their SHA-256", okCheck)
    // two archives of the same data must differ (fresh salt and IV)
    let b = try make("enc2.rar", password: pw)
    check("encrypted: salt and IV are random per archive", try Data(contentsOf: a) != Data(contentsOf: b))
} catch { check("encrypted", false, "\(error)") }

// MARK: editing

do {
    let a = try make("edit.rar")
    let extra = work.appendingPathComponent("added.txt"); try "added later".write(to: extra, atomically: true, encoding: .utf8)
    try AXCore.edit(a, remove: [("a/sub", true), ("b/text.txt", false)], add: [extra], level: 3, password: nil, legacy: false, progress: { _ in })
    let names = Set(try AXCore.list(a, password: nil).entries.map(\.path))
    check("edit: removed folder and file, added file", !names.contains("a/sub/deeper/two.txt") && !names.contains("b/text.txt") && names.contains("added.txt") && names.contains("b/random.bin"), "\(names.sorted())")
    let back = try extract(a, "own-edit")
    check("edit: remaining content intact", (try? Data(contentsOf: back.appendingPathComponent("b/random.bin"))) == (try? Data(contentsOf: src.appendingPathComponent("b/random.bin")))
          && (try? String(contentsOf: back.appendingPathComponent("added.txt"))) == "added later")
    let ref = work.appendingPathComponent("bsdtar-edit"); try fm.createDirectory(at: ref, withIntermediateDirectories: true)
    check("edit: bsdtar accepts the rewritten archive", sh("/usr/bin/bsdtar -xf \(q(a)) -C \(q(ref))").status == 0)
    // an encrypted archive stays encrypted through an edit
    let e = try make("edit-enc.rar", password: pw)
    try AXCore.edit(e, remove: [("b/text.txt", false)], add: [], level: 3, password: pw, legacy: false, progress: { _ in })
    do { _ = try extract(e, "edit-enc-none"); check("edit: encrypted archive stays encrypted", false) }
    catch AXError.passwordRequired { check("edit: encrypted archive stays encrypted", true) } catch { check("edit: encrypted archive stays encrypted", false, "\(error)") }
    check("edit: encrypted archive still opens with the password", (try? extract(e, "edit-enc-ok", password: pw)).map { tree($0).keys.contains("b/random.bin") } ?? false)
} catch { check("edit", false, "\(error)") }

// MARK: attack: an entry named "../secret" must never pull a real file into a rewritten archive

do {
    let dir = work.appendingPathComponent("attack"); try fm.createDirectory(at: dir, withIntermediateDirectories: true)
    let secret = dir.appendingPathComponent("secret.txt")                          // sits where "../secret.txt" would resolve from the temp folder
    try "TOP-SECRET-CONTENT".write(to: secret, atomically: true, encoding: .utf8)
    let decoy = work.appendingPathComponent("decoy.txt"); try "decoy".write(to: decoy, atomically: true, encoding: .utf8)
    let evil = dir.appendingPathComponent("evil.rar")
    let w = try Rar5Writer(url: evil, solid: false)
    try w.addFile(source: decoy, name: "../secret.txt", size: 5, mtime: Date(), mode: 0o644, progress: nil)
    try w.addFile(source: decoy, name: "/etc/hosts", size: 5, mtime: Date(), mode: 0o644, progress: nil)
    try w.addFile(source: decoy, name: "keep.txt", size: 5, mtime: Date(), mode: 0o644, progress: nil)
    try w.addFile(source: decoy, name: "drop.txt", size: 5, mtime: Date(), mode: 0o644, progress: nil)
    try w.finish()
    try AXCore.edit(evil, remove: [("drop.txt", false)], add: [], level: 3, password: nil, legacy: false, progress: { _ in })
    let raw = try Data(contentsOf: evil)
    let names = try AXCore.list(evil, password: nil).entries.map(\.path)
    check("attack: the real file behind “../secret.txt” is not copied into the archive", raw.range(of: Data("TOP-SECRET-CONTENT".utf8)) == nil)
    // "/etc/hosts" is made relative like everywhere else in ArchiveX ("etc/hosts"); only the "../" entry is refused
    check("attack: the “../” entry is dropped and the others are kept", names == ["etc/hosts", "keep.txt"], "\(names)")
} catch { check("attack", false, "\(error)") }

print("\nRESULT: \(passed) passed, \(failed) failed")
exit(failed == 0 ? 0 : 1)
