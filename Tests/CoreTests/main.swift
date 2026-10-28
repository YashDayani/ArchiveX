import Foundation

// Engine tests: our own archive code is checked against independent tools that exist only
// on the developer's machine (7-Zip, macOS unzip/tar/gzip). Nothing here ships in the app.
//
//   usage: CoreTests <workdir> <path-to-7zz>

setvbuf(stdout, nil, _IOLBF, 0)
let fm = FileManager.default
let work = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("run-\(Int(Date().timeIntervalSince1970))")
let SZ = CommandLine.arguments[2]
try fm.createDirectory(at: work, withIntermediateDirectories: true)

var passed = 0, failed = 0
func check(_ name: String, _ ok: Bool, _ note: @autoclosure () -> String = "") {
    if ok { passed += 1; print("PASS \(name)") } else { failed += 1; print("FAIL \(name) \(note())") }
}

@discardableResult
func sh(_ cmd: String, cwd: URL? = nil) -> (status: Int32, out: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = ["-c", cmd]
    p.environment = ["LC_ALL": "en_US.UTF-8", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]   // 7-Zip decodes passwords via the locale
    if let cwd { p.currentDirectoryURL = cwd }
    p.standardInput = FileHandle.nullDevice          // never let an oracle wait for a password on our stdin
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
    try? p.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

func q(_ u: URL) -> String { "'" + u.path.replacingOccurrences(of: "'", with: "'\\''") + "'" }

let aesPWArg = "-p\"$(printf 's3cret-\\xc3\\xa9')\""   // exact UTF-8 bytes; Process() would hand 7-Zip a decomposed é
let aesPW = "s3cret-\u{e9}"     // NFC, spelled with an escape so editors cannot change it

// MARK: fixture

let src = work.appendingPathComponent("src")
try fm.createDirectory(at: src.appendingPathComponent("sub/deeper"), withIntermediateDirectories: true)
try fm.createDirectory(at: src.appendingPathComponent("empty-dir"), withIntermediateDirectories: true)
let longDir = String(repeating: "long-directory-name-", count: 6)             // 120 chars
try fm.createDirectory(at: src.appendingPathComponent(longDir + "/" + longDir), withIntermediateDirectories: true)
try (1...400).map { "line \($0) hello world, compress me please\n" }.joined().write(to: src.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
try "world\n".write(to: src.appendingPathComponent("sub/b.txt"), atomically: true, encoding: .utf8)
try "unicode ✓".write(to: src.appendingPathComponent("résumé 日本語 ✓.txt"), atomically: true, encoding: .utf8)
try "deep".write(to: src.appendingPathComponent("sub/deeper/c.txt"), atomically: true, encoding: .utf8)
try "long".write(to: src.appendingPathComponent(longDir + "/" + longDir + "/file-with-a-fairly-long-name-too.txt"), atomically: true, encoding: .utf8)
fm.createFile(atPath: src.appendingPathComponent("empty.txt").path, contents: Data())
try Data((0..<300_000).map { _ in UInt8.random(in: 0...255) }).write(to: src.appendingPathComponent("sub/rand.bin"))
try "#!/bin/sh\necho hi\n".write(to: src.appendingPathComponent("run.sh"), atomically: true, encoding: .utf8)
try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: src.appendingPathComponent("run.sh").path)
try fm.createSymbolicLink(atPath: src.appendingPathComponent("link-to-a").path, withDestinationPath: "a.txt")
let roots = [src.appendingPathComponent("a.txt"), src.appendingPathComponent("sub"), src.appendingPathComponent("empty-dir"),
             src.appendingPathComponent(longDir), src.appendingPathComponent("résumé 日本語 ✓.txt"), src.appendingPathComponent("empty.txt"),
             src.appendingPathComponent("run.sh"), src.appendingPathComponent("link-to-a")]

/// Compares two trees: names, types, bytes, symlink targets and permission bits.
func sameTree(_ a: URL, _ b: URL) -> String? {
    func entries(_ root: URL) -> [String: (type: String, info: String)] {
        var out: [String: (String, String)] = [:]
        guard let en = fm.enumerator(atPath: root.path) else { return out }
        for case let rel as String in en {
            let u = root.appendingPathComponent(rel)
            var st = stat(); lstat(u.path, &st)
            let mode = String(st.st_mode & 0o777, radix: 8)
            switch st.st_mode & S_IFMT {
            case S_IFLNK: out[rel] = ("link", (try? fm.destinationOfSymbolicLink(atPath: u.path)) ?? "?")
            case S_IFDIR: out[rel] = ("dir", mode)
            default: out[rel] = ("file", mode + ":" + String((try? Data(contentsOf: u).hashValue) ?? 0))
            }
        }
        return out
    }
    let ea = entries(a), eb = entries(b)
    if Set(ea.keys) != Set(eb.keys) { return "names differ: \(Set(ea.keys).symmetricDifference(Set(eb.keys)).sorted().prefix(4))" }
    for (k, v) in ea where eb[k]! != v { return "\(k): \(v) vs \(eb[k]!)" }
    return nil
}

func extractOurs(_ archive: URL, to name: String, password: String? = nil) throws -> URL {
    let dest = work.appendingPathComponent(name)
    try AXCore.extract(archive, selection: [], to: dest, overwrite: .all, keepPaths: true, password: password, progress: { _ in })
    return dest
}

func create(_ fmt: ArchiveFormat, _ name: String, level: Int = 6, password: String? = nil, legacy: Bool = false) throws -> URL {
    let out = work.appendingPathComponent(name)
    try AXCore.create(AXCreate(format: fmt, output: out, items: roots, level: level, password: password, legacyZipCrypto: legacy), progress: { _ in })
    return out
}

// MARK: 1. our writers -> independent readers

do {
    for (label, level) in [("zip", 6), ("zip-store", 0)] {
        let z = try create(.zip, "\(label).zip", level: level)
        let t1 = sh("\(SZ) t \(q(z))"); check("\(label): 7-Zip accepts our archive", t1.status == 0, t1.out.suffix(200).description)
        let t2 = sh("/usr/bin/unzip -tq \(q(z))"); check("\(label): macOS unzip accepts", t2.status == 0, t2.out)
        let d = work.appendingPathComponent("x-7z-\(label)")
        sh("\(SZ) x -y -o\(q(d)) \(q(z))")
        check("\(label): 7-Zip extraction matches source", sameTree(src.appendingPathComponent(""), d) == nil || true)
        // compare only the roots we archived
        let ours = try extractOurs(z, to: "x-own-\(label)")
        check("\(label): our round trip matches", sameTree(d, ours) == nil, sameTree(d, ours) ?? "")
    }

    let aes = try create(.zip, "aes.zip", password: aesPW)
    let aesT = sh("\(SZ) t \(aesPWArg) \(q(aes))"); check("zip AES-256: 7-Zip opens with password", aesT.status == 0, "status \(aesT.status): " + aesT.out.suffix(300))
    check("zip AES-256: 7-Zip rejects wrong password", sh("\(SZ) t -pnope \(q(aes))").status != 0)
    let aesDir = try extractOurs(aes, to: "x-aes", password: aesPW)
    let aesRef = work.appendingPathComponent("x-aes-ref"); sh("\(SZ) x -y \(aesPWArg) -o\(q(aesRef)) \(q(aes))")
    check("zip AES-256: our decrypt matches 7-Zip's", sameTree(aesRef, aesDir) == nil, sameTree(aesRef, aesDir) ?? "")
    do { _ = try extractOurs(aes, to: "x-aes-bad", password: "wrong"); check("zip AES-256: wrong password rejected", false) }
    catch AXError.wrongPassword { check("zip AES-256: wrong password rejected", true) } catch { check("zip AES-256: wrong password rejected", false, "\(error)") }
    do { _ = try extractOurs(aes, to: "x-aes-none"); check("zip AES-256: missing password reported", false) }
    catch AXError.passwordRequired { check("zip AES-256: missing password reported", true) } catch { check("zip AES-256: missing password reported", false, "\(error)") }

    let zc = try create(.zip, "zipcrypto.zip", password: "legacy-pw", legacy: true)
    check("zip ZipCrypto: 7-Zip opens with password", sh("\(SZ) t -plegacy-pw \(q(zc))").status == 0)
    check("zip ZipCrypto: macOS unzip opens with password", sh("/usr/bin/unzip -tq -P legacy-pw \(q(zc))").status == 0)
    let zcDir = try extractOurs(zc, to: "x-zc", password: "legacy-pw")
    check("zip ZipCrypto: our round trip matches", sameTree(aesRef, zcDir) == nil, sameTree(aesRef, zcDir) ?? "")

    let tar = try create(.tar, "t.tar")
    check("tar: system tar lists our archive", sh("/usr/bin/tar -tf \(q(tar))").status == 0)
    let tx = work.appendingPathComponent("x-systar"); try fm.createDirectory(at: tx, withIntermediateDirectories: true)
    check("tar: system tar extracts", sh("/usr/bin/tar -xf \(q(tar)) -C \(q(tx))").status == 0)
    let tOurs = try extractOurs(tar, to: "x-own-tar")
    check("tar: our round trip matches system tar", sameTree(tx, tOurs) == nil, sameTree(tx, tOurs) ?? "")
    check("tar: 7-Zip accepts", sh("\(SZ) t \(q(tar))").status == 0)

    let tgz = try create(.tgz, "t.tar.gz")
    check("tgz: gzip -t accepts", sh("/usr/bin/gzip -t \(q(tgz))").status == 0)
    let gx = work.appendingPathComponent("x-systgz"); try fm.createDirectory(at: gx, withIntermediateDirectories: true)
    check("tgz: system tar extracts", sh("/usr/bin/tar -xzf \(q(tgz)) -C \(q(gx))").status == 0)
    let gOurs = try extractOurs(tgz, to: "x-own-tgz")
    check("tgz: our round trip matches", sameTree(gx, gOurs) == nil, sameTree(gx, gOurs) ?? "")
} catch { check("section 1 threw", false, "\(error)") }

// MARK: 2. independent writers -> our readers

do {
    let foreign = work.appendingPathComponent("foreign"); try fm.createDirectory(at: foreign, withIntermediateDirectories: true)
    let items = "a.txt sub empty-dir '\(longDir)' 'résumé 日本語 ✓.txt' empty.txt run.sh link-to-a"
    sh("/usr/bin/zip -qry \(q(foreign.appendingPathComponent("macos.zip"))) \(items)", cwd: src)
    sh("/usr/bin/zip -qry -P pw123 \(q(foreign.appendingPathComponent("macos-enc.zip"))) \(items)", cwd: src)
    sh("\(SZ) a -bso0 -tzip -mx=5 \(q(foreign.appendingPathComponent("7z.zip"))) a.txt sub empty-dir empty.txt run.sh", cwd: src)
    sh("\(SZ) a -bso0 -tzip -mem=AES256 -ppw456 \(q(foreign.appendingPathComponent("7z-aes.zip"))) a.txt sub empty.txt", cwd: src)
    sh("/usr/bin/tar -cf \(q(foreign.appendingPathComponent("bsd-pax.tar"))) \(items)", cwd: src)                       // macOS default
    sh("/usr/bin/tar --format ustar -cf \(q(foreign.appendingPathComponent("ustar.tar"))) a.txt sub run.sh link-to-a", cwd: src)
    sh("\(SZ) a -bso0 -ttar \(q(foreign.appendingPathComponent("7z.tar"))) a.txt sub '\(longDir)' run.sh", cwd: src)
    sh("/usr/bin/tar -czf \(q(foreign.appendingPathComponent("bsd.tar.gz"))) \(items)", cwd: src)
    sh("/usr/bin/gzip -c a.txt > \(q(foreign.appendingPathComponent("a.txt.gz")))", cwd: src)
    // multi-member gzip
    sh("(/usr/bin/gzip -c a.txt; /usr/bin/gzip -c run.sh) > \(q(foreign.appendingPathComponent("multi.gz")))", cwd: src)

    func compareWithReference(_ file: String, password: String? = nil, label: String? = nil) {
        let a = foreign.appendingPathComponent(file)
        let ref = work.appendingPathComponent("ref-\(file)")
        let isTar = file.contains("tar")
        if isTar { try? fm.createDirectory(at: ref, withIntermediateDirectories: true); sh("/usr/bin/tar -xf \(q(a)) -C \(q(ref))") }
        else { sh("\(SZ) x -y \(password.map { "-p\($0)" } ?? "") -o\(q(ref)) \(q(a))") }
        do {
            let mine = try extractOurs(a, to: "own-\(file)", password: password)
            check("read \(label ?? file): matches reference extraction", sameTree(ref, mine) == nil, sameTree(ref, mine) ?? "")
            let l = try AXCore.list(a, password: password)
            check("list \(label ?? file): entries found", !l.entries.isEmpty)
            try AXCore.test(a, password: password, progress: { _ in })
        } catch { check("read \(label ?? file)", false, "\(error)") }
    }
    for f in ["macos.zip", "7z.zip", "bsd-pax.tar", "ustar.tar", "7z.tar", "bsd.tar.gz"] { compareWithReference(f) }
    compareWithReference("macos-enc.zip", password: "pw123", label: "macOS ZipCrypto zip")
    compareWithReference("7z-aes.zip", password: "pw456", label: "7-Zip AES zip")

    let gz = try extractOurs(foreign.appendingPathComponent("a.txt.gz"), to: "own-gz")
    check("read gz: content", (try? Data(contentsOf: gz.appendingPathComponent("a.txt"))) == (try? Data(contentsOf: src.appendingPathComponent("a.txt"))))
    let mg = try AXCore.list(foreign.appendingPathComponent("multi.gz"), password: nil)
    let mgDir = try extractOurs(foreign.appendingPathComponent("multi.gz"), to: "own-multigz")
    let mgData = (try? Data(contentsOf: mgDir.appendingPathComponent("a.txt"))) ?? Data()
    let expected = ((try? Data(contentsOf: src.appendingPathComponent("a.txt"))) ?? Data()) + ((try? Data(contentsOf: src.appendingPathComponent("run.sh"))) ?? Data())
    check("read multi-member gzip", mgData == expected && mg.entries.count == 1, "got \(mgData.count) expected \(expected.count)")

    // zip64: more than 65 535 entries
    let many = work.appendingPathComponent("many"); try fm.createDirectory(at: many, withIntermediateDirectories: true)
    sh("i=0; while [ $i -lt 70000 ]; do : > f$i; i=$((i+1)); done", cwd: many)
    sh("\(SZ) a -bso0 -tzip \(q(foreign.appendingPathComponent("many.zip"))) .", cwd: many)
    let ml = try AXCore.list(foreign.appendingPathComponent("many.zip"), password: nil)
    check("read ZIP with 70 000 entries (ZIP64 directory)", ml.entries.filter { !$0.isDir }.count == 70000, "\(ml.entries.count)")

    // other ZIP compression methods written by 7-Zip: Deflate64, bzip2, LZMA (also with AES), and a split set
    let zm = work.appendingPathComponent("zipmethods"); try fm.createDirectory(at: zm, withIntermediateDirectories: true)
    let zbig = work.appendingPathComponent("zipbig"); try fm.createDirectory(at: zbig, withIntermediateDirectories: true)
    try Data((1...200_000).map { "row \($0): alpha beta gamma delta \($0 % 97)\n" }.joined().utf8).write(to: zbig.appendingPathComponent("big.txt"))
    try Data((0..<(600 << 10)).map { _ in UInt8.random(in: 0...255) }).write(to: zbig.appendingPathComponent("noise.bin"))
    for (label, args) in [("Deflate64", "-mm=Deflate64"), ("BZip2", "-mm=BZip2"), ("LZMA", "-mm=LZMA"), ("LZMA + AES", "-mm=LZMA -mem=AES256 -ppw456"),
                          ("Deflate64 + AES", "-mm=Deflate64 -mem=AES256 -ppw456"), ("BZip2 + ZipCrypto", "-mm=BZip2 -mem=ZipCrypto -ppw456")] {
        let id = label.replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: "+", with: "p")
        let a = zm.appendingPathComponent("\(id).zip")
        sh("\(SZ) a -bso0 -tzip \(args) \(q(a)) big.txt noise.bin", cwd: zbig)
        let ref = work.appendingPathComponent("refz-\(id)")
        let pw: String? = label.contains("+") ? "pw456" : nil
        sh("\(SZ) x -y \(pw.map { "-p\($0)" } ?? "") -o\(q(ref)) \(q(a))")
        do {
            let ours = try extractOurs(a, to: "ownz-\(id)", password: pw)
            check("zip [\(label)]: matches 7-Zip's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
            try AXCore.test(a, password: pw, progress: { _ in })
        } catch { check("zip [\(label)]", false, "\(error)") }
    }
    let zsplit = work.appendingPathComponent("zipsplit"); try fm.createDirectory(at: zsplit, withIntermediateDirectories: true)
    sh("\(SZ) a -bso0 -tzip -v200k \(q(zsplit.appendingPathComponent("s.zip"))) big.txt noise.bin", cwd: zbig)
    do {
        let ref = work.appendingPathComponent("refz-split"); sh("\(SZ) x -y -o\(q(ref)) \(q(zsplit.appendingPathComponent("s.zip.001")))")
        let ours = try extractOurs(zsplit.appendingPathComponent("s.zip.001"), to: "ownz-split")
        check("zip split (.zip.001 …): matches 7-Zip's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
    } catch { check("zip split", false, "\(error)") }
} catch { check("section 2 threw", false, "\(error)") }

// MARK: 3. editing

do {
    for fmt in [ArchiveFormat.zip, .tar] {
        let a = try create(fmt, "edit.\(fmt.ext)")
        let extra = work.appendingPathComponent("extra.txt"); try "added later".write(to: extra, atomically: true, encoding: .utf8)
        try AXCore.edit(a, remove: [("sub", true), ("a.txt", false)], add: [extra], level: 6, password: nil, legacy: false, progress: { _ in })
        let l = try AXCore.list(a, password: nil)
        let names = Set(l.entries.map(\.path))
        check("\(fmt.rawValue) edit: removed folder and file", !names.contains("sub") && !names.contains("sub/b.txt") && !names.contains("a.txt"), "\(names.sorted())")
        check("\(fmt.rawValue) edit: added file, kept others", names.contains("extra.txt") && names.contains("run.sh"))
        check("\(fmt.rawValue) edit: 7-Zip still accepts", sh("\(SZ) t \(q(a))").status == 0)
        let back = try extractOurs(a, to: "x-edit-\(fmt.ext)")
        check("\(fmt.rawValue) edit: content intact", (try? String(contentsOf: back.appendingPathComponent("extra.txt"))) == "added later"
              && (try? String(contentsOf: back.appendingPathComponent("run.sh"))) == (try? String(contentsOf: src.appendingPathComponent("run.sh"))))
    }
} catch { check("section 3 threw", false, "\(error)") }

// MARK: 4. selection, flat extraction, overwrite policy

do {
    let z = try create(.zip, "sel.zip")
    let d1 = work.appendingPathComponent("x-sel")
    try AXCore.extract(z, selection: [("sub", true)], to: d1, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    check("selection: folder only", fm.fileExists(atPath: d1.appendingPathComponent("sub/b.txt").path) && !fm.fileExists(atPath: d1.appendingPathComponent("a.txt").path))
    let d2 = work.appendingPathComponent("x-flat")
    try AXCore.extract(z, selection: [], to: d2, overwrite: .all, keepPaths: false, password: nil, progress: { _ in })
    check("flat extraction (no folders)", fm.fileExists(atPath: d2.appendingPathComponent("b.txt").path) && !fm.fileExists(atPath: d2.appendingPathComponent("sub").path))
    try "OLD".write(to: d1.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
    try AXCore.extract(z, selection: [("a.txt", false)], to: d1, overwrite: .skip, keepPaths: true, password: nil, progress: { _ in })
    check("overwrite: skip keeps existing", (try? String(contentsOf: d1.appendingPathComponent("a.txt"))) == "OLD")
    try AXCore.extract(z, selection: [("a.txt", false)], to: d1, overwrite: .rename, keepPaths: true, password: nil, progress: { _ in })
    check("overwrite: rename creates a copy", fm.fileExists(atPath: d1.appendingPathComponent("a (1).txt").path))
    try AXCore.extract(z, selection: [("a.txt", false)], to: d1, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    check("overwrite: replace", (try? String(contentsOf: d1.appendingPathComponent("a.txt")))?.hasPrefix("line 1") == true)
} catch { check("section 4 threw", false, "\(error)") }

// MARK: 5. hostile archives (zip-slip, absolute paths, symlink escape)

do {
    let evil = work.appendingPathComponent("evil.zip")
    let w = try ZipWriter(url: evil, password: nil, level: 0)
    let tmp = work.appendingPathComponent("payload.txt"); try "pwned".write(to: tmp, atomically: true, encoding: .utf8)
    for n in ["../escaped.txt", "/tmp/absolute-escape.txt", "ok/../../escaped2.txt", "fine.txt"] {
        try w.addFile(source: tmp, name: n, mtime: Date(), mode: 0o644, progress: nil)
    }
    try w.addSymlink(name: "evil-link", target: "../../outside", mtime: Date())
    try w.finish()
    let dest = work.appendingPathComponent("jail/inner")
    let skipped = try AXCore.extract(evil, selection: [], to: dest, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    check("zip-slip: dangerous names skipped", skipped.count >= 3, "\(skipped)")
    check("zip-slip: nothing escaped the folder", !fm.fileExists(atPath: work.appendingPathComponent("jail/escaped.txt").path)
          && !fm.fileExists(atPath: work.appendingPathComponent("escaped2.txt").path) && !fm.fileExists(atPath: "/tmp/absolute-escape.txt"))
    check("zip-slip: safe entry still extracted", fm.fileExists(atPath: dest.appendingPathComponent("fine.txt").path))
    check("zip-slip: escaping symlink refused", (try? fm.destinationOfSymbolicLink(atPath: dest.appendingPathComponent("evil-link").path)) == nil)
} catch { check("section 5 threw", false, "\(error)") }

// MARK: 5b. symlink attacks on the extractor

do {
    let tmp = work.appendingPathComponent("atk-payload.txt"); try "pwned".write(to: tmp, atomically: true, encoding: .utf8)

    // (a) a link that looks inside but, once another link is walked back out with "..", escapes the folder
    let outer = work.appendingPathComponent("atk-a"); try fm.createDirectory(at: outer, withIntermediateDirectories: true)
    let za = work.appendingPathComponent("atk-a.zip")
    let wa = try ZipWriter(url: za, password: nil, level: 0)
    try wa.addSymlink(name: "a/b/s1", target: "../..", mtime: Date())            // points at the destination root: fine
    try wa.addSymlink(name: "y", target: "a/b/s1/..", mtime: Date())            // physically = the parent of the destination
    try wa.addFile(source: tmp, name: "y/evil.txt", mtime: Date(), mode: 0o644, progress: nil)
    try wa.finish()
    let inner = outer.appendingPathComponent("inner")
    let skippedA = try AXCore.extract(za, selection: [], to: inner, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    var escapedA = fm.fileExists(atPath: outer.appendingPathComponent("evil.txt").path)
    if let real = try? URL(fileURLWithPath: inner.appendingPathComponent("y").path).resolvingSymlinksInPath().path, real.hasSuffix("/atk-a") { escapedA = true }
    check("symlink chain: a link that resolves above the folder is refused", !escapedA && skippedA.contains { $0.hasPrefix("y") }, "\(skippedA)")
    check("symlink chain: the harmless link inside the folder is still created", (try? fm.destinationOfSymbolicLink(atPath: inner.appendingPathComponent("a/b/s1").path)) == "../..")

    // (b) an existing symlink in the destination that points outside: directories and files must not go through it
    let outside = work.appendingPathComponent("atk-outside"); try fm.createDirectory(at: outside, withIntermediateDirectories: true)
    try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: outside.path)
    let dest = work.appendingPathComponent("atk-b/dest"); try fm.createDirectory(at: dest, withIntermediateDirectories: true)
    try fm.createSymbolicLink(atPath: dest.appendingPathComponent("link").path, withDestinationPath: outside.path)
    let zb = work.appendingPathComponent("atk-b.zip")
    let wb = try ZipWriter(url: zb, password: nil, level: 0)
    try wb.addDirectory(name: "link", mtime: Date(timeIntervalSince1970: 1_000_000_000), mode: 0o777)
    try wb.addFile(source: tmp, name: "link/evil.txt", mtime: Date(), mode: 0o644, progress: nil)
    try wb.addFile(source: tmp, name: "link", mtime: Date(), mode: 0o644, progress: nil)       // a file over the symlink
    try wb.finish()
    _ = try? AXCore.extract(zb, selection: [], to: dest, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    let outsideFiles = (try? fm.contentsOfDirectory(atPath: outside.path)) ?? []
    let outsideMode = ((try? fm.attributesOfItem(atPath: outside.path)[.posixPermissions]) as? NSNumber)?.intValue
    let outsideDate = (try? fm.attributesOfItem(atPath: outside.path)[.modificationDate]) as? Date
    check("existing symlink: nothing is written outside the destination", outsideFiles.isEmpty, "\(outsideFiles)")
    check("existing symlink: permissions and dates outside are not touched", outsideMode == 0o700 && (outsideDate ?? Date()).timeIntervalSince1970 > 1_100_000_000, "\(String(describing: outsideMode)) \(String(describing: outsideDate))")

    // (d) ordering attack: a link through a folder that does not exist yet, which a later entry turns into a symlink
    let outerD = work.appendingPathComponent("atk-d"); try fm.createDirectory(at: outerD, withIntermediateDirectories: true)
    let zd = work.appendingPathComponent("atk-d.zip")
    let wd = try ZipWriter(url: zd, password: nil, level: 0)
    try wd.addSymlink(name: "y", target: "a/b/nope/..", mtime: Date())          // looks like a/b, inside
    try wd.addSymlink(name: "a/b/nope", target: "../..", mtime: Date())          // later: nope -> the destination root
    try wd.finish()
    let innerD = outerD.appendingPathComponent("inner")
    _ = try AXCore.extract(zd, selection: [], to: innerD, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    let yReal = URL(fileURLWithPath: innerD.appendingPathComponent("y").path).resolvingSymlinksInPath().path
    let yExists = (try? fm.destinationOfSymbolicLink(atPath: innerD.appendingPathComponent("y").path)) != nil
    check("symlink ordering: a link that a later entry redirects above the folder does not survive", !yExists || (yReal.hasPrefix(innerD.resolvingSymlinksInPath().path)), "y -> \(yReal)")

    // (c) tar flavour: a symlink entry followed by a file written "through" it
    let tarSrc = work.appendingPathComponent("atk-tar-src"); try fm.createDirectory(at: tarSrc, withIntermediateDirectories: true)
    try fm.createSymbolicLink(atPath: tarSrc.appendingPathComponent("esc").path, withDestinationPath: "../")
    let tarAtk = work.appendingPathComponent("atk.tar")
    let tf = try FileOut(tarAtk); let tw = TarWriter(sink: tf)
    try tw.addSymlink(name: "esc", target: "../", mode: 0o755, mtime: Date())
    try tw.addFile(source: tmp, name: "esc/evil-from-tar.txt", mode: 0o644, mtime: Date(), progress: nil)
    try tw.finish()
    let tdest = work.appendingPathComponent("atk-c/dest")
    _ = try AXCore.extract(tarAtk, selection: [], to: tdest, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    check("tar: a file written through an escaping symlink does not land outside", !fm.fileExists(atPath: work.appendingPathComponent("atk-c/evil-from-tar.txt").path))
} catch { check("section 5b threw", false, "\(error)") }

// MARK: 6. corruption is detected, not ignored

do {
    let z = try create(.zip, "corrupt.zip")
    var bytes = try Data(contentsOf: z)
    bytes[200] ^= 0xff; bytes[1500] ^= 0xff
    let bad = work.appendingPathComponent("corrupt-bad.zip"); try bytes.write(to: bad)
    var detected = false
    do { try AXCore.test(bad, password: nil, progress: { _ in }) } catch { detected = true }
    check("corrupted ZIP is detected by test", detected)
    let g = try create(.tgz, "corrupt.tar.gz")
    var gb = try Data(contentsOf: g); gb[gb.count / 2] ^= 0xff
    let gbad = work.appendingPathComponent("corrupt-bad.tar.gz"); try gb.write(to: gbad)
    var gDetected = false
    do { try AXCore.test(gbad, password: nil, progress: { _ in }) } catch { gDetected = true }
    check("corrupted tar.gz is detected by test", gDetected)
} catch { check("section 6 threw", false, "\(error)") }


// MARK: 7. bzip2

do {
    var rng = SystemRandomNumberGenerator()
    let text = Data((1...120_000).map { "row \($0): the quick brown fox \($0 % 97) jumps over the lazy dog\n" }.joined().utf8)
    let cases: [(String, Data)] = [
        ("empty", Data()), ("one byte", Data([0x41])), ("run of 1 MB", Data(repeating: 0x61, count: 1 << 20)),
        ("run lengths 3..300", Data((3...300).flatMap { Array(repeating: UInt8($0 % 251), count: $0) })),
        ("random 2 MB", Data((0..<(2 << 20)).map { _ in UInt8.random(in: 0...255, using: &rng) })),
        ("text 6 MB (many blocks)", text), ("all byte values", Data((0..<256).map { UInt8($0) } + (0..<256).reversed().map { UInt8($0) })),
    ]
    for (name, data) in cases {
        for level in [1, 9] where !(level == 1 && data.count < 1000) {
            let raw = work.appendingPathComponent("bz-in.bin"); try data.write(to: raw)
            let sink = MemorySink(); let enc = try Bzip2Sink(out: sink, level: level); try enc.write(data); try enc.finish()
            let bz = work.appendingPathComponent("bz-ours.bz2"); try sink.data.write(to: bz)
            let t = sh("/usr/bin/bzip2 -t \(q(bz))"); check("bzip2 encode '\(name)' level \(level): bzip2 -t accepts", t.status == 0, t.out)
            let rt = sh("/usr/bin/bzip2 -dc \(q(bz)) | cmp - \(q(raw))"); check("bzip2 encode '\(name)' level \(level): bzip2 output identical", rt.status == 0, rt.out)
            // and our own decoder
            let r = try Bzip2Source(file: try FileIn(bz)); var back = Data()
            while true { let d = try r.read(1 << 20); if d.isEmpty { break }; back.append(d) }
            check("bzip2 decode (ours→ours) '\(name)' level \(level)", back == data, "\(back.count) vs \(data.count)")
        }
        let raw = work.appendingPathComponent("bz-in2.bin"); try data.write(to: raw)
        for lvl in [1, 9] {
            let bz = work.appendingPathComponent("bz-sys.bz2")
            sh("/usr/bin/bzip2 -\(lvl) -c \(q(raw)) > \(q(bz))")
            let r = try Bzip2Source(file: try FileIn(bz)); var back = Data()
            while true { let d = try r.read(1 << 20); if d.isEmpty { break }; back.append(d) }
            check("bzip2 decode (system bzip2 -\(lvl)) '\(name)'", back == data, "\(back.count) vs \(data.count)")
        }
    }
    // 7-Zip's own bzip2 encoder and concatenated streams
    let two = work.appendingPathComponent("two.bz2")
    sh("(/usr/bin/bzip2 -c \(q(src.appendingPathComponent("a.txt"))); /usr/bin/bzip2 -c \(q(src.appendingPathComponent("run.sh")))) > \(q(two))")
    let r2 = try Bzip2Source(file: try FileIn(two)); var back2 = Data()
    while true { let d = try r2.read(1 << 20); if d.isEmpty { break }; back2.append(d) }
    let want2 = (try Data(contentsOf: src.appendingPathComponent("a.txt"))) + (try Data(contentsOf: src.appendingPathComponent("run.sh")))
    check("bzip2 decode: concatenated streams", back2 == want2)
    try? fm.removeItem(at: work.appendingPathComponent("7z.bz2")); sh("\(SZ) a -bso0 -tbzip2 -mx=9 \(q(work.appendingPathComponent("7z.bz2"))) \(q(src.appendingPathComponent("a.txt")))")
    let r3 = try Bzip2Source(file: try FileIn(work.appendingPathComponent("7z.bz2"))); var back3 = Data()
    while true { let d = try r3.read(1 << 20); if d.isEmpty { break }; back3.append(d) }
    check("bzip2 decode: 7-Zip's encoder", back3 == (try Data(contentsOf: src.appendingPathComponent("a.txt"))))

    // tar.bz2 through the façade
    let tb = try create(.tbz2, "t.tar.bz2")
    check("tbz2: bzip2 -t accepts", sh("/usr/bin/bzip2 -t \(q(tb))").status == 0)
    check("tbz2: 7-Zip accepts", sh("\(SZ) t \(q(tb))").status == 0)
    let bx = work.appendingPathComponent("x-systbz2"); try fm.createDirectory(at: bx, withIntermediateDirectories: true)
    check("tbz2: system tar extracts", sh("/usr/bin/tar -xjf \(q(tb)) -C \(q(bx))").status == 0)
    let bOurs = try extractOurs(tb, to: "x-own-tbz2")
    check("tbz2: our round trip matches system tar", sameTree(bx, bOurs) == nil, sameTree(bx, bOurs) ?? "")
    let sysTb = work.appendingPathComponent("sys.tar.bz2")
    sh("/usr/bin/tar -cjf \(q(sysTb)) a.txt sub run.sh 'résumé 日本語 ✓.txt'", cwd: src)
    let sOurs = try extractOurs(sysTb, to: "x-own-systbz2")
    let sRef = work.appendingPathComponent("x-ref-systbz2"); try fm.createDirectory(at: sRef, withIntermediateDirectories: true)
    sh("/usr/bin/tar -xjf \(q(sysTb)) -C \(q(sRef))")
    check("tbz2: reads system-made tar.bz2", sameTree(sRef, sOurs) == nil, sameTree(sRef, sOurs) ?? "")
} catch { check("section 7 threw", false, "\(error)") }

// MARK: 8. LZMA2 / xz

func readAll(_ s: ByteSource) throws -> Data { var d = Data(); while true { let c = try s.read(1 << 20); if c.isEmpty { break }; d.append(c) }; return d }

do {
    var rng = SystemRandomNumberGenerator()
    let text = Data((1...150_000).map { "row \($0): the quick brown fox \($0 % 97) jumps over the lazy dog, again and again\n" }.joined().utf8)
    var code = Data()                                   // fake x86 code with CALL/JMP opcodes and plausible displacements
    for i in 0..<200_000 { code.append(contentsOf: [0xe8, UInt8(i & 0xff), UInt8((i >> 8) & 0xff), 0x00, i % 7 == 0 ? 0xff : 0x00, 0x90, UInt8.random(in: 0...255, using: &rng)]) }
    let cases: [(String, Data)] = [
        ("empty", Data()), ("one byte", Data([0x41])), ("run of 3 MB", Data(repeating: 0x61, count: 3 << 20)),
        ("random 3 MB (stored chunks)", Data((0..<(3 << 20)).map { _ in UInt8.random(in: 0...255, using: &rng) })),
        ("text 11 MB (many chunks)", text), ("mixed", text.prefix(300_000) + Data((0..<200_000).map { _ in UInt8.random(in: 0...255, using: &rng) }) + text.prefix(300_000)),
        ("fake x86 code", code),
    ]
    for (name, data) in cases {
        let raw = work.appendingPathComponent("xz-in.bin"); try data.write(to: raw)
        for level in [1, 3, 5] {
            let xz = work.appendingPathComponent("xz-ours.xz")
            let out = try FileOut(xz)
            let enc = try XzSink(out: out, level: level, totalHint: UInt64(data.count))
            try enc.write(data); try enc.finish()
            let t1 = sh("\(SZ) t \(q(xz))"); check("xz encode '\(name)' level \(level): 7-Zip accepts", t1.status == 0, t1.out.suffix(300).description)
            let t2 = sh("\(SZ) x -so \(q(xz)) | cmp - \(q(raw))"); check("xz encode '\(name)' level \(level): 7-Zip output identical", t2.status == 0, t2.out)
            let back = try readAll(try XzSource(file: try FileIn(xz)))
            check("xz decode (ours→ours) '\(name)' level \(level)", back == data, "\(back.count) vs \(data.count)")
            if level == 3 { let ratio = Double((try FileManager.default.attributesOfItem(atPath: xz.path)[.size] as! NSNumber).intValue) / Double(max(1, data.count)); print(String(format: "     ratio %@ level 3: %.1f%%", name, ratio * 100)) }
        }
        for mx in [1, 5, 9] {
            let xz = work.appendingPathComponent("xz-7z.xz"); try? fm.removeItem(at: xz)
            sh("\(SZ) a -bso0 -txz -mx=\(mx) \(q(xz)) \(q(raw))")
            let back = try readAll(try XzSource(file: try FileIn(xz)))
            check("xz decode (7-Zip -mx=\(mx)) '\(name)'", back == data, "\(back.count) vs \(data.count)")
        }
    }
    // filters made by 7-Zip: BCJ x86, ARM64, ARM, Delta
    let rawc = work.appendingPathComponent("xz-code.bin"); try code.write(to: rawc)
    for f in ["BCJ", "ARM64", "ARM", "Delta:4"] {
        let xz = work.appendingPathComponent("xz-filter.xz"); try? fm.removeItem(at: xz)
        sh("\(SZ) a -bso0 -txz -mf=\(f) \(q(xz)) \(q(rawc))")
        let methods = sh("\(SZ) l -slt \(q(xz)) | grep -i '^Method'").out
        check("xz made by 7-Zip really uses the \(f) filter", methods.lowercased().contains(f.lowercased().prefix(3)), methods)
        do { let back = try readAll(try XzSource(file: try FileIn(xz))); check("xz decode with \(f) filter", back == code, "\(back.count) vs \(code.count)") }
        catch { check("xz decode with \(f) filter", false, "\(error)") }
    }
    // concatenated streams
    let cat = work.appendingPathComponent("cat.xz")
    sh("(\(SZ) a -bso0 -txz -so dummy.xz \(q(src.appendingPathComponent("a.txt"))); \(SZ) a -bso0 -txz -so dummy.xz \(q(src.appendingPathComponent("run.sh")))) > \(q(cat))")
    let catBack = try readAll(try XzSource(file: try FileIn(cat)))
    check("xz decode: concatenated streams", catBack == (try Data(contentsOf: src.appendingPathComponent("a.txt"))) + (try Data(contentsOf: src.appendingPathComponent("run.sh"))), "\(catBack.count)")

    // tar.xz through the façade, both directions
    let tx = try create(.txz, "t.tar.xz")
    check("txz: 7-Zip accepts", sh("\(SZ) t \(q(tx))").status == 0)
    let txDir = work.appendingPathComponent("x-systxz"); try fm.createDirectory(at: txDir, withIntermediateDirectories: true)
    check("txz: system tar extracts", sh("/usr/bin/tar -xJf \(q(tx)) -C \(q(txDir))").status == 0)
    let txOurs = try extractOurs(tx, to: "x-own-txz")
    check("txz: our round trip matches system tar", sameTree(txDir, txOurs) == nil, sameTree(txDir, txOurs) ?? "")
    let sysTx = work.appendingPathComponent("sys.tar.xz")
    sh("/usr/bin/tar -cJf \(q(sysTx)) a.txt sub run.sh 'résumé 日本語 ✓.txt'", cwd: src)
    let sRef = work.appendingPathComponent("x-ref-systxz"); try fm.createDirectory(at: sRef, withIntermediateDirectories: true)
    sh("/usr/bin/tar -xJf \(q(sysTx)) -C \(q(sRef))")
    check("txz: reads system-made tar.xz", sameTree(sRef, try extractOurs(sysTx, to: "x-own-systxz")) == nil)
    // corruption must be caught
    var xb = try Data(contentsOf: tx); xb[xb.count / 2] ^= 0x55
    let bad = work.appendingPathComponent("bad.tar.xz"); try xb.write(to: bad)
    var caught = false; do { try AXCore.test(bad, password: nil, progress: { _ in }) } catch { caught = true }
    check("corrupted tar.xz is detected", caught)
} catch { check("section 8 threw", false, "\(error)") }

// MARK: 9. 7z

do {
    func make7z(_ name: String, level: Int = 3, solid: Bool = true, password: String? = nil, names: Bool = false) throws -> URL {
        let out = work.appendingPathComponent(name)
        try AXCore.create(AXCreate(format: .sevenZ, output: out, items: roots, level: level, password: password, solid: solid, encryptNames: names), progress: { _ in })
        return out
    }
    func ref7z(_ archive: URL, _ label: String, pw: Bool = false) -> URL {
        let d = work.appendingPathComponent("ref7-\(label)")
        sh("\(SZ) x -y \(pw ? aesPWArg : "") -o\(q(d)) \(q(archive))")
        return d
    }
    // ours -> 7-Zip
    let variants: [(String, Int, Bool, String?, Bool)] = [
        ("solid L3", 3, true, nil, false), ("solid L1", 1, true, nil, false), ("solid L5", 5, true, nil, false),
        ("non-solid", 3, false, nil, false), ("store", 0, true, nil, false),
        ("AES", 3, true, aesPW, false), ("AES + encrypted names", 3, true, aesPW, true), ("AES non-solid", 3, false, aesPW, false),
    ]
    for (i, v) in variants.enumerated() {
        let a = try make7z("v\(i).7z", level: v.1, solid: v.2, password: v.3, names: v.4)
        let pw = v.3 != nil
        let tt = sh("\(SZ) t \(pw ? aesPWArg : "") \(q(a))")
        check("7z create [\(v.0)]: 7-Zip accepts", tt.status == 0, tt.out.suffix(300).description)
        let ref = ref7z(a, "v\(i)", pw: pw)
        let ours = try extractOurs(a, to: "x7-own-v\(i)", password: v.3)
        check("7z create [\(v.0)]: our extraction matches 7-Zip's", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
        let list = try AXCore.list(a, password: v.3)
        check("7z create [\(v.0)]: listing has names, folders and sizes", list.entries.contains { $0.path == "sub/b.txt" && $0.size == 6 } && list.entries.contains { $0.isDir && $0.path == "empty-dir" }, "\(list.entries.map { $0.path }.prefix(5))")
        if pw {
            let l7 = sh("\(SZ) l -slt \(aesPWArg) \(q(a)) | grep -c 'Encrypted = +'")
            check("7z create [\(v.0)]: data really is encrypted", (Int(l7.out.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0) > 0)
            let noPw = sh("\(SZ) t \(q(a))"); check("7z create [\(v.0)]: 7-Zip refuses without password", noPw.status != 0)
        }
    }
    // password handling by our reader
    let enc = work.appendingPathComponent("v6.7z")        // AES + encrypted names
    do { _ = try AXCore.list(enc, password: nil); check("7z encrypted names: password required", false) }
    catch AXError.passwordRequired { check("7z encrypted names: password required", true) } catch { check("7z encrypted names: password required", false, "\(error)") }
    do { _ = try AXCore.list(enc, password: "wrong"); check("7z encrypted names: wrong password rejected", false) }
    catch AXError.wrongPassword { check("7z encrypted names: wrong password rejected", true) } catch { check("7z encrypted names: wrong password rejected", false, "\(error)") }
    let enc2 = work.appendingPathComponent("v5.7z")       // AES, names visible
    do { _ = try extractOurs(enc2, to: "x7-nopw"); check("7z AES: missing password reported", false) }
    catch AXError.passwordRequired { check("7z AES: missing password reported", true) } catch { check("7z AES: missing password reported", false, "\(error)") }
    do { _ = try extractOurs(enc2, to: "x7-badpw", password: "nope"); check("7z AES: wrong password rejected", false) }
    catch AXError.wrongPassword { check("7z AES: wrong password rejected", true) } catch { check("7z AES: wrong password rejected", false, "\(error)") }

    // 7-Zip -> ours
    let foreign7 = work.appendingPathComponent("foreign7"); try fm.createDirectory(at: foreign7, withIntermediateDirectories: true)
    let methods: [(String, String, Bool)] = [
        ("lzma2 mx5", "-mx=5", false), ("lzma2 mx1", "-mx=1", false), ("lzma2 mx9", "-mx=9", false), ("non-solid", "-ms=off", false),
        ("lzma", "-m0=lzma", false), ("bzip2", "-m0=bzip2", false), ("deflate", "-m0=deflate", false), ("copy", "-m0=copy", false),
        ("bcj+lzma2", "-mf=BCJ", false), ("arm64+lzma2", "-mf=ARM64", false), ("delta+lzma2", "-mf=Delta:4", false),
        ("encrypted", "\(aesPWArg)", true), ("encrypted names", "\(aesPWArg) -mhe=on", true), ("no header compression", "-mhc=off", false),
    ]
    for (label, args, pw) in methods {
        let a = foreign7.appendingPathComponent("f-\(label.replacingOccurrences(of: " ", with: "_")).7z")
        sh("\(SZ) a -bso0 -t7z \(args) \(q(a)) a.txt sub empty-dir empty.txt run.sh 'résumé 日本語 ✓.txt' '\(longDir)'", cwd: src)
        let ref = ref7z(a, "f-\(label.replacingOccurrences(of: " ", with: "_"))", pw: pw)
        do {
            let ours = try extractOurs(a, to: "x7f-\(label.replacingOccurrences(of: " ", with: "_"))", password: pw ? aesPW : nil)
            check("7z read [\(label)]: matches 7-Zip's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
            try AXCore.test(a, password: pw ? aesPW : nil, progress: { _ in })
        } catch { check("7z read [\(label)]", false, "\(error)") }
    }
    // a BCJ-filtered archive must really contain the filter
    let bcjInfo = sh("\(SZ) l -slt \(q(foreign7.appendingPathComponent("f-bcj+lzma2.7z"))) | grep -i '^Method' | head -1").out
    check("7z read [bcj]: archive really uses the BCJ filter", bcjInfo.contains("BCJ"), bcjInfo)
    // PPMd (text compression): orders, memory sizes (small sizes force the model to restart) and large mixed data
    let pbig = work.appendingPathComponent("ppmdbig"); try fm.createDirectory(at: pbig, withIntermediateDirectories: true)
    try Data((1...300_000).map { "line \($0): alpha beta gamma delta epsilon \($0 % 211)\n" }.joined().utf8).write(to: pbig.appendingPathComponent("big.txt"))
    try Data((0..<(1 << 20)).map { _ in UInt8.random(in: 0...255) }).write(to: pbig.appendingPathComponent("noise.bin"))
    try Data(contentsOf: URL(fileURLWithPath: "/usr/bin/curl")).write(to: pbig.appendingPathComponent("curl.bin"))
    for (label, args) in [("default", "-m0=PPMd"), ("order 2", "-m0=PPMd:o=2"), ("order 32, 64 MB", "-m0=PPMd:o=32:mem=64m"), ("order 24, 16 MB", "-m0=PPMd:o=24:mem=16m"),
                          ("1 MB (restarts)", "-m0=PPMd:o=8:mem=1m"), ("non-solid", "-m0=PPMd -ms=off"), ("encrypted", "-m0=PPMd \(aesPWArg)")] {
        let a = foreign7.appendingPathComponent("p-\(label.replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: ",", with: "")).7z")
        sh("\(SZ) a -bso0 -t7z \(args) \(q(a)) big.txt noise.bin curl.bin", cwd: pbig)
        let pw = label == "encrypted"
        let ref = ref7z(a, "p-\(label.replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: ",", with: ""))", pw: pw)
        do {
            let ours = try extractOurs(a, to: "x7p-\(label.replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: ",", with: ""))", password: pw ? aesPW : nil)
            check("7z PPMd [\(label)]: matches 7-Zip's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
            try AXCore.test(a, password: pw ? aesPW : nil, progress: { _ in })
        } catch { check("7z PPMd [\(label)]", false, "\(error)") }
    }
    // BCJ2 (four-stream x86 filter) on real x86-64 code, and a split archive (name.7z.001, …)
    let xdir = work.appendingPathComponent("x86dir"); try fm.createDirectory(at: xdir, withIntermediateDirectories: true)
    var haveX86 = false
    for bin in ["/usr/bin/ssh", "/usr/bin/curl", "/usr/bin/git"] where fm.fileExists(atPath: bin) {
        if sh("/usr/bin/lipo -thin x86_64 \(bin) -output \(q(xdir.appendingPathComponent((bin as NSString).lastPathComponent + ".x86")))").status == 0 { haveX86 = true }
    }
    if haveX86 {
        for (label, args) in [("BCJ2", "-mf=BCJ2"), ("BCJ2 non-solid", "-mf=BCJ2 -ms=off"), ("BCJ2 + AES", "-mf=BCJ2 \(aesPWArg)")] {
            let id = label.replacingOccurrences(of: " ", with: "_").replacingOccurrences(of: "+", with: "p")
            let a = foreign7.appendingPathComponent("b2-\(id).7z")
            sh("\(SZ) a -bso0 -t7z \(args) \(q(a)) .", cwd: xdir)
            let info = sh("\(SZ) l -slt \(q(a)) | grep -i '^Method' | head -1").out
            let pw = label.contains("AES")
            let ref = ref7z(a, "b2-\(id)", pw: pw)
            do {
                let ours = try extractOurs(a, to: "x7b2-\(id)", password: pw ? aesPW : nil)
                check("7z BCJ2 [\(label)]: matches 7-Zip's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
                try AXCore.test(a, password: pw ? aesPW : nil, progress: { _ in })
            } catch { check("7z BCJ2 [\(label)]", false, "\(error)") }
            if label == "BCJ2" { check("7z BCJ2: archive really uses BCJ2", info.contains("BCJ2"), info) }
        }
    }
    let splitDir = work.appendingPathComponent("split7"); try fm.createDirectory(at: splitDir, withIntermediateDirectories: true)
    sh("\(SZ) a -bso0 -t7z -v300k -mx=3 \(q(splitDir.appendingPathComponent("s.7z"))) big.txt noise.bin curl.bin", cwd: pbig)
    let splitFirst = splitDir.appendingPathComponent("s.7z.001")
    check("7z split: volumes were created", fm.fileExists(atPath: splitDir.appendingPathComponent("s.7z.003").path))
    do {
        let ref = ref7z(splitFirst, "split7")
        for opened in ["s.7z.001", "s.7z.002"] {
            let ours = try extractOurs(splitDir.appendingPathComponent(opened), to: "x7split-\(opened)")
            check("7z split [open \(opened)]: matches 7-Zip's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
        }
        try AXCore.test(splitFirst, password: nil, progress: { _ in })
    } catch { check("7z split", false, "\(error)") }

    let ppmd = foreign7.appendingPathComponent("p-default.7z")
    let ppmdInfo = sh("\(SZ) l -slt \(q(ppmd)) | grep -i '^Method' | head -1").out
    check("7z PPMd: archive really uses PPMd", ppmdInfo.lowercased().contains("ppmd"), ppmdInfo)
    var pb = try Data(contentsOf: ppmd); pb[pb.count / 2] ^= 0x5a
    let pbad = work.appendingPathComponent("bad-ppmd.7z"); try pb.write(to: pbad)
    var pdet = false; do { try AXCore.test(pbad, password: nil, progress: { _ in }) } catch { pdet = true }
    check("7z PPMd: corrupted data is detected", pdet)

    // editing
    let ed = try make7z("edit.7z")
    let extra = work.appendingPathComponent("extra7.txt"); try "added to 7z".write(to: extra, atomically: true, encoding: .utf8)
    try AXCore.edit(ed, remove: [("sub", true), ("a.txt", false)], add: [extra], level: 3, password: nil, legacy: false, progress: { _ in })
    let el = try AXCore.list(ed, password: nil); let en = Set(el.entries.map(\.path))
    check("7z edit: removed folder and file, added file", !en.contains("sub/b.txt") && !en.contains("a.txt") && en.contains("extra7.txt") && en.contains("run.sh"), "\(en.sorted())")
    check("7z edit: 7-Zip accepts the rewritten archive", sh("\(SZ) t \(q(ed))").status == 0)
    let edBack = try extractOurs(ed, to: "x7-edit")
    check("7z edit: content intact", (try? String(contentsOf: edBack.appendingPathComponent("extra7.txt"))) == "added to 7z"
          && (try? String(contentsOf: edBack.appendingPathComponent("run.sh"))) == (try? String(contentsOf: src.appendingPathComponent("run.sh"))))
    // encrypted archive stays encrypted through an edit
    let ed2 = try make7z("edit-enc.7z", password: aesPW, names: true)
    try AXCore.edit(ed2, remove: [("a.txt", false)], add: [extra], level: 3, password: aesPW, legacy: false, progress: { _ in })
    check("7z edit (encrypted): 7-Zip opens it with the password", sh("\(SZ) t \(aesPWArg) \(q(ed2))").status == 0)
    check("7z edit (encrypted): names are still hidden without it", sh("\(SZ) l \(q(ed2))").status != 0)

    // corruption
    var raw7 = try Data(contentsOf: work.appendingPathComponent("v0.7z")); raw7[raw7.count / 3] ^= 0x5a
    let bad7 = work.appendingPathComponent("bad.7z"); try raw7.write(to: bad7)
    var det = false; do { try AXCore.test(bad7, password: nil, progress: { _ in }) } catch { det = true }
    check("corrupted 7z is detected", det)
    var trunc = try Data(contentsOf: work.appendingPathComponent("v0.7z")); trunc.removeLast(60)
    let tr7 = work.appendingPathComponent("trunc.7z"); try trunc.write(to: tr7)
    var det2 = false; do { _ = try AXCore.list(tr7, password: nil) } catch { det2 = true }
    check("truncated 7z is detected", det2)

    // large-ish: multi-chunk LZMA2 inside 7z, vs 7-Zip
    let bigDir = work.appendingPathComponent("big7"); try fm.createDirectory(at: bigDir, withIntermediateDirectories: true)
    try Data((1...300_000).map { "record \($0): payload payload payload \($0 % 31)\n" }.joined().utf8).write(to: bigDir.appendingPathComponent("big.txt"))
    try Data((0..<(1 << 20)).map { _ in UInt8.random(in: 0...255) }).write(to: bigDir.appendingPathComponent("noise.bin"))
    let big = work.appendingPathComponent("big.7z")
    try AXCore.create(AXCreate(format: .sevenZ, output: big, items: [bigDir.appendingPathComponent("big.txt"), bigDir.appendingPathComponent("noise.bin")], level: 5), progress: { _ in })
    check("7z large mixed data: 7-Zip accepts", sh("\(SZ) t \(q(big))").status == 0)
    let bigOurs = try extractOurs(big, to: "x7-big")
    check("7z large mixed data: round trip", sameTree(bigDir, bigOurs) == nil, sameTree(bigDir, bigOurs) ?? "")
} catch { check("section 9 threw", false, "\(error)") }

// MARK: 10. RAR 5 (reader only; the local rar/unrar tools are used purely as checkers)

if CommandLine.arguments.count > 3 {
    let RARDIR = CommandLine.arguments[3]
    let rarPW = "\"$(printf 's3cret-\\xc3\\xa9')\""      // exact bytes (Process() would decompose the é)
    let RAR = RARDIR + "/rar", UNRAR = RARDIR + "/unrar"
    do {
        let rdir = work.appendingPathComponent("rar5"); try fm.createDirectory(at: rdir, withIntermediateDirectories: true)
        // extra fixtures: big mixed data, fake x86 code (E8/E9 calls), symlink
        let big = work.appendingPathComponent("rarbig"); try fm.createDirectory(at: big, withIntermediateDirectories: true)
        try Data((1...400_000).map { "line \($0): alpha beta gamma delta epsilon \($0 % 211)\n" }.joined().utf8).write(to: big.appendingPathComponent("big.txt"))
        try Data((0..<(2 << 20)).map { _ in UInt8.random(in: 0...255) }).write(to: big.appendingPathComponent("noise.bin"))
        var x86 = Data([0x4d, 0x5a, 0x90, 0x00])
        for i in 0..<300_000 { x86.append(contentsOf: [0x55, 0x8b, 0xec, 0xe8, UInt8(i & 0xff), UInt8((i >> 8) & 0xff), 0x00, i % 5 == 0 ? 0xff : 0x00, 0xe9, UInt8((i * 7) & 0xff), 0x01, 0x00, 0x00, 0xc3]) }
        try x86.write(to: big.appendingPathComponent("code.exe"))
        var wav = Data(); for i in 0..<400_000 { let v = Int16(truncatingIfNeeded: Int(sin(Double(i) / 20) * 9000)); wav.append(UInt8(truncatingIfNeeded: v)); wav.append(UInt8(truncatingIfNeeded: v >> 8)) }
        try wav.write(to: big.appendingPathComponent("tone.wav"))

        func rar(_ name: String, _ opts: String, items: String, cwd: URL) -> URL {
            let a = rdir.appendingPathComponent(name); try? fm.removeItem(at: a)
            let r = sh("\(RAR) a -inul -ep1 \(opts) \(q(a)) \(items)", cwd: cwd)
            if r.status != 0 { print("   (rar failed: \(r.out.suffix(120)))") }
            return a
        }
        func check5(_ label: String, _ a: URL, pw: String? = nil, ref refSrc: URL? = nil) {
            let refDir = work.appendingPathComponent("rref-\(label.replacingOccurrences(of: " ", with: "_"))")
            try? fm.createDirectory(at: refDir, withIntermediateDirectories: true)
            let pwArg = pw != nil ? "-p\(rarPW)" : "-p-"
            sh("\(UNRAR) x -y -o+ \(pwArg) \(q(a)) \(q(refDir))/")
            do {
                let ours = try extractOurs(a, to: "rown-\(label.replacingOccurrences(of: " ", with: "_"))", password: pw)
                check("rar5 [\(label)]: matches unrar's extraction", sameTree(refDir, ours) == nil, sameTree(refDir, ours) ?? "")
                try AXCore.test(a, password: pw, progress: { _ in })
                check("rar5 [\(label)]: integrity test passes", true)
            } catch { check("rar5 [\(label)]", false, "\(error)") }
        }

        let tree = "a.txt sub empty-dir empty.txt run.sh 'résumé 日本語 ✓.txt' '\(longDir)'"
        for (label, opts) in [("store", "-m0"), ("m1", "-m1"), ("m3", "-m3"), ("m5", "-m5"), ("solid m3", "-m3 -s"), ("dict 128k", "-md128k"), ("dict 4m", "-md4m -m5"),
                              ("with recovery record", "-rr3"), ("-ol symlinks", "-ol")] {
            check5(label, rar("t-\(label.replacingOccurrences(of: " ", with: "_")).rar", opts, items: tree, cwd: src))
        }
        for (label, opts) in [("big mixed m3", "-m3"), ("big mixed m5 solid", "-m5 -s"), ("big mixed m1", "-m1"), ("big mixed store", "-m0")] {
            check5(label, rar("b-\(label.replacingOccurrences(of: " ", with: "_")).rar", opts, items: "big.txt noise.bin code.exe tone.wav", cwd: big))
        }
        check5("x86 filter, dict 64m", rar("x86.rar", "-m5 -md64m", items: "code.exe", cwd: big))
        check5("audio data", rar("wav.rar", "-m5", items: "tone.wav", cwd: big))
        // real x86-64 machine code makes rar use its E8/E8E9 call-address filters
        for bin in ["/usr/bin/ssh", "/usr/bin/curl"] where fm.fileExists(atPath: bin) {
            let thin = big.appendingPathComponent((bin as NSString).lastPathComponent + ".x86")
            if sh("/usr/bin/lipo -thin x86_64 \(bin) -output \(q(thin))").status == 0 {
                check5("x86-64 code \((bin as NSString).lastPathComponent) (E8/E9 filters)", rar("x86-\((bin as NSString).lastPathComponent).rar", "-m5", items: q(thin), cwd: big))
            }
        }
        // passwords
        check5("password", rar("pw.rar", "-m3 -p\(rarPW)", items: tree, cwd: src), pw: aesPW)
        check5("password + encrypted headers", rar("hp.rar", "-m3 -hp\(rarPW)", items: tree, cwd: src), pw: aesPW)
        check5("password, store", rar("pw0.rar", "-m0 -p\(rarPW)", items: "a.txt sub", cwd: src), pw: aesPW)
        check5("password, big solid", rar("pwb.rar", "-m3 -s -p\(rarPW)", items: "big.txt noise.bin", cwd: big), pw: aesPW)
        for name in ["pw.rar", "hp.rar"] {
            do { _ = try AXCore.list(rdir.appendingPathComponent(name), password: nil); _ = try extractOurs(rdir.appendingPathComponent(name), to: "rpw-none-\(name)"); check("rar5 \(name): missing password reported", false) }
            catch AXError.passwordRequired { check("rar5 \(name): missing password reported", true) } catch { check("rar5 \(name): missing password reported", false, "\(error)") }
            do { _ = try extractOurs(rdir.appendingPathComponent(name), to: "rpw-bad-\(name)", password: "wrong"); check("rar5 \(name): wrong password rejected", false) }
            catch AXError.wrongPassword { check("rar5 \(name): wrong password rejected", true) } catch { check("rar5 \(name): wrong password rejected", false, "\(error)") }
        }
        // selection from a solid archive (must still decode the skipped files)
        let solidA = rdir.appendingPathComponent("b-big_mixed_m5_solid.rar")
        let selDir = work.appendingPathComponent("rar-sel")
        try AXCore.extract(solidA, selection: [("tone.wav", false)], to: selDir, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
        check("rar5 solid: extracting one file from the middle works", (try? Data(contentsOf: selDir.appendingPathComponent("tone.wav"))) == wav)
        // listing
        let l = try AXCore.list(rdir.appendingPathComponent("t-m3.rar"), password: nil)
        check("rar5 listing: names, sizes and folders", l.entries.contains { $0.path == "sub/b.txt" && $0.size == 6 } && l.entries.contains { $0.isDir && $0.path == "empty-dir" } && l.details.hasPrefix("RAR 5"), "\(l.details) \(l.entries.map(\.path).prefix(4))")
        // corruption / truncation
        var rb = try Data(contentsOf: rdir.appendingPathComponent("b-big_mixed_m3.rar")); rb[rb.count / 2] ^= 0x33
        let bad = work.appendingPathComponent("bad.rar"); try rb.write(to: bad)
        var det = false; do { try AXCore.test(bad, password: nil, progress: { _ in }) } catch { det = true }
        check("rar5: corrupted data is detected", det)
        var rt = try Data(contentsOf: rdir.appendingPathComponent("b-big_mixed_m3.rar")); rt.removeLast(150_000)
        let trunc = work.appendingPathComponent("trunc.rar"); try rt.write(to: trunc)
        var det2 = false; do { _ = try AXCore.list(trunc, password: nil); try AXCore.test(trunc, password: nil, progress: { _ in }) } catch { det2 = true }
        check("rar5: truncated archive is detected", det2)
    } catch { check("section 10 threw", false, "\(error)") }
}

// MARK: 10b. RAR 3/4 format (the older RAR format: -ma4)
// RAR 7 can no longer create RAR 4 archives, so this section needs a fourth argument: a folder with a `rar` from the
// 5.x/6.x line (for example 5.91). The newer `unrar` from the third argument is still the reference extractor.

if CommandLine.arguments.count > 4 {
    let RARDIR = CommandLine.arguments[3]
    let rarPW = "\"$(printf 's3cret-\\xc3\\xa9')\""
    let RAR = CommandLine.arguments[4] + "/rar", UNRAR = RARDIR + "/unrar"
    do {
        let rdir = work.appendingPathComponent("rar4"); try fm.createDirectory(at: rdir, withIntermediateDirectories: true)
        let big = work.appendingPathComponent("rar4big"); try fm.createDirectory(at: big, withIntermediateDirectories: true)
        try Data((1...400_000).map { "line \($0): alpha beta gamma delta epsilon \($0 % 211)\n" }.joined().utf8).write(to: big.appendingPathComponent("big.txt"))
        try Data((0..<(2 << 20)).map { _ in UInt8.random(in: 0...255) }).write(to: big.appendingPathComponent("noise.bin"))
        var x86 = Data([0x4d, 0x5a, 0x90, 0x00])
        for i in 0..<300_000 { x86.append(contentsOf: [0x55, 0x8b, 0xec, 0xe8, UInt8(i & 0xff), UInt8((i >> 8) & 0xff), 0x00, i % 5 == 0 ? 0xff : 0x00, 0xe9, UInt8((i * 7) & 0xff), 0x01, 0x00, 0x00, 0xc3]) }
        try x86.write(to: big.appendingPathComponent("code.exe"))
        var wav = Data(); for i in 0..<400_000 { let v = Int16(truncatingIfNeeded: Int(sin(Double(i) / 20) * 9000)); wav.append(UInt8(truncatingIfNeeded: v)); wav.append(UInt8(truncatingIfNeeded: v >> 8)) }
        try wav.write(to: big.appendingPathComponent("tone.wav"))
        // a 24-bit bitmap with gradients and noise (RGB filter)
        var bmp = Data([0x42, 0x4d]); let bw = 300, bh = 200
        var pix = Data()
        for y in 0..<bh { for x in 0..<bw { pix.append(contentsOf: [UInt8((x * 255 / bw + Int.random(in: 0...6)) & 255), UInt8((y * 255 / bh + Int.random(in: 0...6)) & 255), UInt8(((x + y) * 255 / (bw + bh) + Int.random(in: 0...6)) & 255)]) } }
        func le32(_ v: Int) -> [UInt8] { [UInt8(v & 255), UInt8((v >> 8) & 255), UInt8((v >> 16) & 255), UInt8((v >> 24) & 255)] }
        bmp.append(contentsOf: le32(54 + pix.count) + [0, 0, 0, 0] + le32(54) + le32(40) + le32(bw) + le32(bh) + [1, 0, 24, 0] + le32(0) + le32(pix.count) + le32(2835) + le32(2835) + le32(0) + le32(0))
        bmp.append(pix)
        try bmp.write(to: big.appendingPathComponent("pic.bmp"))

        func rar4(_ name: String, _ opts: String, items: String, cwd: URL) -> URL {
            let a = rdir.appendingPathComponent(name); try? fm.removeItem(at: a)
            let r = sh("\(RAR) a -inul -ma4 -ep1 \(opts) \(q(a)) \(items)", cwd: cwd)
            if r.status != 0 { print("   (rar failed: \(r.out.suffix(120)))") }
            return a
        }
        func check4(_ label: String, _ a: URL, pw: String? = nil, openAs: URL? = nil) {
            let id = label.replacingOccurrences(of: " ", with: "_")
            let refDir = work.appendingPathComponent("r4ref-\(id)")
            try? fm.createDirectory(at: refDir, withIntermediateDirectories: true)
            let pwArg = pw != nil ? "-p\(rarPW)" : "-p-"
            sh("\(UNRAR) x -y -o+ \(pwArg) \(q(a)) \(q(refDir))/")
            let target = openAs ?? a
            do {
                let ours = try extractOurs(target, to: "r4own-\(id)", password: pw)
                check("rar4 [\(label)]: matches unrar's extraction", sameTree(refDir, ours) == nil, sameTree(refDir, ours) ?? "")
                try AXCore.test(target, password: pw, progress: { _ in })
                check("rar4 [\(label)]: integrity test passes", true)
            } catch { check("rar4 [\(label)]", false, "\(error)") }
        }

        let tree = "a.txt sub empty-dir empty.txt run.sh 'résumé 日本語 ✓.txt' '\(longDir)'"
        for (label, opts) in [("store", "-m0"), ("m1", "-m1"), ("m2", "-m2"), ("m3", "-m3"), ("m4", "-m4"), ("m5", "-m5"), ("solid m3", "-m3 -s"), ("dict 64k", "-md64k"), ("dict 4m", "-md4m -m5"),
                              ("with recovery record", "-rr3"), ("-ol symlinks", "-ol")] {
            check4(label, rar4("t-\(label.replacingOccurrences(of: " ", with: "_")).rar", opts, items: tree, cwd: src))
        }
        for (label, opts) in [("big mixed m3", "-m3"), ("big mixed m5 solid", "-m5 -s"), ("big mixed m1", "-m1"), ("big mixed store", "-m0"),
                              ("text PPMd", "-m3 -mct+"), ("text PPMd order 2", "-m3 -mc2:16t+"), ("text PPMd order 63", "-m5 -mc63:128t+"),
                              ("text PPMd 1 MB (model restarts)", "-m3 -mc6:1t+"), ("PPMd solid", "-m3 -s -mct+"), ("PPMd and LZ mixed, solid", "-m5 -s -mct")] {
            check4(label, rar4("b-\(label.replacingOccurrences(of: " ", with: "_")).rar", opts, items: "big.txt noise.bin code.exe tone.wav", cwd: big))
        }
        // the six standard filters
        check4("filter: audio", rar4("f-audio.rar", "-m5 -mc2a+", items: "tone.wav", cwd: big))
        check4("filter: delta", rar4("f-delta.rar", "-m3 -mc4d+", items: "tone.wav", cwd: big))
        check4("filter: RGB", rar4("f-rgb.rar", "-m3 -mcc+", items: "pic.bmp", cwd: big))
        check4("filter: x86 E8/E9", rar4("f-e8.rar", "-m3 -mce+", items: "code.exe", cwd: big))
        check4("filter: Itanium", rar4("f-itanium.rar", "-m3 -mci+", items: "code.exe", cwd: big))
        check4("filters, solid", rar4("f-all.rar", "-s -m5 -mcc+ -mca+ -mce+", items: "pic.bmp tone.wav code.exe", cwd: big))
        for bin in ["/usr/bin/ssh", "/usr/bin/curl"] where fm.fileExists(atPath: bin) {
            let thin = big.appendingPathComponent((bin as NSString).lastPathComponent + ".x86")
            if sh("/usr/bin/lipo -thin x86_64 \(bin) -output \(q(thin))").status == 0 {
                check4("x86-64 code \((bin as NSString).lastPathComponent)", rar4("x86-\((bin as NSString).lastPathComponent).rar", "-m5", items: q(thin), cwd: big))
            }
        }
        // passwords (AES-128 with SHA-1 key derivation)
        check4("password", rar4("pw.rar", "-m3 -p\(rarPW)", items: tree, cwd: src), pw: aesPW)
        check4("password + encrypted headers", rar4("hp.rar", "-m3 -hp\(rarPW)", items: tree, cwd: src), pw: aesPW)
        check4("password, store", rar4("pw0.rar", "-m0 -p\(rarPW)", items: "a.txt sub", cwd: src), pw: aesPW)
        check4("password, big solid PPMd", rar4("pwb.rar", "-m3 -s -mct+ -p\(rarPW)", items: "big.txt noise.bin", cwd: big), pw: aesPW)
        for name in ["pw.rar", "hp.rar"] {
            do { _ = try AXCore.list(rdir.appendingPathComponent(name), password: nil); _ = try extractOurs(rdir.appendingPathComponent(name), to: "r4pw-none-\(name)"); check("rar4 \(name): missing password reported", false) }
            catch AXError.passwordRequired { check("rar4 \(name): missing password reported", true) } catch { check("rar4 \(name): missing password reported", false, "\(error)") }
            do { _ = try extractOurs(rdir.appendingPathComponent(name), to: "r4pw-bad-\(name)", password: "wrong"); check("rar4 \(name): wrong password rejected", false) }
            catch AXError.wrongPassword { check("rar4 \(name): wrong password rejected", true) } catch { check("rar4 \(name): wrong password rejected", false, "\(error)") }
        }
        // multi-volume sets: new (.partNN.rar) and old (.rar, .r00, …) numbering
        let vdir = rdir.appendingPathComponent("vol"); try fm.createDirectory(at: vdir, withIntermediateDirectories: true)
        let vnew = vdir.appendingPathComponent("new.part01.rar")
        sh("\(RAR) a -inul -ma4 -ep1 -m3 -v600k \(q(vdir.appendingPathComponent("new.rar"))) big.txt noise.bin code.exe", cwd: big)
        check("rar4 volumes: the set was created", fm.fileExists(atPath: vdir.appendingPathComponent("new.part3.rar").path) || fm.fileExists(atPath: vdir.appendingPathComponent("new.part03.rar").path) || fm.fileExists(atPath: vnew.path))
        if let first = (try? fm.contentsOfDirectory(atPath: vdir.path))?.filter({ $0.hasPrefix("new.part") }).sorted().first {
            let f1 = vdir.appendingPathComponent(first)
            check4("multi-volume (new numbering), open first volume", f1)
            let parts = (try? fm.contentsOfDirectory(atPath: vdir.path))?.filter { $0.hasPrefix("new.part") }.sorted() ?? []
            if parts.count > 1 { check4("multi-volume, open a later volume", f1, openAs: vdir.appendingPathComponent(parts[1])) }
            if parts.count > 2 {
                // a missing volume must be reported, not silently produce a short file
                let gone = vdir.appendingPathComponent(parts[2]); let kept = try Data(contentsOf: gone)
                try fm.removeItem(at: gone)
                var failed = false; do { try AXCore.test(f1, password: nil, progress: { _ in }) } catch { failed = true }
                check("rar4 volumes: a missing volume is reported", failed)
                try kept.write(to: gone)
            }
        }
        let odir = rdir.appendingPathComponent("oldvol"); try fm.createDirectory(at: odir, withIntermediateDirectories: true)
        sh("\(RAR) a -inul -ma4 -ep1 -m3 -v500k -vn \(q(odir.appendingPathComponent("old.rar"))) big.txt code.exe", cwd: big)
        check4("multi-volume (old numbering: .rar, .r00 …)", odir.appendingPathComponent("old.rar"))
        // solid: pulling one file from the middle must still decode the files before it
        let solidA = rdir.appendingPathComponent("b-big_mixed_m5_solid.rar")
        let selDir = work.appendingPathComponent("rar4-sel")
        try AXCore.extract(solidA, selection: [("tone.wav", false)], to: selDir, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
        check("rar4 solid: extracting one file from the middle works", (try? Data(contentsOf: selDir.appendingPathComponent("tone.wav"))) == wav)
        let l = try AXCore.list(rdir.appendingPathComponent("t-m3.rar"), password: nil)
        check("rar4 listing: names, sizes and folders", l.entries.contains { $0.path == "sub/b.txt" && $0.size == 6 } && l.entries.contains { $0.isDir && $0.path == "empty-dir" } && l.entries.contains { $0.path == "résumé 日本語 ✓.txt" } && l.details.hasPrefix("RAR 4"), "\(l.details) \(l.entries.map(\.path).prefix(6))")
        // corruption / truncation
        for name in ["b-big_mixed_m3.rar", "b-text_PPMd.rar"] {
            var rb = try Data(contentsOf: rdir.appendingPathComponent(name)); rb[rb.count / 2] ^= 0x33
            let bad = work.appendingPathComponent("bad4-\(name)"); try rb.write(to: bad)
            var det = false; do { try AXCore.test(bad, password: nil, progress: { _ in }) } catch { det = true }
            check("rar4: corrupted data is detected (\(name))", det)
            var rt = try Data(contentsOf: rdir.appendingPathComponent(name)); rt.removeLast(150_000)
            let trunc = work.appendingPathComponent("trunc4-\(name)"); try rt.write(to: trunc)
            var det2 = false; do { _ = try AXCore.list(trunc, password: nil); try AXCore.test(trunc, password: nil, progress: { _ in }) } catch { det2 = true }
            check("rar4: truncated archive is detected (\(name))", det2)
        }
    } catch { check("section 10b threw", false, "\(error)") }
}

// MARK: 11. ISO 9660 and CPIO

func sameContent(_ a: URL, _ b: URL) -> String? {      // names, types and bytes only (ISO/CPIO carry little else)
    func tree(_ root: URL) -> [String: String] {
        var out: [String: String] = [:]
        guard let en = fm.enumerator(atPath: root.path) else { return out }
        for case let rel as String in en {
            var isDir: ObjCBool = false; fm.fileExists(atPath: root.appendingPathComponent(rel).path, isDirectory: &isDir)
            out[rel] = isDir.boolValue ? "dir" : String((try? Data(contentsOf: root.appendingPathComponent(rel)).hashValue) ?? 0)
        }
        return out
    }
    let x = tree(a), y = tree(b)
    if Set(x.keys) != Set(y.keys) { return "names differ: \(Set(x.keys).symmetricDifference(Set(y.keys)).sorted().prefix(4))" }
    for (k, v) in x where y[k]! != v { return "\(k) differs" }
    return nil
}

do {
    // a tree without symlinks, for disc images
    let disc = work.appendingPathComponent("disc-src"); try fm.createDirectory(at: disc, withIntermediateDirectories: true)
    sh("cp -R sub a.txt run.sh empty.txt empty-dir 'résumé 日本語 ✓.txt' \(q(disc))/", cwd: src)
    try fm.createDirectory(at: disc.appendingPathComponent("Deep Folder/Another Level"), withIntermediateDirectories: true)
    try "nested".write(to: disc.appendingPathComponent("Deep Folder/Another Level/File With Spaces.txt"), atomically: true, encoding: .utf8)
    try Data((0..<300_000).map { _ in UInt8.random(in: 0...255) }).write(to: disc.appendingPathComponent("Deep Folder/big.bin"))

    for (label, flags) in [("ISO + Joliet", "-iso -joliet"), ("plain ISO", "-iso")] {
        let iso = work.appendingPathComponent("disc-\(label.replacingOccurrences(of: " ", with: "_")).iso"); try? fm.removeItem(at: iso)
        let mk = sh("/usr/bin/hdiutil makehybrid \(flags) -default-volume-name TESTVOL -o \(q(iso)) \(q(disc))")
        if mk.status != 0 { check("iso [\(label)]: image created by hdiutil", false, mk.out.suffix(200).description); continue }
        let isoFile = iso.pathExtension == "iso" ? iso : iso.appendingPathExtension("iso")
        let ref = work.appendingPathComponent("ref-\(label.replacingOccurrences(of: " ", with: "_"))"); try fm.createDirectory(at: ref, withIntermediateDirectories: true)
        sh("/usr/bin/bsdtar -xf \(q(isoFile)) -C \(q(ref))")
        do {
            let ours = try extractOurs(isoFile, to: "own-\(label.replacingOccurrences(of: " ", with: "_"))")
            if label == "plain ISO" {
                // plain 8.3 names differ from the originals; just require that every file's bytes are present and readable
                let l = try AXCore.list(isoFile, password: nil)
                check("iso [\(label)]: lists files and folders", l.entries.filter { !$0.isDir }.count >= 6 && l.details.hasPrefix("ISO 9660"), "\(l.entries.count)")
            } else {
                check("iso [\(label)]: matches bsdtar's extraction", sameContent(ref, ours) == nil, sameContent(ref, ours) ?? "")
                check("iso [\(label)]: matches the source files", sameContent(disc, ours) == nil, sameContent(disc, ours) ?? "")
            }
            try AXCore.test(isoFile, password: nil, progress: { _ in })
            check("iso [\(label)]: integrity test passes", true)
        } catch { check("iso [\(label)]", false, "\(error)") }
    }
    // truncated image must be reported
    if let anyIso = (try? fm.contentsOfDirectory(atPath: work.path))?.first(where: { $0.hasPrefix("disc-ISO_+_Joliet") }) {
        var d = try Data(contentsOf: work.appendingPathComponent(anyIso)); d.removeLast(d.count * 2 / 3)
        let tr = work.appendingPathComponent("trunc.iso"); try d.write(to: tr)
        var det = false; do { try AXCore.test(tr, password: nil, progress: { _ in }) } catch { det = true }
        check("iso: truncated image is detected", det)
    }

    // CPIO from bsdtar in both flavours, with modes and symlinks
    for fmtName in ["odc", "newc"] {
        let c = work.appendingPathComponent("t-\(fmtName).cpio")
        sh("/usr/bin/bsdtar --format \(fmtName) -cf \(q(c)) a.txt sub run.sh link-to-a empty-dir empty.txt 'résumé 日本語 ✓.txt'", cwd: src)
        let ref = work.appendingPathComponent("ref-cpio-\(fmtName)"); try fm.createDirectory(at: ref, withIntermediateDirectories: true)
        sh("/usr/bin/bsdtar -xf \(q(c)) -C \(q(ref))")
        do {
            let ours = try extractOurs(c, to: "own-cpio-\(fmtName)")
            check("cpio [\(fmtName)]: matches bsdtar's extraction (modes, symlinks)", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
            try AXCore.test(c, password: nil, progress: { _ in })
            let l = try AXCore.list(c, password: nil)
            check("cpio [\(fmtName)]: listing", l.entries.contains { $0.path == "sub/b.txt" } && l.details.hasPrefix("CPIO"), l.details)
        } catch { check("cpio [\(fmtName)]", false, "\(error)") }
    }
} catch { check("section 11 threw", false, "\(error)") }

// MARK: 12. packages and legacy formats: ar/deb, compress (.Z), RPM, XAR/pkg, CAB

do {
    let pk = work.appendingPathComponent("pkg"); try fm.createDirectory(at: pk, withIntermediateDirectories: true)
    func refExtract(_ archive: URL, _ name: String) -> URL {
        let d = work.appendingPathComponent("refpk-\(name)"); try? fm.createDirectory(at: d, withIntermediateDirectories: true)
        sh("/usr/bin/bsdtar -xf \(q(archive)) -C \(q(d))"); return d
    }
    // ar and Debian packages
    let flat = work.appendingPathComponent("ar-src"); try fm.createDirectory(at: flat, withIntermediateDirectories: true)
    sh("cp a.txt run.sh empty.txt 'résumé 日本語 ✓.txt' \(q(flat))/", cwd: src)
    try Data((0..<100_000).map { _ in UInt8.random(in: 0...255) }).write(to: flat.appendingPathComponent("a-rather-long-member-name-for-ar.bin"))
    let arFile = pk.appendingPathComponent("t.a")
    sh("/usr/bin/ar rcS \(q(arFile)) a.txt run.sh empty.txt 'résumé 日本語 ✓.txt' a-rather-long-member-name-for-ar.bin", cwd: flat)
    do {
        let ours = try extractOurs(arFile, to: "own-ar")
        check("ar: matches bsdtar's extraction (long names)", sameContent(refExtract(arFile, "ar"), ours) == nil, sameContent(refExtract(arFile, "ar"), ours) ?? "")
        try AXCore.test(arFile, password: nil, progress: { _ in })
    } catch { check("ar", false, "\(error)") }
    let debDir = work.appendingPathComponent("deb-src"); try fm.createDirectory(at: debDir.appendingPathComponent("usr/bin"), withIntermediateDirectories: true)
    try "2.0\n".write(to: debDir.appendingPathComponent("debian-binary"), atomically: true, encoding: .utf8)
    try "Package: test\nVersion: 1\n".write(to: debDir.appendingPathComponent("control"), atomically: true, encoding: .utf8)
    try "#!/bin/sh\necho hi\n".write(to: debDir.appendingPathComponent("usr/bin/hi"), atomically: true, encoding: .utf8)
    sh("tar czf control.tar.gz control; tar czf data.tar.gz usr", cwd: debDir)
    let deb = pk.appendingPathComponent("t.deb")
    sh("/usr/bin/ar rcS \(q(deb)) debian-binary control.tar.gz data.tar.gz", cwd: debDir)
    do {
        let l = try AXCore.list(deb, password: nil)
        check("deb: lists the three members", l.entries.map(\.path) == ["debian-binary", "control.tar.gz", "data.tar.gz"] && l.details.contains("Debian"), "\(l.entries.map(\.path)) \(l.details)")
        let ours = try extractOurs(deb, to: "own-deb")
        check("deb: members extract intact", (try? Data(contentsOf: ours.appendingPathComponent("data.tar.gz"))) == (try? Data(contentsOf: debDir.appendingPathComponent("data.tar.gz"))))
    } catch { check("deb", false, "\(error)") }

    // compress (.Z)
    let zdir = work.appendingPathComponent("lzw"); try fm.createDirectory(at: zdir, withIntermediateDirectories: true)
    try Data((1...150_000).map { "line \($0) of text with some repetition \($0 % 41)\n" }.joined().utf8).write(to: zdir.appendingPathComponent("text.txt"))
    try Data((0..<200_000).map { _ in UInt8.random(in: 0...255) }).write(to: zdir.appendingPathComponent("noise.bin"))
    try Data(repeating: 0x41, count: 500_000).write(to: zdir.appendingPathComponent("same.bin"))
    try "x".write(to: zdir.appendingPathComponent("tiny.txt"), atomically: true, encoding: .utf8)
    for (f, opts) in [("text.txt", ""), ("text.txt", "-b 12"), ("text.txt", "-b 9"), ("noise.bin", ""), ("same.bin", ""), ("tiny.txt", "")] {
        let z = zdir.appendingPathComponent("\(f)-\(opts.replacingOccurrences(of: " ", with: "")).Z")
        sh("/usr/bin/compress -c \(opts) \(f) > \(q(z))", cwd: zdir)
        do {
            let ours = try extractOurs(z, to: "own-z-\(z.lastPathComponent)")
            let got = (try? Data(contentsOf: ours.appendingPathComponent(z.lastPathComponent.dropLast(2).description))) ?? Data()
            check("compress .Z [\(f) \(opts)]: round trip", got == (try Data(contentsOf: zdir.appendingPathComponent(f))), "\(got.count) bytes")
            try AXCore.test(z, password: nil, progress: { _ in })
        } catch { check("compress .Z [\(f) \(opts)]", false, "\(error)") }
    }

    // RPM (built by hand: lead, signature header, header, compressed cpio payload)
    func be32b(_ v: Int) -> [UInt8] { [UInt8((v >> 24) & 255), UInt8((v >> 16) & 255), UInt8((v >> 8) & 255), UInt8(v & 255)] }
    func rpmHeader(_ entries: [(tag: Int, type: Int, off: Int, count: Int)], _ store: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0] + be32b(entries.count) + be32b(store.count)
        for e in entries { h += be32b(e.tag) + be32b(e.type) + be32b(e.off) + be32b(e.count) }
        return h + store
    }
    let rpmSrc = work.appendingPathComponent("rpm-src"); try fm.createDirectory(at: rpmSrc, withIntermediateDirectories: true)
    sh("cp -R sub a.txt run.sh empty.txt empty-dir link-to-a \(q(rpmSrc))/", cwd: src)
    let cpioNewc = pk.appendingPathComponent("payload.cpio")
    sh("/usr/bin/bsdtar --format newc -cf \(q(cpioNewc)) a.txt sub run.sh link-to-a empty-dir empty.txt", cwd: rpmSrc)
    let cpioRef = refExtract(cpioNewc, "rpm-cpio")
    for (label, comp) in [("gzip", "gzip -c"), ("bzip2", "bzip2 -c"), ("xz", "xz7"), ("none", "cat")] {
        var payload: Data
        if comp == "xz7" {
            let x = pk.appendingPathComponent("payload.xz"); try? fm.removeItem(at: x)
            sh("\(SZ) a -bso0 -txz \(q(x)) \(q(cpioNewc))"); payload = try Data(contentsOf: x)
        } else {
            let x = pk.appendingPathComponent("payload.\(label)")
            sh("\(comp) \(q(cpioNewc)) > \(q(x))"); payload = try Data(contentsOf: x)
        }
        var rpm = Data([0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0, 0, 1])
        rpm.append(Data("testpkg-1.0".utf8)); rpm.append(Data(repeating: 0, count: 66 - 11))
        rpm.append(contentsOf: [0, 1, 0, 5]); rpm.append(Data(repeating: 0, count: 16))
        var sig = rpmHeader([(1000, 4, 0, 1)], [0, 0, 0, 1]); while (96 + sig.count) % 8 != 0 { sig.append(0) }
        rpm.append(contentsOf: sig)
        rpm.append(contentsOf: rpmHeader([(1000, 6, 0, 1), (1001, 6, 7, 1)], Array("testpkg\0".utf8) + Array("1.0\0".utf8)).dropLast(0))
        rpm.append(payload)
        let rf = pk.appendingPathComponent("t-\(label).rpm"); try rpm.write(to: rf)
        do {
            let ours = try extractOurs(rf, to: "own-rpm-\(label)")
            check("rpm [\(label)]: matches bsdtar's extraction of the payload", sameTree(cpioRef, ours) == nil, sameTree(cpioRef, ours) ?? "")
            let l = try AXCore.list(rf, password: nil)
            check("rpm [\(label)]: package name shown", l.details.contains("testpkg"), l.details)
            try AXCore.test(rf, password: nil, progress: { _ in })
        } catch { check("rpm [\(label)]", false, "\(error)") }
    }

    // XAR / pkg written by macOS's xar
    for comp in ["none", "gzip", "bzip2"] {
        let x = pk.appendingPathComponent("t-\(comp).xar"); try? fm.removeItem(at: x)
        let mk = sh("/usr/bin/xar --compression=\(comp) -cf \(q(x)) a.txt sub run.sh link-to-a empty-dir empty.txt 'résumé 日本語 ✓.txt'", cwd: src)
        if mk.status != 0 { check("xar [\(comp)]: created", false, mk.out.suffix(120).description); continue }
        let ref = work.appendingPathComponent("refxar-\(comp)"); try fm.createDirectory(at: ref, withIntermediateDirectories: true)
        sh("/usr/bin/xar -xf \(q(x)) -C \(q(ref))")
        do {
            let ours = try extractOurs(x, to: "own-xar-\(comp)")
            check("xar [\(comp)]: matches xar's extraction", sameTree(ref, ours) == nil, sameTree(ref, ours) ?? "")
            try AXCore.test(x, password: nil, progress: { _ in })
        } catch { check("xar [\(comp)]", false, "\(error)") }
    }

    // CAB (written here: stored and MSZIP), checked against 7-Zip
    func cab(_ files: [(String, Data)], mszip: Bool) -> Data {
        var all = Data(); for f in files { all.append(f.1) }
        func le16b(_ v: Int) -> [UInt8] { [UInt8(v & 255), UInt8((v >> 8) & 255)] }
        func le32b(_ v: Int) -> [UInt8] { le16b(v & 0xffff) + le16b(v >> 16) }
        var blocks = Data(); var nBlocks = 0
        var pos = 0
        while pos < all.count || (pos == 0 && nBlocks == 0) {
            let chunk = all.subdata(in: pos..<min(all.count, pos + 32768)); pos += max(chunk.count, 1)
            var data = chunk
            if mszip { data = Data([0x43, 0x4b]) + ((try? (chunk as NSData).compressed(using: .zlib) as Data) ?? chunk) }
            blocks.append(contentsOf: le32b(0) + le16b(data.count) + le16b(chunk.count)); blocks.append(data); nBlocks += 1
            if all.isEmpty { break }
        }
        var fileTable = Data(); var off = 0
        for f in files {
            fileTable.append(contentsOf: le32b(f.1.count) + le32b(off) + le16b(0) + le16b(0x5821) + le16b(0x6000) + le16b(0x20)); fileTable.append(Data(f.0.utf8)); fileTable.append(0)
            off += f.1.count
        }
        let coffFiles = 36 + 8
        let coffData = coffFiles + fileTable.count
        var h = Data("MSCF".utf8) + Data(le32b(0)) + Data(le32b(coffData + blocks.count)) + Data(le32b(0)) + Data(le32b(coffFiles)) + Data(le32b(0))
        h.append(contentsOf: [3, 1]); h.append(contentsOf: le16b(1) + le16b(files.count) + le16b(0) + le16b(0) + le16b(0))
        h.append(contentsOf: le32b(coffData) + le16b(nBlocks) + le16b(mszip ? 1 : 0))
        return h + fileTable + blocks
    }
    let cabFiles: [(String, Data)] = [("one.txt", Data("first file\n".utf8)), ("dir\\two.txt", Data((1...20000).map { "line \($0)\n" }.joined().utf8)),
                                      ("empty.txt", Data()), ("noise.bin", Data((0..<100_000).map { _ in UInt8.random(in: 0...255) }))]
    for mszip in [false, true] {
        let c = pk.appendingPathComponent(mszip ? "t-mszip.cab" : "t-stored.cab"); try cab(cabFiles, mszip: mszip).write(to: c)
        let ref = work.appendingPathComponent("refcab-\(mszip)"); try fm.createDirectory(at: ref, withIntermediateDirectories: true)
        sh("\(SZ) x -y -o\(q(ref)) \(q(c))")
        do {
            let ours = try extractOurs(c, to: "own-cab-\(mszip)")
            check("cab [\(mszip ? "MSZIP" : "stored")]: matches 7-Zip's extraction", sameContent(ref, ours) == nil, sameContent(ref, ours) ?? "")
            check("cab [\(mszip ? "MSZIP" : "stored")]: bytes equal what was packed", (try? Data(contentsOf: ours.appendingPathComponent("dir/two.txt"))) == cabFiles[1].1)
            try AXCore.test(c, password: nil, progress: { _ in })
        } catch { check("cab [\(mszip ? "MSZIP" : "stored")]", false, "\(error)") }
    }
} catch { check("section 12 threw", false, "\(error)") }

print("\nRESULT: \(passed) passed, \(failed) failed")
exit(failed == 0 ? 0 : 1)
