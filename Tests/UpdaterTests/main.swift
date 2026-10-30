import AppKit
import CryptoKit
import Foundation

// Checks for the updater: version ordering, release parsing, the checksum list, the GitHub-only download rule, and a full
// update run against local files (verify, unpack, validate, hand-off) including a tampered download.
//   swiftc -O -swift-version 5 $(ls Sources/*.swift | grep -v App.swift) Sources/Core/*.swift Tests/UpdaterTests/main.swift -o /tmp/UpdaterTests
//   /tmp/UpdaterTests <work-dir>

setvbuf(stdout, nil, _IOLBF, 0)
_ = NSApplication.shared
var pass = 0, fail = 0
func check(_ n: String, _ ok: Bool, _ note: String = "") { if ok { pass += 1; print("PASS", n) } else { fail += 1; print("FAIL", n, note) } }
let fm = FileManager.default
let work = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("up-\(Int(Date().timeIntervalSince1970))")
try! fm.createDirectory(at: work, withIntermediateDirectories: true)

func v(_ s: String) -> AppVersion { AppVersion(s)! }
func sh(_ exe: String, _ args: [String], cwd: URL? = nil) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args; p.currentDirectoryURL = cwd
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    try! p.run(); p.waitUntilExit()
}

/// A tiny signed app bundle with the given version, zipped like the release workflow does.
func makeRelease(version: String, bundleID: String = "io.feedspace.archivex", in dir: URL) -> (zip: URL, sums: URL) {
    let app = dir.appendingPathComponent("ArchiveX.app")
    try? fm.removeItem(at: app)
    try! fm.createDirectory(at: app.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
    try! "#!/bin/sh\nexit 0\n".write(to: app.appendingPathComponent("Contents/MacOS/ArchiveX"), atomically: true, encoding: .utf8)
    sh("/bin/chmod", ["+x", app.appendingPathComponent("Contents/MacOS/ArchiveX").path])
    let plist: [String: Any] = ["CFBundleIdentifier": bundleID, "CFBundleShortVersionString": version, "CFBundleExecutable": "ArchiveX", "CFBundlePackageType": "APPL"]
    (plist as NSDictionary).write(to: app.appendingPathComponent("Contents/Info.plist"), atomically: true)
    sh("/usr/bin/codesign", ["--force", "--deep", "-s", "-", app.path])
    let zip = dir.appendingPathComponent("ArchiveX.zip")
    try? fm.removeItem(at: zip)
    sh("/usr/bin/ditto", ["-c", "-k", "--keepParent", app.path, zip.path])
    let hash = try! ArchiveHasher.hash(file: zip).sha256
    let sums = dir.appendingPathComponent("SHA256SUMS")
    try! "\(hash)  ArchiveX.zip\n".write(to: sums, atomically: true, encoding: .utf8)
    return (zip, sums)
}

@MainActor func run() async {
    // 1. versions
    check("1.10.0 is newer than 1.9.9", v("1.10.0") > v("1.9.9"))
    check("v-prefix is ignored", v("v1.2.0") == v("1.2.0"))
    check("1.2 equals 1.2.0", v("1.2") == v("1.2.0"))
    check("a pre-release is older than its release", v("1.3.0-beta.1") < v("1.3.0"))
    check("beta.2 is newer than beta.1", v("1.3.0-beta.1") < v("1.3.0-beta.2"))
    check("junk is not a version", AppVersion("latest") == nil && AppVersion("") == nil && AppVersion("1.x") == nil)

    // 2. release parsing
    func json(tag: String = "v1.2.0", draft: Bool = false, pre: Bool = false, assets: [(String, String)] = [("ArchiveX.zip", "https://github.com/a/b/releases/download/v1.2.0/ArchiveX.zip"), ("SHA256SUMS", "https://github.com/a/b/releases/download/v1.2.0/SHA256SUMS")]) -> Data {
        let a = assets.map { "{\"name\":\"\($0.0)\",\"browser_download_url\":\"\($0.1)\",\"size\":1234}" }.joined(separator: ",")
        return Data("{\"tag_name\":\"\(tag)\",\"body\":\"## Notes\\n- fix\",\"html_url\":\"https://github.com/a/b/releases/tag/\(tag)\",\"draft\":\(draft),\"prerelease\":\(pre),\"assets\":[\(a)]}".utf8)
    }
    func parsed(_ d: Data) -> UpdateOffer? { (try? Updater.parseRelease(d)) ?? nil }
    let offer = parsed(json())
    check("a release is parsed", offer?.version == "1.2.0" && offer?.size == 1234 && offer?.sumsURL != nil && offer?.notes.contains("fix") == true)
    check("drafts and pre-releases are ignored", parsed(json(draft: true)) == nil && parsed(json(pre: true)) == nil)
    check("a release without the app zip is ignored", parsed(json(assets: [("Other.zip", "https://github.com/x")])) == nil)
    check("a non-version tag is ignored", parsed(json(tag: "nightly")) == nil)

    // 3. checksum list
    let h = String(repeating: "ab", count: 32)
    check("shasum output is read", Updater.expectedSHA256(in: "\(h)  ArchiveX.zip\n", for: "ArchiveX.zip") == h)
    check("binary-mode marker and upper case are accepted", Updater.expectedSHA256(in: "\(h.uppercased()) *ArchiveX.zip", for: "ArchiveX.zip") == h)
    check("another file's hash is not used", Updater.expectedSHA256(in: "\(h)  Other.zip\n", for: "ArchiveX.zip") == nil)
    check("a short or non-hex hash is rejected", Updater.expectedSHA256(in: "abc  ArchiveX.zip", for: "ArchiveX.zip") == nil && Updater.expectedSHA256(in: "\(String(repeating: "zz", count: 32))  ArchiveX.zip", for: "ArchiveX.zip") == nil)

    // 4. only GitHub over HTTPS
    func trusted(_ s: String) -> Bool { Updater.isTrustedGitHubURL(URL(string: s)!) }
    check("github.com and its asset host are trusted", trusted("https://github.com/a/b/releases/download/v1/ArchiveX.zip") && trusted("https://objects.githubusercontent.com/x"))
    check("http, other hosts and look-alikes are not", !trusted("http://github.com/x") && !trusted("https://evil.example/x") && !trusted("https://github.com.evil.example/x") && !trusted("https://notgithub.com/x") && !trusted("file:///tmp/x"))

    // 5. in-place replacement rule
    check("a writable folder allows replacement", Updater.canReplace(work.appendingPathComponent("X.app")))
    check("a translocated app does not", !Updater.canReplace(URL(fileURLWithPath: "/private/var/folders/x/AppTranslocation/y/d/ArchiveX.app")))

    // 6. full runs against local files
    let upd = Updater()
    upd.isTrustedDownload = { _ in true }
    upd.checkSigner = { _ in .matches }
    upd.publicKey = nil                 // the checks below predate signing; signed updates are tested in 6h
    upd.defaults = UserDefaults(suiteName: "archivex-updater-test-\(UUID().uuidString)")!
    upd.currentVersion = "1.0.0"
    upd.appURL = work.appendingPathComponent("Installed/ArchiveX.app")
    try! fm.createDirectory(at: upd.appURL.deletingLastPathComponent(), withIntermediateDirectories: true)
    var handedOff: URL?
    upd.relaunch = { _, newApp in handedOff = newApp; return false }       // do not quit the test process

    let good = work.appendingPathComponent("good"); try! fm.createDirectory(at: good, withIntermediateDirectories: true)
    let rel = makeRelease(version: "1.1.0", in: good)
    let local = UpdateOffer(version: "1.1.0", notes: "", pageURL: URL(string: "https://github.com/a/b")!, zipURL: rel.zip, sumsURL: rel.sums, size: 1)

    // 6a. the local release feed is found newer
    let feed = work.appendingPathComponent("latest.json")
    try! json().write(to: feed)
    upd.releaseURL = feed
    let fetched = (try? await upd.fetchLatest()) ?? nil
    check("the feed is read and offers 1.2.0", fetched?.version == "1.2.0")
    await upd.check(manual: true)
    if case .available(let o) = upd.state { check("check(manual:) offers the newer version", o.version == "1.2.0") } else { check("check(manual:) offers the newer version", false, "\(upd.state)") }
    upd.currentVersion = "1.2.0"
    await upd.check(manual: true)
    check("the same version is up to date", upd.state == .upToDate)
    upd.currentVersion = "1.0.0"

    // 6b. a good update verifies, unpacks, validates and reaches the hand-off (which we decline)
    upd.state = .idle; upd.install(local)
    for _ in 0..<200 { if case .failed = upd.state { break }; if handedOff != nil { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    check("a good update reaches the installer hand-off", handedOff?.lastPathComponent == "ArchiveX.app", "\(upd.state)")
    if case .failed(let m) = upd.state { check("declined hand-off reports a failure", m.contains("installer")) }

    // 6c. a tampered zip is rejected before it is unpacked
    handedOff = nil
    let bad = work.appendingPathComponent("bad"); try! fm.createDirectory(at: bad, withIntermediateDirectories: true)
    let rel2 = makeRelease(version: "1.1.0", in: bad)
    let fh = try! FileHandle(forWritingTo: rel2.zip); try! fh.seekToEnd(); try! fh.write(contentsOf: Data([0, 1, 2])); try! fh.close()
    upd.state = .idle; upd.install(UpdateOffer(version: "1.1.0", notes: "", pageURL: local.pageURL, zipURL: rel2.zip, sumsURL: rel2.sums, size: 1))
    for _ in 0..<200 { if case .failed = upd.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .failed(let m) = upd.state { check("a tampered download is rejected", m.contains("checksum") && handedOff == nil, m) } else { check("a tampered download is rejected", false, "\(upd.state)") }

    // 6d. a different app, or one that is not newer, is rejected
    let other = work.appendingPathComponent("other"); try! fm.createDirectory(at: other, withIntermediateDirectories: true)
    let rel3 = makeRelease(version: "1.1.0", bundleID: "com.evil.app", in: other)
    upd.state = .idle; upd.install(UpdateOffer(version: "1.1.0", notes: "", pageURL: local.pageURL, zipURL: rel3.zip, sumsURL: rel3.sums, size: 1))
    for _ in 0..<200 { if case .failed = upd.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .failed(let m) = upd.state { check("a different bundle identifier is rejected", m.contains("not ArchiveX") && handedOff == nil, m) } else { check("a different bundle identifier is rejected", false, "\(upd.state)") }

    upd.currentVersion = "1.1.0"
    upd.state = .idle; upd.install(local)
    for _ in 0..<200 { if case .failed = upd.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .failed(let m) = upd.state { check("a version that is not newer is rejected", m.contains("not newer") && handedOff == nil, m) } else { check("a version that is not newer is rejected", false, "\(upd.state)") }

    // 6e. a release without a checksum file or from an untrusted host is refused
    upd.currentVersion = "1.0.0"
    upd.state = .idle; upd.install(UpdateOffer(version: "1.1.0", notes: "", pageURL: local.pageURL, zipURL: rel.zip, sumsURL: nil, size: 1))
    if case .failed(let m) = upd.state { check("no checksum file means no install", m.contains("SHA256SUMS")) } else { check("no checksum file means no install", false, "\(upd.state)") }
    upd.isTrustedDownload = Updater.isTrustedGitHubURL
    upd.state = .idle; upd.install(local)
    for _ in 0..<100 { if case .failed = upd.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .failed(let m) = upd.state { check("a non-GitHub download location is refused", m.contains("not GitHub")) } else { check("a non-GitHub download location is refused", false, "\(upd.state)") }

    // 6f. signer pinning: a different signer is refused; an unpinnable (ad-hoc) running app gets a manual install
    upd.currentVersion = "1.0.0"; handedOff = nil; upd.isTrustedDownload = { _ in true }
    upd.checkSigner = { _ in .mismatch }
    upd.state = .idle; upd.install(local)
    for _ in 0..<200 { if case .failed = upd.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .failed(let m) = upd.state { check("a different signer is refused", m.contains("different developer") && handedOff == nil, m) } else { check("a different signer is refused", false, "\(upd.state)") }
    upd.checkSigner = { _ in .cannotPin }
    upd.state = .idle; upd.install(local)
    for _ in 0..<200 { if case .failed = upd.state { break }; if handedOff != nil { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    check("an ad-hoc running app (no signer to pin) still installs in place", handedOff?.lastPathComponent == "ArchiveX.app", "\(upd.state)")
    // a read-only install location falls back to showing the new app in Finder
    handedOff = nil; upd.checkSigner = { _ in .matches }
    let savedApp = upd.appURL; upd.appURL = URL(fileURLWithPath: "/System/Applications/ArchiveX.app")
    upd.state = .idle; upd.install(local)
    for _ in 0..<200 { if case .revealed = upd.state { break }; if case .failed = upd.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .revealed = upd.state { check("a read-only install location falls back to Finder", handedOff == nil) } else { check("a read-only install location falls back to Finder", false, "\(upd.state)") }
    upd.appURL = savedApp
    let realTrust = Updater.signerTrust(of: good.appendingPathComponent("ArchiveX.app"))
    check("an ad-hoc running app cannot pin a signer (the real check)", realTrust == .cannotPin, "\(realTrust)")
    check("the swap script no longer strips quarantine", !Updater.helperScript.contains("quarantine"))
    upd.checkSigner = { _ in .matches }

    // 6g. every launch checks, even right after an earlier check
    let launch = Updater()
    launch.defaults = UserDefaults(suiteName: "archivex-updater-test-\(UUID().uuidString)")!
    launch.currentVersion = "1.0.0"; launch.releaseURL = feed
    launch.checkOnLaunch()
    for _ in 0..<100 { if case .available = launch.state { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
    if case .available = launch.state { check("the launch check finds the update", launch.sheetVisible) } else { check("the launch check finds the update", false, "\(launch.state)") }
    let off = Updater(); off.defaults = UserDefaults(suiteName: "archivex-updater-test-\(UUID().uuidString)")!
    off.defaults.set(false, forKey: Updater.autoCheckKey); off.currentVersion = "1.0.0"; off.releaseURL = feed
    off.checkOnLaunch(); try? await Task.sleep(nanoseconds: 500_000_000)
    check("the launch check respects the off switch", off.state == .idle)

    // 6h. signed updates: only a zip signed with the app's key is installed, even when the checksum list was forged to match it
    let signer = Curve25519.Signing.PrivateKey(), stranger = Curve25519.Signing.PrivateKey()
    func signature(of zip: URL, by key: Curve25519.Signing.PrivateKey, to name: String) -> URL {
        let out = zip.deletingLastPathComponent().appendingPathComponent(name)
        try! key.signature(for: try! Data(contentsOf: zip)).base64EncodedString().write(to: out, atomically: true, encoding: .utf8)
        return out
    }
    func attempt(_ o: UpdateOffer) async -> String {
        handedOff = nil
        upd.state = .idle; upd.install(o)
        for _ in 0..<200 { if case .failed = upd.state { break }; if handedOff != nil { break }; try? await Task.sleep(nanoseconds: 50_000_000) }
        if handedOff != nil { return "installed" }          // the stand-in installer declines on purpose, so reaching it is success
        if case .failed(let m) = upd.state { return m }
        return "\(upd.state)"
    }
    upd.currentVersion = "1.0.0"; upd.checkSigner = { _ in .matches }; upd.isTrustedDownload = { _ in true }
    upd.publicKey = signer.publicKey.rawRepresentation
    let sdir = work.appendingPathComponent("signed"); try! fm.createDirectory(at: sdir, withIntermediateDirectories: true)
    let sr = makeRelease(version: "1.1.0", in: sdir)
    let goodSig = signature(of: sr.zip, by: signer, to: "good.sig")
    func signedOffer(zip: URL, sums: URL, sig: URL?) -> UpdateOffer { UpdateOffer(version: "1.1.0", notes: "", pageURL: local.pageURL, zipURL: zip, sumsURL: sums, size: 1, sigURL: sig) }
    check("a zip signed with the app's key is installed", await attempt(signedOffer(zip: sr.zip, sums: sr.sums, sig: goodSig)) == "installed")

    // an attacker who controls the release swaps the zip AND rewrites SHA256SUMS to match it
    let evil = sdir.appendingPathComponent("evil.zip"); try! fm.copyItem(at: sr.zip, to: evil)
    let fh2 = try! FileHandle(forWritingTo: evil); try! fh2.seekToEnd(); try! fh2.write(contentsOf: Data([9, 9, 9])); try! fh2.close()
    let evilSums = sdir.appendingPathComponent("evil-sums"); try! "\(try! ArchiveHasher.hash(file: evil).sha256)  ArchiveX.zip\n".write(to: evilSums, atomically: true, encoding: .utf8)
    let forged = await attempt(signedOffer(zip: evil, sums: evilSums, sig: goodSig))
    check("a forged zip with a matching checksum list is refused", forged.contains("signature is not valid"), forged)
    let strangerSig = signature(of: sr.zip, by: stranger, to: "stranger.sig")
    let byStranger = await attempt(signedOffer(zip: sr.zip, sums: sr.sums, sig: strangerSig))
    check("a zip signed with someone else's key is refused", byStranger.contains("signature is not valid"), byStranger)
    let junk = sdir.appendingPathComponent("junk.sig"); try! "not a signature".write(to: junk, atomically: true, encoding: .utf8)
    let junked = await attempt(signedOffer(zip: sr.zip, sums: sr.sums, sig: junk))
    check("a garbage signature file is refused", junked.contains("signature is not valid"), junked)
    let unsigned = await attempt(signedOffer(zip: sr.zip, sums: sr.sums, sig: nil))
    check("a release without a signature is not installed", unsigned.contains("isn’t signed"), unsigned)
    upd.publicKey = nil
    check("before signing is set up the checksum alone still decides", await attempt(signedOffer(zip: sr.zip, sums: sr.sums, sig: nil)) == "installed")
    check("a signature of the wrong length is refused", !Updater.verifySignature(zip: sr.zip, signatureBase64: "AAAA", publicKey: signer.publicKey.rawRepresentation))
    check("a valid signature verifies", Updater.verifySignature(zip: sr.zip, signatureBase64: try! String(contentsOf: goodSig), publicKey: signer.publicKey.rawRepresentation))
    let withSig = parsed(json(assets: [("ArchiveX.zip", "https://github.com/a/b/z"), ("SHA256SUMS", "https://github.com/a/b/s"), ("ArchiveX.zip.sig", "https://github.com/a/b/g")]))
    check("the signature file is found in a release", withSig?.sigURL?.lastPathComponent == "g" && parsed(json())?.sigURL == nil)
    upd.checkSigner = { _ in .matches }

    // 7. skipping a version silences quiet checks only
    upd.currentVersion = "1.0.0"; upd.releaseURL = feed; upd.state = .idle
    upd.skip(UpdateOffer(version: "1.2.0", notes: "", pageURL: local.pageURL, zipURL: rel.zip, sumsURL: nil, size: 1))
    await upd.check(manual: false)
    check("a skipped version is not offered by the quiet check", upd.state == .idle && !upd.sheetVisible)
    await upd.check(manual: true)
    if case .available = upd.state { check("a manual check still offers it", true) } else { check("a manual check still offers it", false, "\(upd.state)") }

    // 7b. the installer must not wait forever for an app that does not quit
    func runHelper(victim: Process) -> (swapped: Bool, victimGone: Bool, secs: Double) {
        let root = work.appendingPathComponent("helper-\(UUID().uuidString)")
        let bin = root.appendingPathComponent("bin"), apps = root.appendingPathComponent("Apps"), w = root.appendingPathComponent("work")
        let newApp = w.appendingPathComponent("unpacked/ArchiveX.app")
        for d in [bin, apps.appendingPathComponent("ArchiveX.app/Contents"), newApp.appendingPathComponent("Contents")] { try! fm.createDirectory(at: d, withIntermediateDirectories: true) }
        try! "old".write(to: apps.appendingPathComponent("ArchiveX.app/Contents/v"), atomically: true, encoding: .utf8)
        try! "new".write(to: newApp.appendingPathComponent("Contents/v"), atomically: true, encoding: .utf8)
        try! "#!/bin/sh\nexit 0\n".write(to: bin.appendingPathComponent("open"), atomically: true, encoding: .utf8)
        sh("/bin/chmod", ["+x", bin.appendingPathComponent("open").path])
        let script = w.appendingPathComponent("swap.sh")
        try! Updater.helperScript.write(to: script, atomically: true, encoding: .utf8)
        try! victim.run()
        let t0 = Date()
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = [script.path, String(victim.processIdentifier), apps.appendingPathComponent("ArchiveX.app").path, newApp.path, w.path]
        p.environment = ["PATH": bin.path + ":/usr/bin:/bin", "ARCHIVEX_GRACE": "5"]
        try! p.run(); p.waitUntilExit()
        let installed = (try? String(contentsOf: apps.appendingPathComponent("ArchiveX.app/Contents/v"))) ?? ""
        return (installed == "new" && !fm.fileExists(atPath: w.path), !victim.isRunning, Date().timeIntervalSince(t0))
    }
    let polite = Process(); polite.executableURL = URL(fileURLWithPath: "/bin/sleep"); polite.arguments = ["300"]
    let r1 = runHelper(victim: polite)
    check("an app that stays running is ended after the grace period and the update still installs", r1.swapped && r1.victimGone && r1.secs < 8, "\(r1)")
    let stubborn = Process(); stubborn.executableURL = URL(fileURLWithPath: "/bin/sh")
    stubborn.arguments = ["-c", "trap '' TERM; while true; do sleep 1; done"]
    let r2 = runHelper(victim: stubborn)
    check("an app that ignores the first request is force-ended", r2.swapped && r2.victimGone && r2.secs < 12, "\(r2)")

    // 8. release notes shown in the sheet
    let gh = """
    ## What's Changed
    * Add search and Quick Look by @YashDayani in https://github.com/YashDayani/ArchiveX/pull/3
    * Fix [crash](https://github.com/a/b/issues/1) on open in https://github.com/a/b/pull/4
    ## New Contributors
    * @someone made their first contribution in https://github.com/a/b/pull/5

    **Full Changelog**: https://github.com/YashDayani/ArchiveX/compare/v1.1.1...v1.2.0
    """
    check("GitHub-generated notes lose links, credits, contributors and the changelog line",
          ReleaseNotes.parse(gh) == [.bullet("Add search and Quick Look"), .bullet("Fix crash on open")], "\(ReleaseNotes.parse(gh))")
    check("a notes body that is only the changelog link is empty", ReleaseNotes.parse("**Full Changelog**: https://github.com/a/b/compare/v1...v2").isEmpty)
    let ours = "## What's new\n\n### Add updates\n- Checks on every launch\n- Installs **in place**\n\n- A plain change\n\n**Full Changelog**: https://x"
    check("our notes keep headings and bullets",
          ReleaseNotes.parse(ours) == [.heading("Add updates"), .bullet("Checks on every launch"), .bullet("Installs **in place**"), .bullet("A plain change")], "\(ReleaseNotes.parse(ours))")
    check("no URL is left in any line", !ReleaseNotes.parse(gh + ours).contains { if case .bullet(let s) = $0 { return s.contains("http") } else { return false } })

    print("\n\(pass) passed, \(fail) failed")
    exit(fail == 0 ? 0 : 1)
}
Task { await run() }
RunLoop.main.run()
