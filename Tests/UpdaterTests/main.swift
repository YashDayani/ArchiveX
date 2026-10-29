import AppKit
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

    // 7. skipping a version silences quiet checks only
    upd.currentVersion = "1.0.0"; upd.releaseURL = feed; upd.state = .idle
    upd.skip(UpdateOffer(version: "1.2.0", notes: "", pageURL: local.pageURL, zipURL: rel.zip, sumsURL: nil, size: 1))
    await upd.check(manual: false)
    check("a skipped version is not offered by the quiet check", upd.state == .idle && !upd.sheetVisible)
    await upd.check(manual: true)
    if case .available = upd.state { check("a manual check still offers it", true) } else { check("a manual check still offers it", false, "\(upd.state)") }

    print("\n\(pass) passed, \(fail) failed")
    exit(fail == 0 ? 0 : 1)
}
Task { await run() }
RunLoop.main.run()
