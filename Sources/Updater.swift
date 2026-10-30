import AppKit
import CryptoKit
import Foundation
import Security

// Checks GitHub Releases for a newer ArchiveX and installs it.
//
// The release workflow publishes ArchiveX.zip and SHA256SUMS. An update is only installed when the zip arrives over HTTPS from
// GitHub, matches the checksum in SHA256SUMS, unpacks to an app with our bundle identifier and a valid code signature, and is
// newer than the running version. The new app must also be signed by the same developer as the running one (its designated
// requirement when it has one (an ad-hoc signed app has no signer to pin). If the running app cannot be replaced in place, the new
// app is revealed in Finder for the user to install by hand instead.

struct UpdateOffer: Equatable {
    var version: String
    var notes: String
    var pageURL: URL
    var zipURL: URL
    var sumsURL: URL?
    var size: Int64
    var sigURL: URL? = nil
}

/// A dotted version such as 1.2.0 or v1.3-beta.1. A pre-release sorts before the release it leads up to.
struct AppVersion: Comparable, Equatable {
    var numbers: [Int]
    var pre: String

    init?(_ text: String) {
        var s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("v") || s.hasPrefix("V") { s.removeFirst() }
        let parts = s.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard let head = parts.first, !head.isEmpty else { return nil }
        var nums: [Int] = []
        for piece in head.split(separator: ".", omittingEmptySubsequences: false) {
            guard let n = Int(piece), n >= 0 else { return nil }
            nums.append(n)
        }
        numbers = nums
        pre = parts.count > 1 ? String(parts[1]) : ""
    }

    static func < (a: AppVersion, b: AppVersion) -> Bool {
        for i in 0..<max(a.numbers.count, b.numbers.count) {
            let x = i < a.numbers.count ? a.numbers[i] : 0, y = i < b.numbers.count ? b.numbers[i] : 0
            if x != y { return x < y }
        }
        if a.pre == b.pre { return false }
        if a.pre.isEmpty { return false }          // a is the final release
        if b.pre.isEmpty { return true }           // b is the final release, a only a pre-release of it
        return a.pre.compare(b.pre, options: .numeric) == .orderedAscending
    }
    static func == (a: AppVersion, b: AppVersion) -> Bool { !(a < b) && !(b < a) }
}

/// Turns a GitHub release body into what the update sheet shows: headings, bullets and plain lines, without links, "by @user in <url>"
/// credits, the "Full Changelog" line or the "New Contributors" list.
enum ReleaseNotes {
    enum Line: Equatable { case heading(String), bullet(String), text(String) }

    static func parse(_ markdown: String) -> [Line] {
        var out: [Line] = []
        var skipping = false
        for raw in markdown.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n") {
            let t = raw.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            if t.hasPrefix("#") {
                let title = clean(String(t.drop(while: { $0 == "#" })))
                let lower = title.lowercased().replacingOccurrences(of: "’", with: "'")
                skipping = lower.contains("new contributor")
                if skipping || title.isEmpty || lower == "what's changed" || lower == "what's new" { continue }
                out.append(.heading(title)); continue
            }
            if skipping { continue }
            let lower = t.lowercased().replacingOccurrences(of: "*", with: "")
            if lower.hasPrefix("full changelog") { continue }
            if t.hasPrefix("- ") || t.hasPrefix("* ") || t.hasPrefix("+ ") {
                let s = clean(String(t.dropFirst(2)))
                if !s.isEmpty { out.append(.bullet(s)) }
                continue
            }
            let s = clean(t)
            if !s.isEmpty { out.append(.text(s)) }
        }
        return out
    }

    static func clean(_ text: String) -> String {
        var r = text
        func sub(_ pattern: String, _ with: String) { r = r.replacingOccurrences(of: pattern, with: with, options: .regularExpression) }
        sub(#"\[([^\]]+)\]\([^)]*\)"#, "$1")                  // [text](url) -> text
        sub(#"\s+by\s+@[\w-]+(\s+in\s+\S+)?"#, "")            // " by @user in https://…"
        sub(#"\s+in\s+https?://\S+"#, "")
        sub(#"https?://\S+"#, "")
        sub(#"\(\s*\)"#, "")
        sub(#"\s+"#, " ")
        return r.trimmingCharacters(in: .whitespaces)
    }
}

enum SignerTrust { case matches, cannotPin, mismatch }

enum UpdateError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let m) = self { return m } else { return nil } }
}

@MainActor
final class Updater: ObservableObject {
    enum State: Equatable {
        case idle
        case checking
        case upToDate
        case available(UpdateOffer)
        case working(String, Double?)
        case failed(String)
        case revealed(URL, String)
    }

    static let shared = Updater()
    static let autoCheckKey = "autoCheckUpdates", skippedKey = "skippedUpdateVersion"
    static let assetName = "ArchiveX.zip", sumsName = "SHA256SUMS", sigName = "ArchiveX.zip.sig"

    @Published var state: State = .idle
    @Published var sheetVisible = false

    // Overridable so tests can run against local files.
    var releaseURL = URL(string: "https://api.github.com/repos/YashDayani/ArchiveX/releases/latest")!
    var currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    var expectedBundleID = Bundle.main.bundleIdentifier ?? "io.feedspace.archivex"
    var appURL = Bundle.main.bundleURL
    var isTrustedDownload: (URL) -> Bool = Updater.isTrustedGitHubURL
    var defaults = UserDefaults.standard
    var checkSigner: (URL) -> SignerTrust = Updater.signerTrust
    /// The Ed25519 key updates must be signed with; nil only until signing has been set up (see UpdateKey).
    var publicKey: Data? = UpdateKey.publicKey
    var relaunch: (_ script: URL, _ newApp: URL) -> Bool = Updater.launchHelper
    var quit: () -> Void = { NSApplication.shared.terminate(nil) }

    // MARK: Checking

    private var launchChecked = false

    /// Called at start-up: every launch asks GitHub once, and only a new, not skipped version opens the sheet.
    func checkOnLaunch() {
        guard !launchChecked, defaults.object(forKey: Self.autoCheckKey) as? Bool ?? true else { return }
        launchChecked = true
        Task { await check(manual: false) }
    }

    func checkNow() {
        sheetVisible = true
        Task { await check(manual: true) }
    }

    func check(manual: Bool) async {
        if case .working = state { return }
        if manual { state = .checking }
        do {
            let offer = try await fetchLatest()
            guard let offer, let remote = AppVersion(offer.version), let local = AppVersion(currentVersion), remote > local else {
                state = .upToDate; return
            }
            if !manual && defaults.string(forKey: Self.skippedKey) == offer.version { state = .idle; return }
            state = .available(offer)
            sheetVisible = true
        } catch {
            state = manual ? .failed(error.localizedDescription) : .idle
        }
    }

    func fetchLatest() async throws -> UpdateOffer? {
        var req = URLRequest(url: releaseURL, timeoutInterval: 20)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("ArchiveX/\(currentVersion)", forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse {
            if http.statusCode == 404 { return nil }
            if http.statusCode == 403 || http.statusCode == 429 { throw UpdateError.message("GitHub is limiting requests right now. Try again in a little while.") }
            guard http.statusCode == 200 else { throw UpdateError.message("GitHub answered with status \(http.statusCode).") }
        }
        return try Self.parseRelease(data)
    }

    static func parseRelease(_ data: Data) throws -> UpdateOffer? {
        struct Asset: Decodable { var name: String; var browserDownloadUrl: URL; var size: Int64 }
        struct Release: Decodable { var tagName: String; var body: String?; var htmlUrl: URL; var draft: Bool?; var prerelease: Bool?; var assets: [Asset] }
        let d = JSONDecoder(); d.keyDecodingStrategy = .convertFromSnakeCase
        let r = try d.decode(Release.self, from: data)
        if r.draft == true || r.prerelease == true { return nil }
        guard AppVersion(r.tagName) != nil else { return nil }
        guard let zip = r.assets.first(where: { $0.name == assetName }) else { return nil }
        var v = r.tagName; if v.hasPrefix("v") || v.hasPrefix("V") { v.removeFirst() }
        return UpdateOffer(version: v, notes: r.body ?? "", pageURL: r.htmlUrl, zipURL: zip.browserDownloadUrl,
                           sumsURL: r.assets.first(where: { $0.name == sumsName })?.browserDownloadUrl, size: zip.size,
                           sigURL: r.assets.first(where: { $0.name == sigName })?.browserDownloadUrl)
    }

    // MARK: Installing

    func skip(_ offer: UpdateOffer) {
        defaults.set(offer.version, forKey: Self.skippedKey)
        sheetVisible = false; state = .idle
    }

    func dismiss() { sheetVisible = false; if case .working = state { return }; state = .idle }

    func install(_ offer: UpdateOffer) {
        guard let sums = offer.sumsURL else {
            state = .failed("This release has no \(Self.sumsName) file, so the download cannot be verified. Download it from the release page instead.")
            return
        }
        Task {
            do { try await perform(offer, sumsURL: sums) }
            catch { state = .failed(error.localizedDescription) }
        }
    }

    private func perform(_ offer: UpdateOffer, sumsURL: URL) async throws {
        guard isTrustedDownload(offer.zipURL), isTrustedDownload(sumsURL) else {
            throw UpdateError.message("The release points to a download location that is not GitHub, so it was not used.")
        }
        let fm = FileManager.default
        let work = fm.temporaryDirectory.appendingPathComponent("archivex-update-\(UUID().uuidString)")
        try fm.createDirectory(at: work, withIntermediateDirectories: true)

        state = .working("Checking the checksum list…", nil)
        let (sumsData, _) = try await URLSession.shared.data(from: sumsURL)
        guard let expected = Self.expectedSHA256(in: String(decoding: sumsData, as: UTF8.self), for: Self.assetName) else {
            throw UpdateError.message("\(Self.sumsName) does not list \(Self.assetName).")
        }

        let zip = work.appendingPathComponent(Self.assetName)
        try await download(offer.zipURL, to: zip)

        state = .working("Verifying the download…", nil)
        let actual = try await Task.detached { try ArchiveHasher.hash(file: zip).sha256 }.value
        guard actual == expected else {
            throw UpdateError.message("The download does not match its published SHA-256 checksum, so it was discarded.")
        }

        // The checksum only shows the zip is the one the release lists; whoever can edit the release can change both. The signature
        // can only be made with the private key, which is not on GitHub's release page, so it proves the zip is ours.
        if let key = publicKey {
            guard let sigURL = offer.sigURL, isTrustedDownload(sigURL) else {
                throw UpdateError.message("This release isn’t signed, so it was not installed. Download it from the release page instead.")
            }
            state = .working("Checking the signature…", nil)
            let (sigData, _) = try await URLSession.shared.data(from: sigURL)
            let sigText = String(decoding: sigData, as: UTF8.self)
            let valid = await Task.detached { Self.verifySignature(zip: zip, signatureBase64: sigText, publicKey: key) }.value
            guard valid else {
                throw UpdateError.message("The update’s signature is not valid, so it was not installed. It does not come from the ArchiveX developer.")
            }
        }

        state = .working("Unpacking…", nil)
        let unpacked = work.appendingPathComponent("unpacked")
        let newApp = try await Task.detached { try Self.unpack(zip, into: unpacked) }.value
        try validate(newApp, offer: offer)

        let trust = checkSigner(newApp)
        if trust == .mismatch {
            throw UpdateError.message("The new version is signed by a different developer than the one you have, so it was not installed.")
        }
        // trust == .cannotPin: this copy is ad-hoc signed, so there is no signer to compare with; the checksum, bundle
        // identifier, version and signature checks above still apply, and the update is installed in place.
        if !Self.canReplace(appURL) {
            try? fm.removeItem(at: zip)
            state = .revealed(newApp, "ArchiveX can’t replace itself where it is installed, so the new version is shown in Finder.")
            NSWorkspace.shared.activateFileViewerSelecting([newApp])
            return
        }
        state = .working("Installing — ArchiveX will restart…", nil)
        let script = work.appendingPathComponent("swap.sh")
        try Self.helperScript.write(to: script, atomically: true, encoding: .utf8)
        if relaunch(script, newApp) { await quitForInstall() }
        else { throw UpdateError.message("Could not start the installer. The new version is in \(newApp.deletingLastPathComponent().path).") }
    }

    /// The installer is waiting for us to exit. A quit request is not always honoured while the update sheet is attached to the
    /// window, so close the sheet first and exit outright if the request is still pending a moment later.
    private func quitForInstall() async {
        sheetVisible = false
        try? await Task.sleep(nanoseconds: 400_000_000)
        quit()
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        exit(0)
    }

    private func download(_ url: URL, to dest: URL) async throws {
        state = .working("Downloading…", 0)
        let (bytes, resp) = try await URLSession.shared.bytes(from: url)
        if let http = resp as? HTTPURLResponse, http.statusCode != 200 { throw UpdateError.message("The download failed with status \(http.statusCode).") }
        let total = resp.expectedContentLength
        FileManager.default.createFile(atPath: dest.path, contents: nil)
        let out = try FileHandle(forWritingTo: dest)
        defer { try? out.close() }
        var buf = Data(), got: Int64 = 0
        for try await b in bytes {
            buf.append(b)
            if buf.count >= 1 << 18 {
                try out.write(contentsOf: buf); got += Int64(buf.count); buf.removeAll(keepingCapacity: true)
                if total > 0 { state = .working("Downloading…", Double(got) / Double(total)) }
            }
        }
        try out.write(contentsOf: buf)
    }

    private func validate(_ app: URL, offer: UpdateOffer) throws {
        guard let info = NSDictionary(contentsOf: app.appendingPathComponent("Contents/Info.plist")) as? [String: Any],
              info["CFBundleIdentifier"] as? String == expectedBundleID else {
            throw UpdateError.message("The downloaded app is not ArchiveX, so it was not installed.")
        }
        guard let v = info["CFBundleShortVersionString"] as? String, let new = AppVersion(v), let cur = AppVersion(currentVersion), new > cur else {
            throw UpdateError.message("The downloaded app is not newer than the one you have.")
        }
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        p.arguments = ["--verify", "--deep", "--strict", app.path]
        p.standardError = FileHandle.nullDevice; p.standardOutput = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw UpdateError.message("The downloaded app's code signature is not valid, so it was not installed.") }
    }

    // MARK: Pure helpers (tested headlessly)

    /// Only HTTPS downloads from GitHub's own hosts are used, whatever the release metadata says.
    nonisolated static func isTrustedGitHubURL(_ url: URL) -> Bool {
        guard url.scheme == "https", let host = url.host?.lowercased() else { return false }
        return host == "github.com" || host == "objects.githubusercontent.com" || host.hasSuffix(".githubusercontent.com")
    }

    /// Reads `shasum` output ("<hex>  <name>", optionally "*name") and returns the lowercase hash for `file`.
    nonisolated static func expectedSHA256(in text: String, for file: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2 else { continue }
            let name = parts[1].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "*"))
            let hex = parts[0].lowercased()
            if name == file, hex.count == 64, hex.allSatisfy(\.isHexDigit) { return hex }
        }
        return nil
    }

    /// Whether `signatureBase64` is a valid Ed25519 signature of the whole zip under `publicKey`.
    nonisolated static func verifySignature(zip: URL, signatureBase64: String, publicKey: Data) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
              let sig = Data(base64Encoded: signatureBase64.trimmingCharacters(in: .whitespacesAndNewlines)), sig.count == 64,
              let data = try? Data(contentsOf: zip, options: .mappedIfSafe) else { return false }
        return key.isValidSignature(sig, for: data)
    }

    /// Whether `newApp` satisfies the designated requirement of the running app, i.e. comes from the same signer.
    /// A running app with only an ad-hoc signature has no signer to compare with, so nothing can be pinned.
    nonisolated static func signerTrust(of newApp: URL) -> SignerTrust {
        var me: SecCode?, mine: SecStaticCode?, info: CFDictionary?, req: SecRequirement?, new: SecStaticCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me,
              SecCodeCopyStaticCode(me, [], &mine) == errSecSuccess, let mine,
              SecCodeCopySigningInformation(mine, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any], dict[kSecCodeInfoTeamIdentifier as String] != nil,
              ((dict[kSecCodeInfoFlags as String] as? UInt32) ?? 0) & SecCodeSignatureFlags.adhoc.rawValue == 0,
              SecCodeCopyDesignatedRequirement(mine, [], &req) == errSecSuccess, let req else { return .cannotPin }
        guard SecStaticCodeCreateWithPath(newApp as CFURL, [], &new) == errSecSuccess, let new else { return .mismatch }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(new, flags, req) == errSecSuccess ? .matches : .mismatch
    }

    /// The app can be swapped in place when its folder is writable and it is not running from a translocated copy.
    nonisolated static func canReplace(_ app: URL) -> Bool {
        let parent = app.deletingLastPathComponent().path
        return app.pathExtension == "app" && !app.path.contains("/AppTranslocation/") && FileManager.default.isWritableFile(atPath: parent)
    }

    nonisolated static func unpack(_ zip: URL, into dir: URL) throws -> URL {
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        p.arguments = ["-x", "-k", zip.path, dir.path]
        p.standardError = FileHandle.nullDevice; p.standardOutput = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw UpdateError.message("The download could not be unpacked.") }
        let apps = (try fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)).filter { $0.pathExtension == "app" }
        guard apps.count == 1, let app = apps.first else { throw UpdateError.message("The download does not contain a single app.") }
        return app
    }

    /// Waits for ArchiveX to quit, swaps the bundle (keeping the old one until the copy worked) and starts the new version.
    static let helperScript = """
    #!/bin/sh
    pid="$1"; app="$2"; new="$3"; work="$4"
    # Wait for ArchiveX to quit. If it has not after ~10 s (a quit request can be declined), end it: SIGTERM first, SIGKILL later.
    grace="${ARCHIVEX_GRACE:-50}"; n=0
    while kill -0 "$pid" 2>/dev/null; do
      n=$((n+1))
      [ "$n" -eq "$grace" ] && kill "$pid" 2>/dev/null
      [ "$n" -eq "$((grace+25))" ] && kill -9 "$pid" 2>/dev/null
      sleep 0.2
    done
    old="$app.old-$$"
    mv "$app" "$old" || { open "$app"; exit 1; }
    if ditto "$new" "$app"; then
      rm -rf "$old"
    else
      rm -rf "$app"; mv "$old" "$app"
    fi
    rm -rf "$work"
    open "$app"
    """

    static func launchHelper(script: URL, newApp: URL) -> Bool {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = [script.path, String(ProcessInfo.processInfo.processIdentifier), Bundle.main.bundleURL.path, newApp.path,
                       script.deletingLastPathComponent().path]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
        return (try? p.run()) != nil
    }
}
