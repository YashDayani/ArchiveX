import AppKit
import SwiftUI
@preconcurrency import UserNotifications

// Polish helpers: plain-language errors, time-remaining text, user preferences and "job finished" notifications.

// MARK: - Plain-language errors

enum FriendlyError {
    /// What to tell the user: what went wrong in everyday words, and what to try next.
    static func describe(_ error: Error) -> String {
        if let ax = error as? AXError {
            switch ax {
            case .corrupt(let detail):
                let d = detail.lowercased()
                if d.contains("unexpected end") || d.contains("truncated") || d.contains("end of file") {
                    return "This archive ends too early, so it is probably an incomplete download or a part is missing. Download it again, or use Test to see which files are still fine."
                }
                if d.contains("checksum") || d.contains("crc") || d.contains("mismatch") {
                    return "A file inside failed its integrity check, so the archive is damaged. Download it again, or extract the other files and skip this one. (\(detail))"
                }
                return "This archive looks damaged. Try downloading it again, or use Test to see which files are affected. (\(detail))"
            case .unsupported(let what):
                return "ArchiveX can’t read this yet: \(what). Another app may open it; ArchiveX still lists everything it can."
            case .wrongPassword:
                return "That password didn’t work. Check it for typos (it is case-sensitive) and try again."
            case .passwordRequired:
                return "This archive is password-protected. Enter its password to continue."
            case .io(let m):
                return friendlyIO(m)
            case .unsafe(let m):
                return "ArchiveX skipped “\(m)” because it would have been written outside the folder you chose."
            }
        }
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain {
            switch ns.code {
            case NSFileWriteOutOfSpaceError:
                return "There isn’t enough free space on that disk. Free up some space or choose another location, then try again."
            case NSFileWriteNoPermissionError, NSFileReadNoPermissionError:
                return "ArchiveX isn’t allowed to use that location. Choose another folder, or allow access in System Settings → Privacy & Security → Files & Folders."
            case NSFileReadNoSuchFileError, NSFileNoSuchFileError:
                return "That file can’t be found any more. It may have been moved or deleted."
            case NSFileWriteVolumeReadOnlyError:
                return "That disk is read-only, so nothing can be saved there. Choose another location."
            default: break
            }
        }
        if ns.domain == NSPOSIXErrorDomain {
            switch Int32(ns.code) {
            case ENOSPC: return "There isn’t enough free space on that disk. Free up some space or choose another location."
            case EACCES, EPERM: return "ArchiveX isn’t allowed to use that location. Choose another folder."
            case ENOENT: return "That file can’t be found any more. It may have been moved or deleted."
            case EROFS: return "That disk is read-only. Choose another location."
            default: break
            }
        }
        return error.localizedDescription
    }

    private static func friendlyIO(_ m: String) -> String {
        let l = m.lowercased()
        if l.contains("no space") { return "There isn’t enough free space on that disk. Free up some space or choose another location." }
        if l.contains("permission") || l.contains("not permitted") { return "ArchiveX isn’t allowed to use that location. Choose another folder." }
        return m
    }
}

// MARK: - Time remaining

enum JobTime {
    /// Seconds left, once there is enough progress to say something sensible.
    static func remaining(elapsed: TimeInterval, fraction: Double) -> TimeInterval? {
        guard fraction >= 0.03, fraction < 1, elapsed >= 2 else { return nil }
        return elapsed * (1 - fraction) / fraction
    }

    static func text(remaining s: TimeInterval) -> String {
        if s < 10 { return "A few seconds left" }
        if s < 60 { return "About \(Int((s / 5).rounded()) * 5) seconds left" }
        let m = Int((s / 60).rounded())
        if m < 60 { return m == 1 ? "About 1 minute left" : "About \(m) minutes left" }
        let h = s / 3600
        return String(format: "About %.1f hours left", h)
    }

    static func elapsed(_ s: TimeInterval) -> String {
        let t = Int(s)
        return t < 60 ? "\(t) s" : String(format: "%d:%02d", t / 60, t % 60)
    }
}

// MARK: - Preferences

enum Prefs {
    static let notifyKey = "notifyWhenDone"
    static let defaultFormatKey = "defaultFormat"          // "" = the format used last
    static let defaultLevelKey = "defaultLevel"            // -1 = built-in default
    static let overwriteKey = "overwritePolicy"            // ExtractDraft.Overwrite raw value
    static let revealKey = "revealAfterExtract"

    static var notify: Bool { UserDefaults.standard.object(forKey: notifyKey) as? Bool ?? true }
    static var reveal: Bool { UserDefaults.standard.object(forKey: revealKey) as? Bool ?? true }
    static var defaultFormat: ArchiveFormat? {
        UserDefaults.standard.string(forKey: defaultFormatKey).flatMap { $0.isEmpty ? nil : ArchiveFormat(rawValue: $0) }
    }
    static var defaultLevel: Int? {
        guard let v = UserDefaults.standard.object(forKey: defaultLevelKey) as? Int, (0...5).contains(v) else { return nil }
        return v
    }
    static var overwrite: ExtractDraft.Overwrite {
        UserDefaults.standard.string(forKey: overwriteKey).flatMap(ExtractDraft.Overwrite.init(rawValue:)) ?? .all
    }
}

// MARK: - Finished-job notifications and Dock badge

@MainActor
enum JobNotifier {
    /// A percentage on the Dock icon while a job runs.
    static func dock(_ fraction: Double?) {
        NSApplication.shared.dockTile.badgeLabel = fraction.map { "\(Int($0 * 100))%" }
    }

    /// Tells the user a long job finished while they were in another app: a notification, and the Dock icon bounces once.
    static func finished(_ message: String, afterSeconds: TimeInterval) {
        dock(nil)
        guard afterSeconds >= 3, !NSApplication.shared.isActive else { return }
        NSApplication.shared.requestUserAttention(.informationalRequest)
        guard Prefs.notify, Bundle.main.bundleIdentifier != nil else { return }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let c = UNMutableNotificationContent()
            c.title = "ArchiveX"; c.body = message; c.sound = .default
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
        }
    }
}

// MARK: - Settings window (⌘,)

struct SettingsView: View {
    @AppStorage(Updater.autoCheckKey) private var autoCheck = true
    @AppStorage(Prefs.notifyKey) private var notify = true
    @AppStorage(Prefs.defaultFormatKey) private var format = ""
    @AppStorage(Prefs.defaultLevelKey) private var level = -1
    @AppStorage(Prefs.overwriteKey) private var overwrite = ExtractDraft.Overwrite.all.rawValue
    @AppStorage(Prefs.revealKey) private var reveal = true

    private let levels = ["Store", "Fastest", "Fast", "Normal", "Good", "Best"]

    var body: some View {
        TabView {
            Form {
                Toggle("Check for updates when ArchiveX starts", isOn: $autoCheck)
                Toggle("Notify me when a long job finishes in the background", isOn: $notify)
            }
            .padding(20).tabItem { Label("General", systemImage: "gearshape") }

            Form {
                Picker("New archives use", selection: $format) {
                    Text("The format I used last").tag("")
                    ForEach(ArchiveFormat.allCases) { Text($0.rawValue).tag($0.rawValue) }
                }
                Picker("Compression level", selection: $level) {
                    Text("Normal (default)").tag(-1)
                    ForEach(0..<levels.count, id: \.self) { Text(levels[$0]).tag($0) }
                }
                Text("You can still change both for each archive when you create it.").font(.caption).foregroundStyle(.secondary)
            }
            .padding(20).tabItem { Label("Compression", systemImage: "archivebox") }

            Form {
                Picker("When a file already exists", selection: $overwrite) {
                    ForEach(ExtractDraft.Overwrite.allCases) { Text($0.rawValue).tag($0.rawValue) }
                }
                Toggle("Show the extracted files in Finder when done", isOn: $reveal)
            }
            .padding(20).tabItem { Label("Extraction", systemImage: "arrow.down.doc") }
        }
        .frame(width: 460, height: 230)
    }
}
