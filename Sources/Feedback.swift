import AppKit
import Foundation

// Help → Report a Bug… / Request a Feature…: opens a new GitHub issue with the technical details already filled in.
// Only the app version, macOS version and chip are sent (as part of the URL); nothing about the user's files or archives.

enum Feedback {
    static let repo = "YashDayani/ArchiveX"

    enum Kind {
        case bug, feature
        var template: String { self == .bug ? "bug_report.yml" : "feature_request.yml" }
    }

    static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown" }

    static var macOSVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "macOS \(v.majorVersion).\(v.minorVersion)" + (v.patchVersion > 0 ? ".\(v.patchVersion)" : "")
    }

    static var chip: String {
        #if arch(arm64)
        return "Apple Silicon (arm64)"
        #else
        return "Intel (x86_64)"
        #endif
    }

    /// The "new issue" page for `kind`, with the form fields (matched by id in the issue templates) already filled in.
    static func url(_ kind: Kind, version: String = appVersion, macOS: String = macOSVersion, chip: String = chip) -> URL {
        var c = URLComponents(string: "https://github.com/\(repo)/issues/new")!
        var items = [URLQueryItem(name: "template", value: kind.template), URLQueryItem(name: "version", value: version)]
        if kind == .bug {
            items += [URLQueryItem(name: "macos", value: macOS), URLQueryItem(name: "chip", value: chip)]
        }
        c.queryItems = items
        return c.url!
    }

    @MainActor static func open(_ kind: Kind) { NSWorkspace.shared.open(url(kind)) }

    static var issuesPage: URL { URL(string: "https://github.com/\(repo)/issues")! }
    static var repoPage: URL { URL(string: "https://github.com/\(repo)")! }
}
