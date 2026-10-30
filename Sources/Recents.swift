import AppKit
import SwiftUI

// The recent archives shown as badges on the welcome screen.

struct RecentArchive: Identifiable, Equatable {
    var id: URL { url }
    let url: URL
    var name: String { url.lastPathComponent }
    /// The folder it lives in, as people say it: "Downloads".
    var place: String { url.deletingLastPathComponent().lastPathComponent }
    var size: String
}

enum Recents {
    /// Most recent first, skipping archives that are gone, at most `limit`.
    static func list(from urls: [URL], limit: Int = 3, exists: (URL) -> Bool = { FileManager.default.fileExists(atPath: $0.path) },
                     size: (URL) -> Int64 = { (try? FileManager.default.attributesOfItem(atPath: $0.path)[.size] as? Int64) ?? 0 }) -> [RecentArchive] {
        var seen = Set<URL>(), out: [RecentArchive] = []
        for u in urls where exists(u) && seen.insert(u).inserted {
            out.append(RecentArchive(url: u, size: Fmt.bytes(size(u))))
            if out.count == limit { break }
        }
        return out
    }

    @MainActor static var current: [RecentArchive] { list(from: NSDocumentController.shared.recentDocumentURLs) }
}

/// One recent archive as a small rectangular badge: its icon, its name, and where it lives.
struct RecentCard: View {
    @EnvironmentObject var model: ArchiveModel
    let item: RecentArchive
    @State private var hover = false

    var body: some View {
        Button { model.open(item.url) } label: {
            HStack(spacing: 10) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: item.url.path)).resizable().frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.name).font(.callout.weight(.medium)).lineLimit(1).truncationMode(.middle)
                    Text("\(item.place) · \(item.size)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12).padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(hover ? 0.09 : 0.05)))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.primary.opacity(0.10), lineWidth: 1))
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .help(item.url.path)
        .accessibilityLabel("Open \(item.name)")
    }
}
