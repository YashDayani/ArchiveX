import Foundation

// Split archives (name.7z.001, name.7z.002, …): how many parts a split will make, and joining parts back into one file.

enum SplitPlan {
    /// The most parts a split can make: the files are compressed, so the real number is usually lower.
    static func maxParts(totalBytes: Int64, volumeBytes: UInt64) -> Int {
        guard volumeBytes > 0 else { return 1 }
        let total = UInt64(max(totalBytes, 0))
        return max(1, Int((total + volumeBytes - 1) / volumeBytes))
    }

    static func summary(totalBytes: Int64, volumeBytes: UInt64) -> String {
        let n = maxParts(totalBytes: totalBytes, volumeBytes: volumeBytes)
        return n <= 1 ? "Everything fits in one part, so nothing will be split."
                      : "Makes at most \(n) parts (usually fewer, because the files are compressed)."
    }

    /// Total size of the regular files in `urls`, folders included.
    static func totalSize(of urls: [URL]) -> Int64 {
        let fm = FileManager.default
        var total: Int64 = 0
        for u in urls {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir) else { continue }
            if !isDir.boolValue {
                total += (try? fm.attributesOfItem(atPath: u.path)[.size] as? Int64) ?? 0
            } else if let e = fm.enumerator(at: u, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]) {
                for case let f as URL in e {
                    let v = try? f.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
                    if v?.isRegularFile == true { total += Int64(v?.fileSize ?? 0) }
                }
            }
        }
        return total
    }
}

extension AXCore {
    /// Joins name.7z.001, .002, … into name.7z next to them (never overwriting a file that is already there) and returns it.
    /// Refuses a set with a missing part, because the joined file would be damaged.
    @discardableResult
    static func joinParts(_ firstPart: URL, progress: @escaping (Double) -> Void) throws -> URL {
        guard let parts = FileIn.splitSet(for: firstPart) else {
            throw AXError.io("“\(firstPart.lastPathComponent)” is not a part of a split archive. Choose the first part, for example name.7z.001.")
        }
        let fm = FileManager.default
        let dir = firstPart.deletingLastPathComponent()
        let name = firstPart.lastPathComponent
        let base = String(name[..<name.index(name.endIndex, offsetBy: -4)])          // "name.7z"

        // splitSet stops at the first gap; a later part would mean a part is missing in between
        let next = parts.count + 2
        if fm.fileExists(atPath: dir.appendingPathComponent(base + "." + String(format: "%03d", next)).path) {
            throw AXError.corrupt("part \(String(format: "%03d", parts.count + 1)) is missing, so the parts cannot be joined")
        }

        var out = dir.appendingPathComponent(base)
        if fm.fileExists(atPath: out.path) {
            let ext = (base as NSString).pathExtension, stem = (base as NSString).deletingPathExtension
            var n = 1
            repeat {
                out = dir.appendingPathComponent("\(stem) (joined\(n > 1 ? " \(n)" : ""))" + (ext.isEmpty ? "" : "." + ext))
                n += 1
            } while fm.fileExists(atPath: out.path)
        }

        let tmp = dir.appendingPathComponent(".\(UUID().uuidString).axtmp")
        let sizes = try parts.map { try FileIn($0).size }
        let total = max(sizes.reduce(0, +), 1)
        var done: UInt64 = 0
        do {
            let sink = try FileOut(tmp)
            for part in parts {
                try Task.checkCancellation()
                let f = try FileIn(part)
                var off: UInt64 = 0
                while off < f.size {
                    try Task.checkCancellation()
                    let chunk = try f.readExactly(at: off, Int(min(UInt64(1 << 20), f.size - off)))
                    try sink.write(chunk)
                    off += UInt64(chunk.count); done += UInt64(chunk.count)
                    progress(Double(done) / Double(total))
                }
            }
            try sink.finish()
            try fm.moveItem(at: tmp, to: out)
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
        return out
    }
}
