import Foundation

// ISO 9660 (with Joliet and Rock Ridge names) and CPIO (newc / odc) readers.

struct DiscEntry {
    var path: String
    var isDir: Bool
    var size: UInt64
    var mtime: Date?
    var mode: UInt32?
    var link: String?
    var extents: [(offset: UInt64, length: UInt64)] = []     // where the data lives (ISO)
    var dataOffset: UInt64 = 0                                // CPIO
}

// MARK: - ISO 9660

final class IsoArchive {
    let file: FileIn
    private(set) var entries: [DiscEntry] = []
    private(set) var flavour = "ISO 9660"
    private let block: Int

    init(url: URL) throws {
        file = try FileIn(url)
        var primary: Data?
        var joliet: Data?
        var sector: UInt64 = 16
        while sector < 64 {
            let d = try file.read(at: sector * 2048, 2048)
            guard d.count == 2048, d[d.startIndex + 1] == 0x43, d[d.startIndex + 2] == 0x44, d[d.startIndex + 3] == 0x30,
                  d[d.startIndex + 4] == 0x30, d[d.startIndex + 5] == 0x31 else { break }          // "CD001"
            let type = d[d.startIndex]
            if type == 1 && primary == nil { primary = d }
            if type == 2 {
                let esc = d.subdata(in: d.startIndex + 88..<d.startIndex + 91)
                if esc == Data([0x25, 0x2f, 0x40]) || esc == Data([0x25, 0x2f, 0x43]) || esc == Data([0x25, 0x2f, 0x45]) { joliet = d }
            }
            if type == 255 { break }
            sector += 1
        }
        guard let pvd = primary else { throw AXError.corrupt("not an ISO 9660 image") }
        block = Int(pvd.le16(128))
        guard block >= 512 else { throw AXError.corrupt("bad ISO block size") }

        // Prefer Rock Ridge names (they keep case, permissions and symlinks); otherwise Joliet; otherwise plain ISO names.
        var list = try walk(root: pvd.subdata(in: pvd.startIndex + 156..<pvd.startIndex + 190), joliet: false)
        if list.rockRidge { flavour = "ISO 9660 · Rock Ridge" }
        else if let j = joliet {
            list = try walk(root: j.subdata(in: j.startIndex + 156..<j.startIndex + 190), joliet: true)
            flavour = "ISO 9660 · Joliet"
        }
        entries = list.entries
    }

    private struct Walked { var entries: [DiscEntry] = []; var rockRidge = false }

    private func date(_ d: Data, _ o: Int) -> Date? {
        var c = DateComponents(); c.timeZone = TimeZone(secondsFromGMT: Int(Int8(bitPattern: d[d.startIndex + o + 6])) * 900)
        c.year = 1900 + Int(d[d.startIndex + o]); c.month = Int(d[d.startIndex + o + 1]); c.day = Int(d[d.startIndex + o + 2])
        c.hour = Int(d[d.startIndex + o + 3]); c.minute = Int(d[d.startIndex + o + 4]); c.second = Int(d[d.startIndex + o + 5])
        return Calendar(identifier: .gregorian).date(from: c)
    }

    private func walk(root: Data, joliet: Bool) throws -> Walked {
        var out = Walked()
        var visited = Set<UInt32>()
        func dir(lba: UInt32, length: UInt32, prefix: String, depth: Int) throws {
            guard depth < 64, visited.insert(lba).inserted else { return }
            let data = try file.read(at: UInt64(lba) * UInt64(block), Int(length))
            var pos = 0
            var pending: DiscEntry?
            while pos < data.count {
                let len = Int(data[data.startIndex + pos])
                if len == 0 { pos = (pos / block + 1) * block; continue }              // records never straddle blocks
                guard len >= 34, pos + len <= data.count else { break }
                let r = data.subdata(in: data.startIndex + pos..<data.startIndex + pos + len)
                pos += len
                let flags = r[r.startIndex + 25]
                let nameLen = Int(r[r.startIndex + 32])
                guard 33 + nameLen <= len else { continue }
                let rawName = r.subdata(in: r.startIndex + 33..<r.startIndex + 33 + nameLen)
                if nameLen == 1 && (rawName[rawName.startIndex] == 0 || rawName[rawName.startIndex] == 1) { continue }       // . and ..
                var name: String
                if joliet { name = String(decoding: stride(from: 0, to: rawName.count - 1, by: 2).map { UInt16(rawName[rawName.startIndex + $0]) << 8 | UInt16(rawName[rawName.startIndex + $0 + 1]) }, as: UTF16.self) }
                else { name = String(decoding: rawName, as: UTF8.self) }
                if let semi = name.lastIndex(of: ";") { name = String(name[..<semi]) }
                if name.hasSuffix(".") && !name.hasPrefix(".") { name.removeLast() }

                // Rock Ridge (system use area after the name, padded to an even offset)
                var su = 33 + nameLen; if su % 2 == 1 { su += 1 }
                var mode: UInt32?, linkTarget: String?, rrName = ""
                var s = su
                while s + 4 <= len {
                    let sig = String(decoding: r.subdata(in: r.startIndex + s..<r.startIndex + s + 2), as: UTF8.self)
                    let sl = Int(r[r.startIndex + s + 2])
                    guard sl >= 4, s + sl <= len else { break }
                    let body = r.subdata(in: r.startIndex + s + 4..<r.startIndex + s + sl)
                    switch sig {
                    case "NM": if body.count >= 1 { rrName += String(decoding: body.dropFirst(), as: UTF8.self); out.rockRidge = true }
                    case "PX": if body.count >= 4 { mode = body.le32(0) }
                    case "SL":
                        var comps: [String] = []; var i = 1
                        while i + 2 <= body.count {
                            let cf = body[body.startIndex + i], cl = Int(body[body.startIndex + i + 1])
                            guard i + 2 + cl <= body.count else { break }
                            let t = String(decoding: body.subdata(in: body.startIndex + i + 2..<body.startIndex + i + 2 + cl), as: UTF8.self)
                            comps.append(cf & 8 != 0 ? "" : cf & 2 != 0 ? "." : cf & 4 != 0 ? ".." : t)
                            i += 2 + cl
                        }
                        linkTarget = (linkTarget ?? "") + comps.joined(separator: "/")
                    default: break
                    }
                    s += sl
                }
                if !rrName.isEmpty { name = rrName }
                let isDir = flags & 2 != 0
                let lbaE = r.le32(2), lenE = r.le32(10)
                let path = prefix.isEmpty ? name : prefix + "/" + name

                if var p = pending, p.path == path {                                      // continuation extent of a huge file
                    p.extents.append((UInt64(lbaE) * UInt64(block), UInt64(lenE))); p.size += UInt64(lenE)
                    pending = flags & 0x80 != 0 ? p : nil
                    if pending == nil { out.entries.append(p) }
                    continue
                }
                var e = DiscEntry(path: path, isDir: isDir, size: isDir ? 0 : UInt64(lenE), mtime: date(r, 18), mode: mode, link: linkTarget)
                if !isDir { e.extents = [(UInt64(lbaE) * UInt64(block), UInt64(lenE))] }
                if let m = mode, m & 0o170000 == 0o120000 { e.link = linkTarget; e.extents = []; e.size = 0 }
                if flags & 0x80 != 0 && !isDir { pending = e; continue }
                out.entries.append(e)
                if isDir { try dir(lba: lbaE, length: lenE, prefix: path, depth: depth + 1) }
            }
        }
        try dir(lba: root.le32(2), length: root.le32(10), prefix: "", depth: 0)
        return out
    }

    var listing: Listing {
        var l = Listing()
        l.details = flavour
        l.entries = entries.map { e in
            ArchiveEntry(path: SafePath.clean(e.path) ?? e.path, isDir: e.isDir, size: Int64(e.size), packed: Int64(e.size), ratio: "",
                         mtime: Dates.text(e.mtime), crc: "", attrs: "", encrypted: false)
        }
        return l
    }

    private func copy(_ e: DiscEntry, to sink: ByteSink, progress: ProgressTracker?) throws {
        for ext in e.extents {
            guard ext.offset + ext.length <= file.size else { throw AXError.corrupt("“\(e.path)” points outside the image (truncated?)") }
            var off: UInt64 = 0
            while off < ext.length {
                let d = try file.read(at: ext.offset + off, Int(min(UInt64(1 << 20), ext.length - off)))
                if d.isEmpty { throw AXError.corrupt("unexpected end of image") }
                off += UInt64(d.count)
                try sink.write(d); try progress?.add(d.count)
            }
        }
    }

    func extract(to ex: Extractor, progress: ProgressTracker?) throws {
        for e in entries {
            try Task.checkCancellation()
            guard let clean = SafePath.clean(e.path) else { _ = try ex.destination(for: e.path, isDir: e.isDir); continue }
            guard ex.isSelected(clean) else { continue }
            if e.isDir {
                if ex.keepPaths, let u = try ex.destination(for: e.path, isDir: true) { try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true); ex.finalize(u, mode: e.mode, mtime: e.mtime) }
                continue
            }
            if let t = e.link { if let u = try ex.destination(for: e.path, isDir: false) { ex.makeSymlink(at: u, target: t) }; continue }
            guard let u = try ex.destination(for: e.path, isDir: false) else { continue }
            let out = try FileOut(u)
            do { try copy(e, to: out, progress: progress) } catch { try? FileManager.default.removeItem(at: u); throw error }
            ex.finalize(u, mode: e.mode, mtime: e.mtime)
        }
    }

    func test(progress: ProgressTracker?) throws {
        for e in entries where !e.isDir && e.link == nil { try Task.checkCancellation(); try copy(e, to: NullSink(), progress: progress) }
    }
}

// MARK: - CPIO

final class CpioArchive {
    let file: FileIn
    private(set) var entries: [DiscEntry] = []
    private(set) var flavour = "CPIO"

    init(url: URL) throws {
        file = try FileIn(url)
        var pos: UInt64 = 0
        func ascii(_ d: Data, _ o: Int, _ n: Int, radix: Int) throws -> UInt64 {
            guard let v = UInt64(String(decoding: d.subdata(in: d.startIndex + o..<d.startIndex + o + n), as: UTF8.self), radix: radix) else { throw AXError.corrupt("bad CPIO header") }
            return v
        }
        while pos + 6 <= file.size {
            let magic = String(decoding: try file.readExactly(at: pos, 6), as: UTF8.self)
            var mode: UInt32, size: UInt64, mtime: UInt64, nameSize: Int, headerLen: Int
            var newc = false
            if magic == "070701" || magic == "070702" {
                let h = try file.readExactly(at: pos, 110)
                mode = UInt32(try ascii(h, 14, 8, radix: 16)); mtime = try ascii(h, 46, 8, radix: 16)
                size = try ascii(h, 54, 8, radix: 16); nameSize = Int(try ascii(h, 94, 8, radix: 16)); headerLen = 110; newc = true
                flavour = "CPIO (newc)"
            } else if magic == "070707" {
                let h = try file.readExactly(at: pos, 76)
                mode = UInt32(try ascii(h, 18, 6, radix: 8)); mtime = try ascii(h, 48, 11, radix: 8)
                nameSize = Int(try ascii(h, 59, 6, radix: 8)); size = try ascii(h, 65, 11, radix: 8); headerLen = 76
                flavour = "CPIO (odc)"
            } else { throw AXError.corrupt(entries.isEmpty ? "not a CPIO archive" : "bad CPIO header") }
            guard nameSize >= 1, nameSize < 65_536 else { throw AXError.corrupt("bad CPIO name") }
            let nameData = try file.readExactly(at: pos + UInt64(headerLen), nameSize)
            var name = String(decoding: nameData.prefix(nameSize - 1), as: UTF8.self)
            var dataStart = pos + UInt64(headerLen) + UInt64(nameSize)
            if newc { dataStart = (dataStart + 3) & ~3 }
            if name == "TRAILER!!!" { break }
            while name.hasPrefix("./") { name.removeFirst(2) }
            guard dataStart + size <= file.size else { throw AXError.corrupt("CPIO archive is truncated") }
            let fmt = mode & 0o170000
            var e = DiscEntry(path: name.trimmingCharacters(in: CharacterSet(charactersIn: "/")), isDir: fmt == 0o040000, size: size,
                              mtime: Date(timeIntervalSince1970: TimeInterval(mtime)), mode: mode & 0o7777)
            e.dataOffset = dataStart
            if fmt == 0o120000, size < 4096 { e.link = String(decoding: try file.readExactly(at: dataStart, Int(size)), as: UTF8.self); e.size = 0 }
            if e.path != "." && !e.path.isEmpty && (fmt == 0o040000 || fmt == 0o100000 || fmt == 0o120000) { entries.append(e) }
            pos = dataStart + size
            if newc { pos = (pos + 3) & ~3 }
        }
    }

    var listing: Listing {
        var l = Listing(); l.details = flavour
        l.entries = entries.map { e in
            ArchiveEntry(path: SafePath.clean(e.path) ?? e.path, isDir: e.isDir, size: Int64(e.size), packed: Int64(e.size), ratio: "",
                         mtime: Dates.text(e.mtime), crc: "", attrs: "", encrypted: false)
        }
        return l
    }

    private func copy(_ e: DiscEntry, to sink: ByteSink, progress: ProgressTracker?) throws {
        var off: UInt64 = 0
        while off < e.size {
            let d = try file.read(at: e.dataOffset + off, Int(min(UInt64(1 << 20), e.size - off)))
            if d.isEmpty { throw AXError.corrupt("unexpected end of CPIO data") }
            off += UInt64(d.count); try sink.write(d); try progress?.add(d.count)
        }
    }

    func extract(to ex: Extractor, progress: ProgressTracker?) throws {
        for e in entries {
            try Task.checkCancellation()
            guard let clean = SafePath.clean(e.path) else { _ = try ex.destination(for: e.path, isDir: e.isDir); continue }
            guard ex.isSelected(clean) else { continue }
            if e.isDir {
                if ex.keepPaths, let u = try ex.destination(for: e.path, isDir: true) { try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true); ex.finalize(u, mode: e.mode, mtime: e.mtime) }
                continue
            }
            if let t = e.link { if let u = try ex.destination(for: e.path, isDir: false) { ex.makeSymlink(at: u, target: t) }; continue }
            guard let u = try ex.destination(for: e.path, isDir: false) else { continue }
            let out = try FileOut(u)
            do { try copy(e, to: out, progress: progress) } catch { try? FileManager.default.removeItem(at: u); throw error }
            ex.finalize(u, mode: e.mode, mtime: e.mtime)
        }
    }

    func test(progress: ProgressTracker?) throws {
        for e in entries where !e.isDir && e.link == nil { try Task.checkCancellation(); try copy(e, to: NullSink(), progress: progress) }
    }
}
