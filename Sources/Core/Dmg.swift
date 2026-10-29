import Foundation
import Compression

// Apple disk images (UDIF .dmg): the chunk table is decoded into a virtual disk, partitions are found (Apple Partition
// Map, GPT or a bare volume) and HFS+ / HFSX volumes are read from it. APFS volumes are recognised but not opened.

protocol RandomAccess: AnyObject {
    var size: UInt64 { get }
    func read(at offset: UInt64, _ count: Int) throws -> Data
}

extension FileIn: RandomAccess {}

@inline(__always) private func be16(_ d: Data, _ o: Int) -> Int { Int(d[d.startIndex + o]) << 8 | Int(d[d.startIndex + o + 1]) }
@inline(__always) private func be32(_ d: Data, _ o: Int) -> Int {
    Int(d[d.startIndex + o]) << 24 | Int(d[d.startIndex + o + 1]) << 16 | Int(d[d.startIndex + o + 2]) << 8 | Int(d[d.startIndex + o + 3])
}
@inline(__always) private func be64(_ d: Data, _ o: Int) -> UInt64 { UInt64(be32(d, o)) << 32 | UInt64(be32(d, o + 4)) }

// MARK: - the virtual disk inside a .dmg

final class DmgImage: RandomAccess {
    private struct Chunk { var type: UInt32; var start: UInt64; var sectors: UInt64; var offset: UInt64; var length: UInt64 }
    private let url: URL
    private let file: FileIn
    private var chunks: [Chunk] = []
    private(set) var size: UInt64 = 0
    private(set) var methods = Set<String>()
    private var cache: [(index: Int, data: Data)] = []

    init(url: URL) throws {
        self.url = url
        file = try FileIn(url)
        guard file.size >= 512 else { throw AXError.corrupt("not a disk image") }
        let k = try file.readExactly(at: file.size - 512, 512)
        guard k.prefix(4) == Data("koly".utf8) else { throw AXError.unsupported("this kind of disk image (only UDIF .dmg files are supported)") }
        let dataFork = be64(k, 24), xmlOff = be64(k, 216), xmlLen = be64(k, 224)
        guard xmlLen > 0, xmlLen < 1 << 28, xmlOff + xmlLen <= file.size else { throw AXError.unsupported("disk images without a chunk table") }
        let xml = try file.readExactly(at: xmlOff, Int(xmlLen))
        guard let plist = try PropertyListSerialization.propertyList(from: xml, options: [], format: nil) as? [String: Any],
              let rf = plist["resource-fork"] as? [String: Any], let blkx = rf["blkx"] as? [[String: Any]] else { throw AXError.corrupt("bad disk image table") }
        for b in blkx {
            guard let m = b["Data"] as? Data, m.count >= 204, m.prefix(4) == Data("mish".utf8) else { continue }
            let base = be64(m, 8)
            let n = be32(m, 200)
            guard m.count >= 204 + n * 40 else { throw AXError.corrupt("bad disk image table") }
            for i in 0..<n {
                let o = 204 + i * 40
                let t = UInt32(be32(m, o))
                if t == 0x7fff_fffe || t == 0xffff_ffff { continue }
                let c = Chunk(type: t, start: base + be64(m, o + 8), sectors: be64(m, o + 16), offset: be64(m, o + 24) + dataFork, length: be64(m, o + 32))
                if c.sectors == 0 { continue }
                if t != 0, t != 2, t != 1, c.offset + c.length > file.size { throw AXError.corrupt("disk image is truncated") }
                chunks.append(c)
                methods.insert(DmgImage.name(t))
            }
        }
        chunks.sort { $0.start < $1.start }
        if let last = chunks.last { size = (last.start + last.sectors) * 512 }
    }

    private static func name(_ t: UInt32) -> String {
        switch t { case 0, 2: return "sparse"; case 1: return "raw"; case 0x8000_0004: return "ADC"; case 0x8000_0005: return "zlib"
        case 0x8000_0006: return "bzip2"; case 0x8000_0007: return "LZFSE"; case 0x8000_0008: return "LZMA"; default: return "type \(t)" }
    }

    private func decode(_ i: Int) throws -> Data {
        if let hit = cache.first(where: { $0.index == i }) { return hit.data }
        let c = chunks[i]
        let want = Int(c.sectors * 512)
        var out: Data
        switch c.type {
        case 0, 2: out = Data(count: want)
        case 1: out = try file.readExactly(at: c.offset, want)
        case 0x8000_0005: out = try ZlibSource(RangeSource(file: file, offset: c.offset, length: c.length)).readAll(limit: want + 1)
        case 0x8000_0006: out = try Bzip2Source(source: RangeSource(file: file, offset: c.offset, length: c.length)).readAll(limit: want + 1)
        case 0x8000_0008: out = try XzSource(file: FileIn(window: url, offset: c.offset, length: c.length)).readAll(limit: want + 1)
        case 0x8000_0007:
            let src = try file.readExactly(at: c.offset, Int(c.length))
            var dst = Data(count: want)
            let n = dst.withUnsafeMutableBytes { d in src.withUnsafeBytes { s in
                compression_decode_buffer(d.bindMemory(to: UInt8.self).baseAddress!, want, s.bindMemory(to: UInt8.self).baseAddress!, src.count, nil, COMPRESSION_LZFSE)
            } }
            guard n == want else { throw AXError.corrupt("damaged LZFSE block in the disk image") }
            out = dst
        default: throw AXError.unsupported("disk image blocks of type \(DmgImage.name(c.type))")
        }
        guard out.count == want else { throw AXError.corrupt("damaged block in the disk image") }
        cache.append((i, out)); if cache.count > 4 { cache.removeFirst() }
        return out
    }

    func read(at offset: UInt64, _ count: Int) throws -> Data {
        var out = Data()
        var pos = offset
        let end = min(offset + UInt64(count), size)
        while pos < end {
            // chunk containing `pos`
            var lo = 0, hi = chunks.count - 1, found = -1
            while lo <= hi {
                let mid = (lo + hi) / 2
                let c = chunks[mid]
                if pos < c.start * 512 { hi = mid - 1 } else if pos >= (c.start + c.sectors) * 512 { lo = mid + 1 } else { found = mid; break }
            }
            if found < 0 { // a gap: zeros up to the next chunk
                let next = chunks.first(where: { $0.start * 512 > pos })?.start ?? (end / 512 + 1)
                let upTo = min(end, next * 512)
                out.append(Data(count: Int(upTo - pos))); pos = upTo; continue
            }
            let c = chunks[found]
            let data = try decode(found)
            let inChunk = Int(pos - c.start * 512)
            let take = min(data.count - inChunk, Int(end - pos))
            out.append(data.subdata(in: data.startIndex + inChunk..<data.startIndex + inChunk + take))
            pos += UInt64(take)
        }
        return out
    }
}

// MARK: - HFS+ / HFSX

final class HfsVolume {
    struct Extent { var start: Int; var count: Int }
    struct Fork { var size: UInt64 = 0; var blocks = 0; var extents: [Extent] = [] }
    struct Node {
        var path = ""
        var isDir = false
        var size: UInt64 = 0
        var mtime: Date?
        var mode: UInt32?
        var link: String?
        var fork = Fork()
        var rsrc = Fork()
        var fileID = 0
        var compressed = false
    }

    let disk: RandomAccess
    let start: UInt64
    private(set) var name = ""
    private(set) var blockSize = 0
    private var overflow: [String: [Extent]] = [:]
    private var catalog = Fork()
    private var attributes = Fork()
    private var decmpfs: [Int: [UInt8]] = [:]
    private var nodeSize = 0
    private(set) var nodes: [Node] = []

    static func probe(_ disk: RandomAccess, at start: UInt64) -> Bool {
        guard let h = try? disk.read(at: start + 1024, 2), h.count == 2 else { return false }
        let sig = be16(h, 0)
        return sig == 0x482b || sig == 0x4858
    }

    private func fork(_ d: Data, _ o: Int) -> Fork {
        var f = Fork(size: be64(d, o), blocks: be32(d, o + 12))
        for i in 0..<8 {
            let s = be32(d, o + 16 + i * 8), c = be32(d, o + 20 + i * 8)
            if c > 0 { f.extents.append(Extent(start: s, count: c)) }
        }
        return f
    }

    private func extents(of f: Fork, fileID: Int, rsrc: Bool = false) -> [Extent] {
        var list = f.extents
        var have = list.reduce(0) { $0 + $1.count }
        while have < f.blocks, let more = overflow["\(fileID)/\(rsrc ? 255 : 0)/\(have)"] {
            list.append(contentsOf: more); have += more.reduce(0) { $0 + $1.count }
        }
        return list
    }

    /// Reads `count` bytes of a fork starting at `offset`.
    private func readFork(_ f: Fork, fileID: Int, at offset: UInt64, _ count: Int, rsrc: Bool = false) throws -> Data {
        var out = Data()
        var pos = offset
        let end = min(offset + UInt64(count), f.size)
        let ext = extents(of: f, fileID: fileID, rsrc: rsrc)
        while pos < end {
            var blockIndex = Int(pos / UInt64(blockSize))
            var found: Extent?
            var skipBlocks = 0
            for e in ext { if blockIndex < e.count { found = e; skipBlocks = blockIndex; break }; blockIndex -= e.count }
            guard let e = found else { throw AXError.corrupt("HFS+ file data is out of range") }
            let inBlock = Int(pos % UInt64(blockSize))
            let avail = (e.count - skipBlocks) * blockSize - inBlock
            let take = min(avail, Int(end - pos))
            out.append(try disk.read(at: start + UInt64(e.start + skipBlocks) * UInt64(blockSize) + UInt64(inBlock), take))
            pos += UInt64(take)
        }
        return out
    }

    /// Records of a B-tree file, as (key bytes, record bytes) in leaf order.
    private func leafRecords(_ f: Fork, fileID: Int) throws -> [(key: Data, rec: Data)] {
        let head = try readFork(f, fileID: fileID, at: 0, 512)
        guard head.count >= 120 else { throw AXError.corrupt("bad HFS+ B-tree") }
        let ns = be16(head, 32), first = be32(head, 24)
        guard ns >= 512, ns <= 65536 else { throw AXError.corrupt("bad HFS+ B-tree") }
        if fileID == 4 { nodeSize = ns }
        var out: [(Data, Data)] = []
        var n = first
        var visited = 0
        while n != 0 {
            visited += 1
            guard visited < 1 << 24 else { throw AXError.corrupt("HFS+ B-tree loop") }
            let node = try readFork(f, fileID: fileID, at: UInt64(n) * UInt64(ns), ns)
            guard node.count == ns else { throw AXError.corrupt("truncated HFS+ B-tree") }
            let kind = Int(node[node.startIndex + 8]), num = be16(node, 10)
            guard kind == 0xff else { throw AXError.corrupt("bad HFS+ B-tree node") }
            for r in 0..<num {
                let off = be16(node, ns - 2 * (r + 1))
                let next = be16(node, ns - 2 * (r + 2))
                guard off + 2 <= ns, next <= ns, next > off else { continue }
                let keyLen = be16(node, off)
                var recOff = off + 2 + keyLen
                if recOff & 1 != 0 { recOff += 1 }
                guard recOff <= next, off + 2 + keyLen <= ns else { continue }
                let key = node.subdata(in: node.startIndex + off + 2..<node.startIndex + off + 2 + keyLen)
                out.append((key, node.subdata(in: node.startIndex + recOff..<node.startIndex + next)))
            }
            n = be32(node, 0)
        }
        return out
    }

    init(disk: RandomAccess, start: UInt64) throws {
        self.disk = disk; self.start = start
        let h = try disk.read(at: start + 1024, 512)
        guard h.count == 512 else { throw AXError.corrupt("truncated HFS+ volume") }
        blockSize = be32(h, 40)
        guard blockSize >= 512, blockSize & (blockSize - 1) == 0, blockSize <= 1 << 26 else { throw AXError.corrupt("bad HFS+ block size") }
        let extentsFork = fork(h, 192)
        catalog = fork(h, 272)
        attributes = fork(h, 352)
        // the extents-overflow tree lists the extents beyond the first eight of any file
        if extentsFork.size > 0 {
            for (key, rec) in try leafRecords(extentsFork, fileID: 3) where key.count >= 10 && rec.count >= 64 {
                let ft = Int(key[key.startIndex + 0]), fid = be32(key, 2), sb = be32(key, 6)
                var list: [Extent] = []
                for i in 0..<8 { let s = be32(rec, i * 8), c = be32(rec, i * 8 + 4); if c > 0 { list.append(Extent(start: s, count: c)) } }
                overflow["\(fid)/\(ft)/\(sb)"] = list
            }
        }
        try loadCatalog()
        try loadCompressionAttributes()
    }

    private func loadCatalog() throws {
        struct Raw { var parent: Int; var name: String; var isDir: Bool; var id: Int; var node: Node; var hardLink: Int? }
        var raws: [Raw] = []
        for (key, rec) in try leafRecords(catalog, fileID: 4) {
            guard key.count >= 6, rec.count >= 2 else { continue }
            let parent = be32(key, 0), nl = be16(key, 4)
            guard key.count >= 6 + nl * 2 else { continue }
            let units = (0..<nl).map { UInt16(be16(key, 6 + $0 * 2)) }
            let nm = String(decoding: units, as: UTF16.self)
            let type = be16(rec, 0)
            func date(_ o: Int) -> Date? { let v = be32(rec, o); return v == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(v) - 2_082_844_800) }
            if type == 1, rec.count >= 88 {
                var n = Node(); n.isDir = true; n.mtime = date(16); n.fileID = be32(rec, 8)
                n.mode = UInt32(be16(rec, 42)) & 0o7777
                raws.append(Raw(parent: parent, name: nm, isDir: true, id: n.fileID, node: n, hardLink: nil))
            } else if type == 2, rec.count >= 248 {
                var n = Node(); n.mtime = date(16); n.fileID = be32(rec, 8)
                let fmode = UInt32(be16(rec, 42))
                n.mode = fmode & 0o7777
                n.fork = fork(rec, 88); n.size = n.fork.size; n.rsrc = fork(rec, 168)
                n.compressed = rec[rec.startIndex + 41] & 0x20 != 0
                let fileType = be32(rec, 48), creator = be32(rec, 52)
                var hard: Int?
                if fileType == 0x686c_6e6b, creator == 0x6866_732b { hard = be32(rec, 44) }
                if fmode & 0o170000 == 0o120000 {
                    n.link = (try? String(decoding: readFork(n.fork, fileID: n.fileID, at: 0, Int(min(n.size, 4096))), as: UTF8.self)) ?? ""
                    n.size = 0
                }
                raws.append(Raw(parent: parent, name: nm, isDir: false, id: n.fileID, node: n, hardLink: hard))
            } else if type == 3, parent == 2, rec.count >= 10, rec.count >= 10 + be16(rec, 8) * 2 {       // the root folder's thread: the volume name
                name = String(decoding: (0..<be16(rec, 8)).map { UInt16(be16(rec, 10 + $0 * 2)) }, as: UTF16.self)
            }
        }
        // the root folder's name is the volume name (its thread record has parent 2 and an empty name)
        var byParent: [Int: [Raw]] = [:]
        for r in raws { byParent[r.parent, default: []].append(r) }
        var privateDir = 0
        for r in byParent[2] ?? [] where r.isDir && r.name.hasPrefix("\u{0}\u{0}\u{0}\u{0}HFS+ Private Data") { privateDir = r.id }
        var inodes: [String: Raw] = [:]
        for r in byParent[privateDir] ?? [] { inodes[r.name] = r }
        func walk(_ dir: Int, _ prefix: String, depth: Int) {
            guard depth < 200 else { return }
            for r in (byParent[dir] ?? []).sorted(by: { $0.name < $1.name }) {
                if dir == 2 {
                    let n = r.name
                    if n.hasPrefix("\u{0}\u{0}\u{0}\u{0}HFS+ Private Data") || n == ".journal" || n == ".journal_info_block" || n.hasPrefix(".HFS+ Private Directory Data") { continue }
                }
                var node = r.node
                if let h = r.hardLink, let target = inodes["iNode\(h)"] {
                    node.fork = target.node.fork; node.rsrc = target.node.rsrc; node.size = target.node.size; node.fileID = target.node.fileID; node.compressed = target.node.compressed
                }
                node.path = prefix + r.name.replacingOccurrences(of: "/", with: ":")
                nodes.append(node)
                if r.isDir { walk(r.id, node.path + "/", depth: depth + 1) }
            }
        }
        walk(2, "", depth: 0)
    }

    /// Compressed files keep their "com.apple.decmpfs" header in the attributes tree.
    private func loadCompressionAttributes() throws {
        guard attributes.size > 0, nodes.contains(where: { $0.compressed }) else { return }
        for (key, rec) in try leafRecords(attributes, fileID: 8) where key.count >= 12 && rec.count >= 16 {
            let fid = be32(key, 2), nl = be16(key, 10)
            guard key.count >= 12 + nl * 2, be32(rec, 0) == 0x10 else { continue }
            let nm = String(decoding: (0..<nl).map { UInt16(be16(key, 12 + $0 * 2)) }, as: UTF16.self)
            let len = be32(rec, 12)
            if nm == "com.apple.decmpfs", rec.count >= 16 + len { decmpfs[fid] = [UInt8](rec.subdata(in: rec.startIndex + 16..<rec.startIndex + 16 + len)) }
        }
        for i in nodes.indices where nodes[i].compressed {
            if let cm = decmpfs[nodes[i].fileID], cm.count >= 16 {
                nodes[i].size = (0..<8).reduce(UInt64(0)) { $0 | UInt64(cm[8 + $1]) << UInt64(8 * $1) }       // uncompressed size (little-endian)
            }
        }
    }

    func stream(_ n: Node) throws -> ByteSource {
        if n.compressed, let cm = decmpfs[n.fileID] {
            return MemorySource(try Decmpfs.decode(cm) {
                let f = n.rsrc
                return try self.readFork(f, fileID: n.fileID, at: 0, Int(f.size), rsrc: true)
            })
        }
        if n.compressed && n.size == 0 { throw AXError.unsupported("HFS+ files stored with transparent compression") }
        final class S: ByteSource {
            let v: HfsVolume; let n: Node; var pos: UInt64 = 0
            init(_ v: HfsVolume, _ n: Node) { self.v = v; self.n = n }
            func read(_ k: Int) throws -> Data {
                guard pos < n.size else { return Data() }
                let d = try v.readFork(n.fork, fileID: n.fileID, at: pos, Int(min(UInt64(k), n.size - pos, 1 << 20)))
                if d.isEmpty { throw AXError.corrupt("unexpected end of HFS+ file") }
                pos += UInt64(d.count); return d
            }
            func skip(_ k: UInt64) throws { try discard(k) }
        }
        return S(self, n)
    }
}

// MARK: - the archive

final class DmgArchive: ContainerArchive {
    private struct Mounted { var name: String; var kind: String; var items: [ContainerItem]; var open: (Int) throws -> ByteSource }
    private var mounted: [Mounted] = []
    private var map: [(vol: Int, index: Int)] = []
    private(set) var items: [ContainerItem] = []
    private(set) var details = "DMG"

    init(url: URL) throws {
        let image = try DmgImage(url: url)
        var hfs: [UInt64] = [], apfs: [UInt64] = []
        let head = try image.read(at: 0, 4096)
        func classify(_ s: UInt64) { if HfsVolume.probe(image, at: s) { hfs.append(s) } else if ApfsVolume.probe(image, at: s) { apfs.append(s) } }
        if head.count >= 1024, head.prefix(2) == Data("ER".utf8), head[head.startIndex + 512] == 0x50, head[head.startIndex + 513] == 0x4d {
            // Apple Partition Map
            let bs = UInt64(be16(head, 2))
            let count = be32(head, 512 + 4)
            for i in 0..<min(count, 128) {
                let e = try image.read(at: 512 + UInt64(i) * 512, 512)
                guard e.count == 512, e[e.startIndex] == 0x50, e[e.startIndex + 1] == 0x4d else { break }
                classify(UInt64(be32(e, 8)) * max(bs, 512))
            }
        } else if head.count >= 1024, head.subdata(in: head.startIndex + 512..<head.startIndex + 520) == Data("EFI PART".utf8) {
            let g = head.subdata(in: head.startIndex + 512..<head.startIndex + 1024)
            func le64(_ o: Int) -> UInt64 { (0..<8).reduce(UInt64(0)) { $0 | UInt64(g[g.startIndex + o + $1]) << UInt64(8 * $1) } }
            func le32(_ o: Int) -> Int { (0..<4).reduce(0) { $0 | Int(g[g.startIndex + o + $1]) << (8 * $1) } }
            let table = le64(72), n = le32(80), esz = le32(84)
            if esz >= 128, n <= 256 {
                let raw = try image.read(at: table * 512, n * esz)
                for i in 0..<n where raw.count >= (i + 1) * esz {
                    let e = raw.subdata(in: raw.startIndex + i * esz..<raw.startIndex + (i + 1) * esz)
                    if e.prefix(16).allSatisfy({ $0 == 0 }) { continue }
                    let first = (0..<8).reduce(UInt64(0)) { $0 | UInt64(e[e.startIndex + 32 + $1]) << UInt64(8 * $1) }
                    classify(first * 512)
                }
            }
        } else { classify(0) }

        for s in hfs {
            let v = try HfsVolume(disk: image, start: s)
            let its = v.nodes.map { n in ContainerItem(path: n.path, isDir: n.isDir, size: n.size, packed: n.size, mtime: n.mtime, mode: n.mode, link: n.link) }
            mounted.append(Mounted(name: v.name, kind: "HFS+", items: its, open: { try v.stream(v.nodes[$0]) }))
        }
        for s in apfs {
            var index = 0
            while true {
                guard let v = try? ApfsVolume(disk: image, start: s, volumeIndex: index) else {
                    if index == 0 { _ = try ApfsVolume(disk: image, start: s, volumeIndex: 0) }          // surface the real error
                    break
                }
                let its = v.nodes.map { n in ContainerItem(path: n.path, isDir: n.isDir, size: n.size, packed: n.size, mtime: n.mtime, mode: n.mode, link: n.link) }
                mounted.append(Mounted(name: v.name, kind: "APFS", items: its, open: { try v.stream(v.nodes[$0]) }))
                index += 1
            }
        }
        guard !mounted.isEmpty else { throw AXError.unsupported("this disk image’s file system (ArchiveX reads HFS+ and APFS volumes)") }
        let multi = mounted.count > 1
        for (vi, v) in mounted.enumerated() {
            let prefix = multi ? (v.name.isEmpty ? "Volume \(vi + 1)" : v.name) + "/" : ""
            for (i, it) in v.items.enumerated() {
                var c = it; c.path = prefix + it.path
                map.append((vi, i)); items.append(c)
            }
        }
        let kinds = Array(Set(mounted.map(\.kind))).sorted().joined(separator: ", ")
        details = "DMG · \(image.methods.sorted().joined(separator: ", ")) · \(kinds)" + (mounted.count == 1 && !mounted[0].name.isEmpty ? " “\(mounted[0].name)”" : "")
    }

    func stream(_ i: Int) throws -> ByteSource { try mounted[map[i].vol].open(map[i].index) }
}
