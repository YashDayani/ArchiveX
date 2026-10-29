import Foundation
import Compression

// Read-only APFS: container superblock, object maps, the file-system B-tree of a volume, extents, symbolic links and
// transparently compressed (decmpfs) files. Encrypted volumes and snapshots are not handled. Written from Apple's
// published APFS reference.

@inline(__always) private func l16(_ d: [UInt8], _ o: Int) -> Int { Int(d[o]) | Int(d[o + 1]) << 8 }
@inline(__always) private func l32(_ d: [UInt8], _ o: Int) -> Int { l16(d, o) | l16(d, o + 2) << 16 }
@inline(__always) private func l64(_ d: [UInt8], _ o: Int) -> UInt64 { UInt64(l32(d, o)) | UInt64(l32(d, o + 4)) << 32 }

final class ApfsVolume {
    struct Extent { var logical: UInt64; var length: UInt64; var physical: UInt64 }
    struct Inode {
        var parent: UInt64 = 0
        var privateID: UInt64 = 0
        var mtime: Date?
        var mode: UInt32 = 0
        var bsdFlags: UInt32 = 0
        var size: UInt64 = 0
    }
    struct XAttr { var embedded: [UInt8]?; var streamID: UInt64 = 0; var streamSize: UInt64 = 0 }
    struct Node {
        var path = ""
        var isDir = false
        var size: UInt64 = 0
        var mtime: Date?
        var mode: UInt32?
        var link: String?
        var inode: UInt64 = 0
    }

    private let disk: RandomAccess
    private let start: UInt64
    private let bs: Int
    private(set) var name = ""
    private(set) var nodes: [Node] = []

    private var inodes: [UInt64: Inode] = [:]
    private var children: [UInt64: [(name: String, id: UInt64)]] = [:]
    private var extents: [UInt64: [Extent]] = [:]
    private var xattrs: [UInt64: [String: XAttr]] = [:]

    static func probe(_ disk: RandomAccess, at start: UInt64) -> Bool {
        ((try? disk.read(at: start + 32, 4)) ?? Data()) == Data("NXSB".utf8)
    }

    private func block(_ n: UInt64) throws -> [UInt8] {
        let d = try disk.read(at: start + n * UInt64(bs), bs)
        guard d.count == bs else { throw AXError.corrupt("APFS block \(n) is outside the image") }
        return [UInt8](d)
    }

    // MARK: B-trees

    private struct BTree {
        let keySize: Int, valSize: Int          // fixed sizes (0 when variable)
    }

    private func isLeafNode(_ b: [UInt8]) -> Bool { l16(b, 32) & 2 != 0 }

    /// Calls `visit(key, value)` for every record of the tree, in key order. `resolve` turns a child pointer into a block.
    private func walk(_ paddr: UInt64, resolve: (UInt64) throws -> UInt64, depth: Int = 0, _ visit: ([UInt8], [UInt8]) throws -> Void) throws {
        guard depth < 12 else { throw AXError.corrupt("APFS tree is too deep") }
        try Task.checkCancellation()
        let b = try block(paddr)
        let flags = l16(b, 32), n = l32(b, 36)
        let root = flags & 1 != 0, leaf = flags & 2 != 0, fixed = flags & 4 != 0
        let tocStart = 56 + l16(b, 40), tocLen = l16(b, 42)
        let keyStart = tocStart + tocLen
        let valEnd = bs - (root ? 40 : 0)
        var keySize = 0, valSize = 0
        if fixed { // sizes come from the root node's info block; omap trees use 16/16
            keySize = 16; valSize = 16
        }
        guard n < bs, tocStart + n * (fixed ? 4 : 8) <= bs else { throw AXError.corrupt("bad APFS B-tree node") }
        for i in 0..<n {
            var k: ArraySlice<UInt8>, v: ArraySlice<UInt8>
            if fixed {
                let ko = l16(b, tocStart + i * 4), vo = l16(b, tocStart + i * 4 + 2)
                guard keyStart + ko + keySize <= bs, valEnd - vo >= 0, valEnd - vo + valSize <= bs else { throw AXError.corrupt("bad APFS B-tree entry") }
                k = b[keyStart + ko..<keyStart + ko + keySize]
                let vl = leaf ? valSize : 8
                v = b[valEnd - vo..<valEnd - vo + vl]
            } else {
                let ko = l16(b, tocStart + i * 8), kl = l16(b, tocStart + i * 8 + 2), vo = l16(b, tocStart + i * 8 + 4), vl = l16(b, tocStart + i * 8 + 6)
                guard keyStart + ko + kl <= bs, valEnd - vo >= 0, valEnd - vo + vl <= bs, valEnd - vo >= 0 else { throw AXError.corrupt("bad APFS B-tree entry") }
                k = b[keyStart + ko..<keyStart + ko + kl]
                v = b[valEnd - vo..<valEnd - vo + vl]
            }
            if leaf { try visit(Array(k), Array(v)) }
            else {
                guard v.count >= 8 else { throw AXError.corrupt("bad APFS B-tree entry") }
                let child = l64(Array(v), 0)
                try walk(try resolve(child), resolve: resolve, depth: depth + 1, visit)
            }
        }
    }

    /// Object map: virtual object id → block, for records not newer than `maxXid`.
    private func loadOmap(_ paddr: UInt64, maxXid: UInt64) throws -> [UInt64: UInt64] {
        let om = try block(paddr)
        let treeOID = l64(om, 48)
        var best: [UInt64: (xid: UInt64, paddr: UInt64)] = [:]
        try walk(treeOID, resolve: { $0 }) { k, v in
            let oid = l64(k, 0), xid = l64(k, 8)
            guard xid <= maxXid, l32(v, 0) & 1 == 0 else { return }
            if let cur = best[oid], cur.xid >= xid { return }
            best[oid] = (xid, l64(v, 8))
        }
        return best.mapValues { $0.paddr }
    }

    // MARK: opening

    init(disk: RandomAccess, start: UInt64, volumeIndex: Int = 0) throws {
        self.disk = disk; self.start = start
        let head = [UInt8](try disk.read(at: start, 4096))
        guard head.count == 4096, Array(head[32..<36]) == Array("NXSB".utf8) else { throw AXError.corrupt("not an APFS container") }
        bs = l32(head, 36)
        guard bs >= 4096, bs <= 65536, bs & (bs - 1) == 0 else { throw AXError.corrupt("bad APFS block size") }
        // the newest superblock lives in the checkpoint descriptor area; block 0 may be stale
        var sb = try block(0)
        let descBlocks = l32(sb, 104), descBase = l64(sb, 112)
        if descBase & (1 << 63) == 0, descBlocks > 0, descBlocks <= 4096 {
            for i in 0..<descBlocks {
                guard let b = try? block(descBase + UInt64(i)), l32(b, 24) & 0xffff == 1, Array(b[32..<36]) == Array("NXSB".utf8) else { continue }
                if l64(b, 16) > l64(sb, 16) { sb = b }
            }
        }
        let xid = l64(sb, 16)
        let omapOID = l64(sb, 160)
        let containerMap = try loadOmap(omapOID, maxXid: xid)
        var fsOIDs: [UInt64] = []
        for i in 0..<100 { let o = l64(sb, 184 + i * 8); if o != 0 { fsOIDs.append(o) } }
        guard volumeIndex < fsOIDs.count, let vPaddr = containerMap[fsOIDs[volumeIndex]] else { throw AXError.corrupt("APFS volume not found") }
        let vsb = try block(vPaddr)
        guard Array(vsb[32..<36]) == Array("APSB".utf8) else { throw AXError.corrupt("bad APFS volume superblock") }
        if l64(vsb, 264) & 1 == 0 { throw AXError.unsupported("encrypted APFS volumes") }
        let nameBytes = vsb[704..<960]
        name = String(decoding: nameBytes.prefix { $0 != 0 }, as: UTF8.self)
        let volXid = l64(vsb, 16)
        let volMap = try loadOmap(l64(vsb, 128), maxXid: volXid)
        guard let rootBlock = volMap[l64(vsb, 136)] else { throw AXError.corrupt("APFS file-system tree not found") }
        try walk(rootBlock, resolve: { oid in
            guard let p = volMap[oid] else { throw AXError.corrupt("APFS object \(oid) is missing") }
            return p
        }) { k, v in self.record(k, v) }
        buildTree()
    }

    private func record(_ k: [UInt8], _ v: [UInt8]) {
        guard k.count >= 8 else { return }
        let h = l64(k, 0)
        let oid = h & 0x0fff_ffff_ffff_ffff, type = Int(h >> 60)
        switch type {
        case 3 where v.count >= 92:
            var ino = Inode()
            ino.parent = l64(v, 0); ino.privateID = l64(v, 8)
            ino.mtime = Date(timeIntervalSince1970: TimeInterval(l64(v, 24)) / 1e9)
            ino.bsdFlags = UInt32(l32(v, 68)); ino.mode = UInt32(l16(v, 80))
            ino.size = l64(v, 84)
            // extended fields: a blob of typed entries; type 8 is the data stream (its first 8 bytes are the size)
            if v.count >= 96 {
                let count = l16(v, 92)
                var dataOff = 96 + count * 4
                for i in 0..<count {
                    let t = Int(v[96 + i * 4]), sz = l16(v, 96 + i * 4 + 2)
                    if t == 8, dataOff + 8 <= v.count { ino.size = l64(v, dataOff) }
                    dataOff += (sz + 7) & ~7
                }
            }
            inodes[oid] = ino
        case 9 where v.count >= 10:
            var nameBytes: ArraySlice<UInt8>
            if k.count >= 12, 12 + (l32(k, 8) & 0x3ff) == k.count { nameBytes = k[12...] }        // hashed key (case-insensitive volumes)
            else if k.count >= 10, 10 + l16(k, 8) == k.count { nameBytes = k[10...] }              // plain key
            else { return }
            let nm = String(decoding: nameBytes.prefix { $0 != 0 }, as: UTF8.self)
            children[oid, default: []].append((nm, l64(v, 0)))
        case 8 where k.count >= 16 && v.count >= 16:
            extents[oid, default: []].append(Extent(logical: l64(k, 8), length: l64(v, 0) & 0x00ff_ffff_ffff_ffff, physical: l64(v, 8)))
        case 4 where k.count >= 10 && v.count >= 4:
            let nl = l16(k, 8)
            guard k.count >= 10 + nl else { return }
            let nm = String(decoding: k[10..<10 + nl].prefix { $0 != 0 }, as: UTF8.self)
            guard nm == "com.apple.fs.symlink" || nm == "com.apple.decmpfs" || nm == "com.apple.ResourceFork" else { return }
            let flags = l16(v, 0), len = l16(v, 2)
            var xa = XAttr()
            if flags & 2 != 0, v.count >= 4 + len { xa.embedded = Array(v[4..<4 + len]) }
            else if flags & 1 != 0, v.count >= 4 + 8 + 8 { xa.streamID = l64(v, 4); xa.streamSize = l64(v, 12) }
            else { return }
            xattrs[oid, default: [:]][nm] = xa
        default: break
        }
    }

    private func buildTree() {
        func walk(_ dir: UInt64, _ prefix: String, depth: Int) {
            guard depth < 200 else { return }
            for c in (children[dir] ?? []).sorted(by: { $0.name < $1.name }) {
                guard let ino = inodes[c.id] else { continue }
                var n = Node()
                n.path = prefix + c.name.replacingOccurrences(of: "/", with: ":")
                n.mtime = ino.mtime; n.mode = ino.mode & 0o7777; n.inode = c.id
                let fmt = ino.mode & 0o170000
                if fmt == 0o040000 { n.isDir = true }
                else if fmt == 0o120000 {
                    if let s = xattrs[c.id]?["com.apple.fs.symlink"]?.embedded { n.link = String(decoding: s.prefix { $0 != 0 }, as: UTF8.self) }
                    else { n.link = "" }
                } else if fmt == 0o100000 {
                    n.size = ino.size
                    if let cm = xattrs[c.id]?["com.apple.decmpfs"]?.embedded, cm.count >= 16, ino.bsdFlags & 0x20 != 0 { n.size = l64(cm, 8) }
                } else { continue }                                // sockets, devices, …
                nodes.append(n)
                if n.isDir { walk(c.id, n.path + "/", depth: depth + 1) }
            }
        }
        walk(2, "", depth: 0)
    }

    // MARK: file data

    private func readStream(id: UInt64, size: UInt64) -> ByteSource { ApfsStream(self, id: id, size: size) }

    fileprivate func readExtents(_ id: UInt64, at pos: UInt64, _ count: Int) throws -> Data {
        guard let list = extents[id] else { return Data(count: count) }
        var out = Data()
        var p = pos
        let end = pos + UInt64(count)
        while p < end {
            if let e = list.last(where: { $0.logical <= p }), p < e.logical + e.length {
                let take = Int(min(end, e.logical + e.length) - p)
                if e.physical == 0 { out.append(Data(count: take)) }
                else {
                    let d = try disk.read(at: start + e.physical * UInt64(bs) + (p - e.logical), take)
                    guard d.count == take else { throw AXError.corrupt("APFS file data is outside the image") }
                    out.append(d)
                }
                p += UInt64(take)
            } else {
                // a hole up to the next extent
                let next = list.first(where: { $0.logical > p })?.logical ?? end
                let take = Int(min(end, next) - p)
                out.append(Data(count: max(take, 0))); p += UInt64(max(take, 1))
            }
        }
        return out
    }

    func stream(_ n: Node) throws -> ByteSource {
        guard let ino = inodes[n.inode] else { throw AXError.corrupt("missing APFS inode") }
        if ino.bsdFlags & 0x20 != 0, let cm = xattrs[n.inode]?["com.apple.decmpfs"]?.embedded {
            return MemorySource(try Decmpfs.decode(cm) { try self.resourceFork(n.inode) })
        }
        return readStream(id: ino.privateID, size: n.size)
    }

    fileprivate func resourceFork(_ id: UInt64) throws -> Data {
        guard let x = xattrs[id]?["com.apple.ResourceFork"] else { throw AXError.corrupt("missing resource fork of a compressed file") }
        if let e = x.embedded { return Data(e) }
        return try readStream(id: x.streamID, size: x.streamSize).readAll(limit: Int(x.streamSize) + 1)
    }
}

private final class ApfsStream: ByteSource {
    let v: ApfsVolume; let id: UInt64; let size: UInt64; var pos: UInt64 = 0
    init(_ v: ApfsVolume, id: UInt64, size: UInt64) { self.v = v; self.id = id; self.size = size }
    func read(_ n: Int) throws -> Data {
        guard pos < size else { return Data() }
        let d = try v.readExtents(id, at: pos, Int(min(UInt64(n), size - pos, 1 << 20)))
        pos += UInt64(d.count)
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}

/// Transparent file compression ("decmpfs") shared by HFS+ and APFS: a small header (`fpmc`, type, size) followed by inline data,
/// or the data lives in the resource fork as a table of 64 KB blocks.
enum Decmpfs {
    static func lzDecode(_ src: Data, _ want: Int, _ algo: compression_algorithm) throws -> Data {
        var dst = Data(count: want)
        let n = dst.withUnsafeMutableBytes { d in src.withUnsafeBytes { s in
            compression_decode_buffer(d.bindMemory(to: UInt8.self).baseAddress!, want, s.bindMemory(to: UInt8.self).baseAddress!, src.count, nil, algo)
        } }
        guard n == want else { throw AXError.corrupt("damaged compressed file data") }
        return dst
    }

    static func decode(_ cm: [UInt8], resource: () throws -> Data) throws -> Data {
        guard cm.count >= 16, Array(cm[0..<4]) == Array("fpmc".utf8) else { throw AXError.corrupt("bad compression header") }
        let type = l32(cm, 4), size = Int(l64(cm, 8))
        guard size < 1 << 32 else { throw AXError.unsupported("huge compressed files") }
        let inline = Data(cm[16...])
        func block(_ d: Data, _ want: Int, zlib: Bool, lzvn: Bool) throws -> Data {
            if d.first == 0xff { return d.dropFirst() }                                        // stored uncompressed
            if zlib { return try ZlibSource(MemorySource(d)).readAll(limit: want + 1) }
            return try lzDecode(d, want, lzvn ? compression_algorithm(rawValue: 0x900) : COMPRESSION_LZFSE)
        }
        switch type {
        case 3, 7, 11: return try block(inline, size, zlib: type == 3, lzvn: type == 7)
        case 9: return inline.first == 0xcc ? inline.dropFirst() : inline
        case 10: return try resource()
        case 8, 12: return try blocks(try resource(), size: size, lzvn: type == 8)
        case 4: throw AXError.unsupported("files compressed with the old zlib resource-fork layout")
        default: throw AXError.unsupported("compressed file type \(type)")
        }
    }

    /// LZVN / LZFSE data in the resource fork: a table of little-endian block offsets (count + 1 of them), then the blocks,
    /// each decoding to 64 KB (the last one to the remainder).
    private static func blocks(_ r: Data, size: Int, lzvn: Bool) throws -> Data {
        let rb = [UInt8](r)
        guard rb.count >= 8 else { throw AXError.corrupt("bad compressed file resource fork") }
        let firstBlock = l32(rb, 0)
        guard firstBlock >= 8, firstBlock % 4 == 0, firstBlock <= rb.count else { throw AXError.corrupt("bad compressed file resource fork") }
        let count = firstBlock / 4 - 1
        let offs = (0...count).map { l32(rb, $0 * 4) }
        var out = Data()
        out.reserveCapacity(size)
        for i in 0..<count {
            let end = i + 1 == count ? rb.count : offs[i + 1]
            guard offs[i] <= end, end <= rb.count else { throw AXError.corrupt("bad compressed file block table") }
            let blk = Data(rb[offs[i]..<end])
            let want = min(65536, size - out.count)
            guard want > 0 else { break }
            if blk.first == 0xff { out.append(blk.dropFirst().prefix(want)) }
            else { out.append(try lzDecode(blk, want, lzvn ? compression_algorithm(rawValue: 0x900) : COMPRESSION_LZFSE)) }
        }
        guard out.count == size else { throw AXError.corrupt("compressed file has the wrong length") }
        return out
    }
}
