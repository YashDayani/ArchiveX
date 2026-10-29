import Foundation

// ZIP reader/writer (PKWARE APPNOTE 6.3.x): store + deflate, ZIP64, UTF-8 names, Unix modes,
// symlinks, extended timestamps, WinZip AES-256 (AE-2) and legacy ZipCrypto.

struct ZipEntry {
    var name: String
    var isDir: Bool
    var flags: UInt16
    var method: UInt16            // as stored (99 = AES wrapper)
    var realMethod: UInt16        // after unwrapping AES
    var dosTime: UInt16
    var dosDate: UInt16
    var crc: UInt32
    var csize: UInt64
    var usize: UInt64
    var localOffset: UInt64
    var madeBy: UInt16
    var intAttr: UInt16
    var extAttr: UInt32
    var extra: Data               // central extra fields except ZIP64
    var comment: Data
    var mtime: Date?
    var aesVersion: UInt16?
    var aesStrength: Int?

    var encrypted: Bool { flags & 1 != 0 }
    var unixMode: UInt32? { madeBy >> 8 == 3 ? extAttr >> 16 : nil }
    var isSymlink: Bool { unixMode.map { $0 & 0xF000 == 0xA000 } ?? false }
}

enum DOSTime {
    static func date(time: UInt16, date: UInt16) -> Date? {
        var c = DateComponents()
        c.year = 1980 + Int(date >> 9); c.month = Int((date >> 5) & 0xf); c.day = Int(date & 0x1f)
        c.hour = Int(time >> 11); c.minute = Int((time >> 5) & 0x3f); c.second = Int(time & 0x1f) * 2
        return Calendar.current.date(from: c)
    }
    static func encode(_ d: Date) -> (time: UInt16, date: UInt16) {
        let c = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute, .second], from: d)
        let y = max(1980, min(2107, c.year ?? 1980))
        let date = UInt16((y - 1980) << 9 | (c.month ?? 1) << 5 | (c.day ?? 1))
        let time = UInt16((c.hour ?? 0) << 11 | (c.minute ?? 0) << 5 | ((c.second ?? 0) / 2))
        return (time, date)
    }
}

// MARK: - Reader

final class ZipArchive {
    let file: FileIn
    private(set) var entries: [ZipEntry] = []
    private(set) var prefix: UInt64 = 0          // bytes before the archive proper (SFX stubs)
    private(set) var cdOffset: UInt64 = 0
    private var diskStarts: [UInt64] = []           // spanned (.z01 …) sets: where each disk begins in the joined file
    private(set) var comment = Data()

    init(url: URL) throws {
        file = try FileIn.openArchive(url)
        try parse()
    }

    private func parse() throws {
        let size = file.size
        guard size >= 22 else { throw AXError.corrupt("not a ZIP file") }
        let tailLen = Int(min(size, 65_557))
        let tailStart = size - UInt64(tailLen)
        let tail = try file.readExactly(at: tailStart, tailLen)
        var e = tailLen - 22
        while e >= 0, tail.le32(e) != 0x0605_4b50 { e -= 1 }
        guard e >= 0 else { throw AXError.corrupt("end of central directory not found") }
        let eocdAbs = tailStart + UInt64(e)

        var total = UInt64(tail.le16(e + 10))
        var cdSize = UInt64(tail.le32(e + 12))
        var cdOff = UInt64(tail.le32(e + 16))
        let commentLen = Int(tail.le16(e + 20))
        if e + 22 + commentLen <= tail.count { comment = tail.subdata(in: tail.startIndex + e + 22..<tail.startIndex + e + 22 + commentLen) }
        var endOfCD = eocdAbs
        // Info-ZIP style spanned sets: offsets are per disk, so they are shifted by where each disk starts in the joined file
        let thisDisk = Int(tail.le16(e + 4)), cdDisk = Int(tail.le16(e + 6))
        if thisDisk > 0 && file.parts.count > 1 {
            var starts: [UInt64] = []
            for pt in file.parts { starts.append(pt.start) }
            diskStarts = starts
        }

        if (total == 0xffff || cdSize == 0xffff_ffff || cdOff == 0xffff_ffff), eocdAbs >= 20 {
            let loc = try file.readExactly(at: eocdAbs - 20, 20)
            if loc.le32(0) == 0x0706_4b50 {
                let z64Off = loc.le64(8)
                let z = try file.readExactly(at: z64Off, 56)
                guard z.le32(0) == 0x0606_4b50 else { throw AXError.corrupt("bad ZIP64 directory") }
                total = z.le64(32); cdSize = z.le64(40); cdOff = z.le64(48)
                endOfCD = z64Off
            }
        }
        if !diskStarts.isEmpty {
            guard cdDisk < diskStarts.count else { throw AXError.corrupt("bad spanned ZIP directory") }
            cdOff += diskStarts[cdDisk]
        } else if cdOff + cdSize < endOfCD { prefix = endOfCD - (cdOff + cdSize) }
        cdOffset = cdOff

        guard cdSize < 1 << 31 else { throw AXError.unsupported("central directory too large") }
        let cd = try file.readExactly(at: cdOff + prefix, Int(cdSize))
        var p = 0
        var list: [ZipEntry] = []
        list.reserveCapacity(Int(min(total, 1 << 20)))
        while p + 46 <= cd.count, list.count < Int(total) {
            guard cd.le32(p) == 0x0201_4b50 else { throw AXError.corrupt("bad central directory entry") }
            let madeBy = cd.le16(p + 4), flags = cd.le16(p + 8), method = cd.le16(p + 10)
            let dt = cd.le16(p + 12), dd = cd.le16(p + 14)
            var crc = cd.le32(p + 16)
            var csize = UInt64(cd.le32(p + 20)), usize = UInt64(cd.le32(p + 24))
            let nl = Int(cd.le16(p + 28)), xl = Int(cd.le16(p + 30)), cl = Int(cd.le16(p + 32))
            let intAttr = cd.le16(p + 36), extAttr = cd.le32(p + 38)
            var lho = UInt64(cd.le32(p + 42))
            let startDisk = Int(cd.le16(p + 34))
            guard p + 46 + nl + xl + cl <= cd.count else { throw AXError.corrupt("truncated central directory") }
            let nameData = cd.subdata(in: cd.startIndex + p + 46..<cd.startIndex + p + 46 + nl)
            let extraData = cd.subdata(in: cd.startIndex + p + 46 + nl..<cd.startIndex + p + 46 + nl + xl)
            let commentData = cd.subdata(in: cd.startIndex + p + 46 + nl + xl..<cd.startIndex + p + 46 + nl + xl + cl)
            p += 46 + nl + xl + cl

            var keep = Data()
            var mtime: Date?
            var aesV: UInt16?, aesS: Int?, realMethod = method
            var unicodeName: String?
            var q = 0
            while q + 4 <= extraData.count {
                let id = extraData.le16(q), len = Int(extraData.le16(q + 2))
                guard q + 4 + len <= extraData.count else { break }
                let body = extraData.subdata(in: extraData.startIndex + q + 4..<extraData.startIndex + q + 4 + len)
                switch id {
                case 0x0001:                                    // ZIP64: only fields that were 0xFFFFFFFF
                    var o = 0
                    if usize == 0xffff_ffff, o + 8 <= body.count { usize = body.le64(o); o += 8 }
                    if csize == 0xffff_ffff, o + 8 <= body.count { csize = body.le64(o); o += 8 }
                    if lho == 0xffff_ffff, o + 8 <= body.count { lho = body.le64(o); o += 8 }
                case 0x5455:
                    if body.count >= 5, body[body.startIndex] & 1 != 0 {
                        mtime = Date(timeIntervalSince1970: TimeInterval(body.le32(1)))
                    }
                    keep.append(extraData.subdata(in: extraData.startIndex + q..<extraData.startIndex + q + 4 + len))
                case 0x9901:
                    if body.count >= 7 {
                        aesV = body.le16(0); aesS = Int(body[body.startIndex + 4]); realMethod = body.le16(5)
                    }
                    keep.append(extraData.subdata(in: extraData.startIndex + q..<extraData.startIndex + q + 4 + len))
                case 0x7075:                                    // Info-ZIP Unicode Path
                    if body.count > 5 { unicodeName = String(data: body.dropFirst(5), encoding: .utf8) }
                    keep.append(extraData.subdata(in: extraData.startIndex + q..<extraData.startIndex + q + 4 + len))
                default:
                    keep.append(extraData.subdata(in: extraData.startIndex + q..<extraData.startIndex + q + 4 + len))
                }
                q += 4 + len
            }
            if aesV == 2 { crc = 0 }
            if !diskStarts.isEmpty { guard startDisk < diskStarts.count else { throw AXError.corrupt("bad spanned ZIP directory") }; lho += diskStarts[startDisk] }
            let name = unicodeName ?? String(data: nameData, encoding: .utf8) ?? String(data: nameData, encoding: .isoLatin1) ?? ""
            let isDir = name.hasSuffix("/") || name.hasSuffix("\\") || (madeBy >> 8 != 3 && extAttr & 0x10 != 0 && usize == 0)
            list.append(ZipEntry(name: name, isDir: isDir, flags: flags, method: method, realMethod: realMethod,
                                 dosTime: dt, dosDate: dd, crc: crc, csize: csize, usize: usize, localOffset: lho,
                                 madeBy: madeBy, intAttr: intAttr, extAttr: extAttr, extra: keep, comment: commentData,
                                 mtime: mtime ?? DOSTime.date(time: dt, date: dd), aesVersion: aesV, aesStrength: aesS))
        }
        entries = list
    }

    var listing: Listing {
        var l = Listing()
        l.details = "ZIP" + (entries.contains { $0.aesStrength != nil } ? " · AES-256" : entries.contains { $0.encrypted } ? " · ZipCrypto" : "")
        l.entries = entries.map { e in
            let clean = SafePath.clean(e.name) ?? e.name
            return ArchiveEntry(path: clean, isDir: e.isDir, size: Int64(e.usize), packed: Int64(e.csize),
                                ratio: (!e.isDir && e.usize > 0) ? "\(min(100, Int(Double(e.csize) / Double(e.usize) * 100)))%" : "",
                                mtime: Dates.text(e.mtime), crc: e.isDir ? "" : (e.aesVersion == 2 ? "" : String(format: "%08X", e.crc)),
                                attrs: "", encrypted: e.encrypted)
        }
        return l
    }

    // MARK: decoding one entry

    /// Streams the (decrypted, decompressed) contents of `e` into `sink`, verifying CRC and size.
    func read(_ e: ZipEntry, password: String?, progress: ProgressTracker?, into sink: ByteSink) throws {
        guard [0, 8, 9, 12, 14].contains(e.realMethod) else {
            throw AXError.unsupported("ZIP compression method \(e.realMethod)")
        }
        if e.csize == 0 && e.usize == 0 { return }
        let lh = try file.readExactly(at: e.localOffset + prefix, 30)
        guard lh.le32(0) == 0x0403_4b50 else { throw AXError.corrupt("bad local header for “\(e.name)”") }
        var pos = e.localOffset + prefix + 30 + UInt64(lh.le16(26)) + UInt64(lh.le16(28))
        var remaining = e.csize

        var crc: UInt32 = 0
        var produced: UInt64 = 0
        let inflater: Inflater? = e.realMethod == 8 || e.realMethod == 9 ? Inflater(deflate64: e.realMethod == 9) : nil
        let pulled = e.realMethod == 12 || e.realMethod == 14        // bzip2 and LZMA are pulled through a decoder
        var finished = false

        func emit(_ d: Data) throws {
            crc = CRC32.update(crc, d)
            produced += UInt64(d.count)
            try sink.write(d)
            try progress?.add(d.count)
        }
        func feed(_ chunk: Data, last: Bool) throws {
            if let inf = inflater {
                if finished { return }
                if try inf.process(chunk, final: last, emit).ended { finished = true }
            } else {
                try emit(chunk)
            }
        }
        func pull(_ n: Int) throws -> Data {
            let d = try file.readExactly(at: pos, n); pos += UInt64(n); remaining -= UInt64(n); return d
        }

        let chunk = 1 << 20
        var aesMac: ZipAES.Mac?
        var aesCipher: ZipAES.Cipher?
        var zc: ZipCrypto?
        var tailBytes: UInt64 = 0

        if e.encrypted {
            guard let pw = password, !pw.isEmpty else { throw AXError.passwordRequired }
            if let strength = e.aesStrength {
                let sl = ZipAES.saltLength(strength)
                guard remaining >= UInt64(sl + 2 + 10) else { throw AXError.corrupt("truncated encrypted data") }
                let salt = try pull(sl), pwv = try pull(2)
                let keys = try ZipAES.deriveKeys(password: pw, salt: salt, strength: strength)
                guard keys.verifier == pwv else { throw AXError.wrongPassword }
                aesCipher = try ZipAES.Cipher(key: keys.enc)
                aesMac = ZipAES.Mac(key: keys.auth)
                tailBytes = 10
            } else {
                guard remaining >= 12 else { throw AXError.corrupt("truncated encrypted data") }
                var z = ZipCrypto(password: pw)
                let header = z.decrypt(try pull(12))
                let check = header[header.startIndex + 11]
                guard check == UInt8(truncatingIfNeeded: e.crc >> 24) || check == UInt8(truncatingIfNeeded: e.dosTime >> 8) else {
                    throw AXError.wrongPassword
                }
                zc = z
            }
        }

        func nextPacked() throws -> Data {
            guard remaining > tailBytes else { return Data() }
            let n = Int(min(UInt64(chunk), remaining - tailBytes))
            var d = try pull(n)
            if let mac = aesMac, let c = aesCipher { mac.update(d); d = try c.apply(d) }
            else if zc != nil { d = zc!.decrypt(d) }
            return d
        }
        if pulled {
            let packed = ClosureSource(nextPacked)
            let decoder: ByteSource
            if e.realMethod == 12 { decoder = try Bzip2Source(source: packed) }
            else {
                let head = try packed.readExactly(4)
                let psize = Int(head[head.startIndex + 2]) | Int(head[head.startIndex + 3]) << 8
                guard psize >= 5, psize <= 64 else { throw AXError.corrupt("bad LZMA properties in “\(e.name)”") }
                let props = try packed.readExactly(psize)
                decoder = try LzmaSource(input: packed, props: props, unpackSize: e.usize)
            }
            while produced < e.usize {
                let d = try decoder.read(Int(min(UInt64(chunk), e.usize - produced)))
                if d.isEmpty { throw AXError.corrupt("“\(e.name)” ended unexpectedly") }
                try emit(d)
            }
            while !(try packed.read(1 << 16)).isEmpty { }          // let the packed tail (and AES tag) through
        } else {
            while remaining > tailBytes {
                try feed(try nextPacked(), last: remaining == tailBytes)
            }
        }
        if let mac = aesMac {
            let tag = try pull(10)
            guard tag == mac.tag() else { throw AXError.corrupt("authentication failed for “\(e.name)”") }
        }
        if inflater != nil && !finished { try feed(Data(), last: true) }
        if inflater != nil && !finished { throw AXError.corrupt("“\(e.name)” ended unexpectedly") }

        guard produced == e.usize else { throw e.encrypted ? AXError.wrongPassword : AXError.corrupt("size mismatch in “\(e.name)”") }
        if !(e.aesVersion == 2), crc != e.crc { throw e.encrypted ? AXError.wrongPassword : AXError.corrupt("CRC mismatch in “\(e.name)”") }
    }

    func extract(selection: [(path: String, isDir: Bool)], to extractor: Extractor, password: String?,
                 progress: ProgressTracker?) throws {
        for e in entries {
            try Task.checkCancellation()
            guard let clean = SafePath.clean(e.name) else { if !e.name.isEmpty { _ = try extractor.destination(for: e.name, isDir: e.isDir) }; continue }
            guard extractor.isSelected(clean) else { continue }
            if e.isDir {
                if extractor.keepPaths, let url = try extractor.destination(for: e.name, isDir: true) {
                    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
                    extractor.finalize(url, mode: e.unixMode, mtime: e.mtime)
                }
                continue
            }
            if e.isSymlink {
                let sink = MemorySink()
                try read(e, password: password, progress: nil, into: sink)
                if let url = try extractor.destination(for: e.name, isDir: false),
                   let target = String(data: sink.data, encoding: .utf8) { extractor.makeSymlink(at: url, target: target) }
                continue
            }
            guard let url = try extractor.destination(for: e.name, isDir: false) else { try progress?.add(Int(e.usize)); continue }
            let out = try FileOut(url)
            do { try read(e, password: password, progress: progress, into: out) }
            catch { try? FileManager.default.removeItem(at: url); throw error }
            extractor.finalize(url, mode: e.unixMode, mtime: e.mtime)
        }
    }

    func test(password: String?, progress: ProgressTracker?) throws {
        for e in entries where !e.isDir {
            try read(e, password: password, progress: progress, into: NullSink())
        }
    }
}

// MARK: - Writer

struct ZipCentral {
    var name: Data
    var flags: UInt16
    var method: UInt16
    var dosTime: UInt16
    var dosDate: UInt16
    var crc: UInt32
    var csize: UInt64
    var usize: UInt64
    var offset: UInt64
    var madeBy: UInt16
    var versionNeeded: UInt16
    var intAttr: UInt16
    var extAttr: UInt32
    var extra: Data
    var comment: Data

    func serialized() -> Data {
        var z64 = Data()
        var u32 = UInt32(truncatingIfNeeded: usize), c32 = UInt32(truncatingIfNeeded: csize), o32 = UInt32(truncatingIfNeeded: offset)
        if usize >= 0xffff_ffff { u32 = 0xffff_ffff; z64.put64(usize) }
        if csize >= 0xffff_ffff { c32 = 0xffff_ffff; z64.put64(csize) }
        if offset >= 0xffff_ffff { o32 = 0xffff_ffff; z64.put64(offset) }
        var ex = Data()
        if !z64.isEmpty { ex.put16(0x0001); ex.put16(UInt16(z64.count)); ex.append(z64) }
        ex.append(extra)
        var d = Data()
        d.put32(0x0201_4b50)
        d.put16(madeBy); d.put16(z64.isEmpty ? versionNeeded : max(45, versionNeeded))
        d.put16(flags); d.put16(method); d.put16(dosTime); d.put16(dosDate)
        d.put32(crc); d.put32(c32); d.put32(u32)
        d.put16(UInt16(name.count)); d.put16(UInt16(ex.count)); d.put16(UInt16(comment.count))
        d.put16(0); d.put16(intAttr); d.put32(extAttr); d.put32(o32)
        d.append(name); d.append(ex); d.append(comment)
        return d
    }
}

final class ZipWriter {
    let out: FileOut
    private(set) var records: [ZipCentral] = []
    let password: String?
    let legacyCrypto: Bool
    let level: Int            // 0 = store

    init(url: URL, password: String?, legacyCrypto: Bool = false, level: Int = 6) throws {
        out = try FileOut(url)
        self.password = (password?.isEmpty ?? true) ? nil : password
        self.legacyCrypto = legacyCrypto
        self.level = level
    }

    private func extTime(_ d: Date) -> Data {
        var x = Data(); x.put16(0x5455); x.put16(5); x.append(1); x.put32(UInt32(max(0, min(4_294_967_295, d.timeIntervalSince1970))))
        return x
    }

    func addDirectory(name: String, mtime: Date, mode: UInt32) throws {
        let nm = Data((name.hasSuffix("/") ? name : name + "/").utf8)
        let (t, dt) = DOSTime.encode(mtime)
        let ex = extTime(mtime)
        let offset = out.position
        var h = Data()
        h.put32(0x0403_4b50); h.put16(20); h.put16(0x0800); h.put16(0); h.put16(t); h.put16(dt)
        h.put32(0); h.put32(0); h.put32(0); h.put16(UInt16(nm.count)); h.put16(UInt16(ex.count)); h.append(nm); h.append(ex)
        try out.write(h)
        records.append(ZipCentral(name: nm, flags: 0x0800, method: 0, dosTime: t, dosDate: dt, crc: 0, csize: 0, usize: 0,
                                  offset: offset, madeBy: 0x031E, versionNeeded: 20, intAttr: 0,
                                  extAttr: ((mode & 0o7777) | 0o040000) << 16 | 0x10, extra: ex, comment: Data()))
    }

    func addSymlink(name: String, target: String, mtime: Date) throws {
        let data = Data(target.utf8)
        let nm = Data(name.utf8)
        let (t, dt) = DOSTime.encode(mtime)
        let ex = extTime(mtime)
        let crc = CRC32.update(0, data)
        let offset = out.position
        var h = Data()
        h.put32(0x0403_4b50); h.put16(20); h.put16(0x0800); h.put16(0); h.put16(t); h.put16(dt)
        h.put32(crc); h.put32(UInt32(data.count)); h.put32(UInt32(data.count))
        h.put16(UInt16(nm.count)); h.put16(UInt16(ex.count)); h.append(nm); h.append(ex); h.append(data)
        try out.write(h)
        records.append(ZipCentral(name: nm, flags: 0x0800, method: 0, dosTime: t, dosDate: dt, crc: crc,
                                  csize: UInt64(data.count), usize: UInt64(data.count), offset: offset, madeBy: 0x031E,
                                  versionNeeded: 20, intAttr: 0, extAttr: (0o120755 as UInt32) << 16, extra: ex, comment: Data()))
    }

    func addFile(source: URL, name: String, mtime: Date, mode: UInt32, progress: ProgressTracker?) throws {
        let src = try FileIn(source)
        let nm = Data(name.utf8)
        let (t, dt) = DOSTime.encode(mtime)
        let ext = extTime(mtime)
        let size = src.size
        let useZip64 = size >= 0xffff_ffff
        let encrypted = password != nil && size > 0
        let aes = encrypted && !legacyCrypto
        var flags: UInt16 = 0x0800 | (encrypted ? 1 : 0)
        var method: UInt16 = (level == 0 || size == 0) ? 0 : 8

        // ZipCrypto's check byte comes from the CRC, so it needs a first pass over the file.
        var preCRC: UInt32 = 0
        if encrypted && legacyCrypto {
            var off: UInt64 = 0
            while off < size {
                let d = try src.read(at: off, 1 << 20)
                if d.isEmpty { break }
                preCRC = CRC32.update(preCRC, d); off += UInt64(d.count)
            }
        }

        let offset = out.position
        var attempt = 0
        while true {
            attempt += 1
            out.truncate(to: offset)

            var extra = Data()
            let z64Pos = extra.count
            if useZip64 { extra.put16(0x0001); extra.put16(16); extra.put64(size); extra.put64(0) }
            extra.append(ext)
            var aesMethodPos = -1
            if aes {
                extra.put16(0x9901); extra.put16(7); extra.put16(2); extra.append(contentsOf: [0x41, 0x45, 3])
                aesMethodPos = extra.count; extra.put16(method)
            }
            var h = Data()
            h.put32(0x0403_4b50)
            h.put16(useZip64 ? 45 : (aes ? 51 : 20))
            h.put16(flags); h.put16(aes ? 99 : method); h.put16(t); h.put16(dt)
            h.put32(0); h.put32(useZip64 ? 0xffff_ffff : 0); h.put32(useZip64 ? 0xffff_ffff : 0)
            h.put16(UInt16(nm.count)); h.put16(UInt16(extra.count)); h.append(nm); h.append(extra)
            try out.write(h)
            let dataStart = out.position

            // data
            var crc: UInt32 = 0
            var usize: UInt64 = 0
            var cipher: ZipAES.Cipher?, mac: ZipAES.Mac?
            var zc: ZipCrypto?
            if aes {
                var salt = Data(count: 16)
                _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
                let keys = try ZipAES.deriveKeys(password: password!, salt: salt, strength: 3)
                cipher = try ZipAES.Cipher(key: keys.enc); mac = ZipAES.Mac(key: keys.auth)
                try out.write(salt); try out.write(keys.verifier)
            } else if encrypted {
                var z = ZipCrypto(password: password!)
                var hdr = Data(count: 12)
                _ = hdr.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 11, $0.baseAddress!) }
                hdr[11] = UInt8(truncatingIfNeeded: preCRC >> 24)
                try out.write(z.encrypt(hdr)); zc = z
            }
            func put(_ d: Data) throws {
                var x = d
                if let c = cipher, let m = mac { x = try c.apply(d); m.update(x) } else if zc != nil { x = zc!.encrypt(d) }
                try out.write(x)
            }
            let deflater: Deflater? = method == 8 ? try Deflater(encode: true) : nil
            var off: UInt64 = 0
            if size == 0, let df = deflater { try df.process(Data(), final: true, put) }
            while off < size {
                let d = try src.read(at: off, 1 << 20)
                if d.isEmpty { break }
                off += UInt64(d.count)
                crc = CRC32.update(crc, d); usize += UInt64(d.count)
                if let df = deflater { try df.process(d, final: off >= size, put) } else { try put(d) }
                try progress?.add(d.count)
            }
            if let m = mac { try out.write(m.tag()) }
            let csize = out.position - dataStart

            // Not worth compressing? Redo as stored.
            let overhead: UInt64 = aes ? 28 : (encrypted ? 12 : 0)
            if method == 8 && attempt == 1 && csize - overhead >= usize && usize > 0 {
                method = 0; flags = flags & ~0
                continue
            }

            // patch header
            var patch = Data()
            let storedCRC: UInt32 = aes ? 0 : crc
            patch.put32(storedCRC)
            if useZip64 { patch.put32(0xffff_ffff); patch.put32(0xffff_ffff) } else { patch.put32(UInt32(csize)); patch.put32(UInt32(usize)) }
            try out.write(at: offset + 14, patch)
            if useZip64 {
                var z = Data(); z.put64(usize); z.put64(csize)
                try out.write(at: offset + 30 + UInt64(nm.count) + UInt64(z64Pos) + 4, z)
            }
            var recExtra = ext
            if aes { recExtra.put16(0x9901); recExtra.put16(7); recExtra.put16(2); recExtra.append(contentsOf: [0x41, 0x45, 3]); recExtra.put16(method) }
            _ = aesMethodPos
            records.append(ZipCentral(name: nm, flags: flags, method: aes ? 99 : method, dosTime: t, dosDate: dt, crc: storedCRC,
                                      csize: csize, usize: usize, offset: offset, madeBy: 0x031E,
                                      versionNeeded: useZip64 ? 45 : (aes ? 51 : 20), intAttr: 0,
                                      extAttr: (0o100000 | (mode & 0o7777)) << 16, extra: recExtra, comment: Data()))
            return
        }
    }

    /// Copies an entry's raw bytes (local header + data) from another archive without recompressing.
    func addRaw(from archive: ZipArchive, entry e: ZipEntry, endOffset: UInt64, progress: ProgressTracker?) throws {
        let start = e.localOffset + archive.prefix
        var pos = start
        let newOffset = out.position
        while pos < endOffset {
            let d = try archive.file.readExactly(at: pos, Int(min(UInt64(1 << 20), endOffset - pos)))
            try out.write(d); pos += UInt64(d.count)
        }
        try progress?.add(Int(e.usize))
        records.append(ZipCentral(name: Data(e.name.utf8), flags: e.flags, method: e.method, dosTime: e.dosTime, dosDate: e.dosDate,
                                  crc: e.aesVersion == 2 ? 0 : e.crc, csize: e.csize, usize: e.usize, offset: newOffset,
                                  madeBy: e.madeBy, versionNeeded: e.aesStrength != nil ? 51 : (e.csize >= 0xffff_ffff ? 45 : 20),
                                  intAttr: e.intAttr, extAttr: e.extAttr, extra: e.extra, comment: e.comment))
    }

    func finish() throws {
        let cdStart = out.position
        for r in records { try out.write(r.serialized()) }
        let cdSize = out.position - cdStart
        if records.count >= 0xffff || cdStart >= 0xffff_ffff || cdSize >= 0xffff_ffff {
            let z64Pos = out.position
            var z = Data()
            z.put32(0x0606_4b50); z.put64(44); z.put16(0x031E); z.put16(45); z.put32(0); z.put32(0)
            z.put64(UInt64(records.count)); z.put64(UInt64(records.count)); z.put64(cdSize); z.put64(cdStart)
            z.put32(0x0706_4b50); z.put32(0); z.put64(z64Pos); z.put32(1)
            try out.write(z)
        }
        var e = Data()
        e.put32(0x0605_4b50); e.put16(0); e.put16(0)
        e.put16(UInt16(min(records.count, 0xffff))); e.put16(UInt16(min(records.count, 0xffff)))
        e.put32(UInt32(min(cdSize, 0xffff_ffff))); e.put32(UInt32(min(cdStart, 0xffff_ffff))); e.put16(0)
        try out.write(e)
    }
}


/// A byte source fed by a closure that returns the next chunk (empty at the end).
final class ClosureSource: ByteSource {
    private let next: () throws -> Data
    private var buf = Data()
    init(_ next: @escaping () throws -> Data) { self.next = next }
    func read(_ n: Int) throws -> Data {
        if buf.isEmpty { buf = try next() }
        guard !buf.isEmpty else { return Data() }
        let take = min(n, buf.count)
        let d = buf.subdata(in: buf.startIndex..<buf.startIndex + take)
        buf = buf.subdata(in: buf.startIndex + take..<buf.endIndex)
        return d
    }
    func skip(_ n: UInt64) throws { try discard(n) }
}
