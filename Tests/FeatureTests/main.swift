import Foundation
import CryptoKit

// Test suite for ArchiveX's roadmap features:
// 1. Archive Comments (ZIP EOCD comments, preservation across edits, independent unzip check)
// 2. Multi-Core / Parallel Extraction (concurrent decompression, directory order, symlinks, CRC integrity)
// 3. Split Archive Creation (.001, .002, ... slicing across ZIP, 7z, TAR, and reassembly / extraction)
//
// Usage:
//   swiftc -O -swift-version 5 Sources/Engine.swift Sources/Core/*.swift Tests/FeatureTests/main.swift -o /tmp/FeatureTests
//   /tmp/FeatureTests <work-dir>

setvbuf(stdout, nil, _IOLBF, 0)
let fm = FileManager.default
let work = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("ft-\(Int(Date().timeIntervalSince1970))")
try! fm.createDirectory(at: work, withIntermediateDirectories: true)

var pass = 0, fail = 0
func check(_ name: String, _ ok: Bool, _ note: String = "") {
    if ok { pass += 1; print("PASS", name) } else { fail += 1; print("FAIL", name, note) }
}
func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
@discardableResult func sh(_ cmd: String) -> (status: Int32, out: String) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = ["-c", cmd]
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe; p.standardInput = FileHandle.nullDevice
    try? p.run(); let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return (p.terminationStatus, String(decoding: d, as: UTF8.self))
}

print("=== 1. Archive Comments (ZIP) ===")
do {
    let src = work.appendingPathComponent("comment_src")
    try fm.createDirectory(at: src, withIntermediateDirectories: true)
    try "hello world\n".write(to: src.appendingPathComponent("note.txt"), atomically: true, encoding: .utf8)

    let commentText = "ArchiveX v1.3\nRelease Notes:\n✓ Multi-core extraction\n✓ Split creation\n✓ Pure Swift"
    let zipURL = work.appendingPathComponent("commented.zip")

    try AXCore.create(AXCreate(format: .zip, output: zipURL, items: [src.appendingPathComponent("note.txt")],
                               comment: commentText), progress: { _ in })

    let l = try AXCore.list(zipURL, password: nil)
    check("listing reads back the exact ZIP comment", l.comment == commentText, "Got: \(l.comment ?? "nil")")

    // Independent check using macOS /usr/bin/unzip -z
    let unzipCheck = sh("/usr/bin/unzip -z '\(zipURL.path)'")
    check("macOS unzip recognizes the comment", unzipCheck.status == 0 && unzipCheck.out.contains("Multi-core extraction"), unzipCheck.out)

    // Edit archive (add file) and verify comment is preserved
    let addedFile = work.appendingPathComponent("added.txt")
    try "another file\n".write(to: addedFile, atomically: true, encoding: .utf8)
    try AXCore.edit(zipURL, remove: [], add: [addedFile], level: 3, password: nil, legacy: false, progress: { _ in })

    let l2 = try AXCore.list(zipURL, password: nil)
    check("comment is preserved after archive edit", l2.comment == commentText, "Got: \(l2.comment ?? "nil")")
    check("edited archive contains both files", l2.entries.count == 2)
} catch {
    check("archive comment tests", false, "\(error)")
}

print("\n=== 2. Multi-Core / Parallel Extraction ===")
do {
    let src = work.appendingPathComponent("multi_src")
    try fm.createDirectory(at: src.appendingPathComponent("sub/nested"), withIntermediateDirectories: true)

    var fileHashes: [String: String] = [:]
    // Generate 40 files across multiple subfolders
    for i in 1...40 {
        let name = i <= 20 ? "file_\(i).txt" : "sub/nested/data_\(i).bin"
        let u = src.appendingPathComponent(name)
        let data: Data
        if i % 2 == 0 {
            data = Data((0..<20_000).map { UInt8(($0 + i) & 0xFF) })
        } else {
            data = Data("Content of file \(i) — \n".utf8)
        }
        try data.write(to: u)
        fileHashes[name] = sha256(data)
    }
    // Add a symlink
    let linkPath = src.appendingPathComponent("sub/nested/link_to_file1.txt").path
    try? fm.createSymbolicLink(atPath: linkPath, withDestinationPath: "../../file_1.txt")

    let zipURL = work.appendingPathComponent("multi_files.zip")
    try AXCore.create(AXCreate(format: .zip, output: zipURL, items: [src]), progress: { _ in })

    // Test archive integrity across cores
    try AXCore.test(zipURL, password: nil, progress: { _ in })
    check("multi-core archive test passes with 40+ files", true)

    // Parallel extract
    let dest = work.appendingPathComponent("extracted_multi")
    try AXCore.extract(zipURL, selection: [], to: dest, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })

    var allMatch = true
    for (rel, expHash) in fileHashes {
        let extractedURL = dest.appendingPathComponent("multi_src/" + rel)
        guard let d = try? Data(contentsOf: extractedURL) else {
            print("Missing extracted file:", rel)
            allMatch = false
            break
        }
        if sha256(d) != expHash {
            print("Hash mismatch on extracted file:", rel)
            allMatch = false
            break
        }
    }
    check("parallel extraction extracted all 40 files with correct SHA-256", allMatch)

    // Verify symlink
    let extractedLink = dest.appendingPathComponent("multi_src/sub/nested/link_to_file1.txt")
    let target = try? fm.destinationOfSymbolicLink(atPath: extractedLink.path)
    check("symlink preserved correctly", target == "../../file_1.txt", "Got: \(target ?? "nil")")
} catch {
    check("multi-core extraction tests", false, "\(error)")
}

print("\n=== 3. Split Archive Creation ===")
do {
    let src = work.appendingPathComponent("split_src")
    try fm.createDirectory(at: src, withIntermediateDirectories: true)
    // Create a 700 KB payload
    let payload = Data((0..<700_000).map { UInt8($0 & 0xFF) })
    try payload.write(to: src.appendingPathComponent("large.bin"))
    try "small config\n".write(to: src.appendingPathComponent("config.txt"), atomically: true, encoding: .utf8)

    let splitSize: UInt64 = 200_000  // 200 KB chunks

    // 3a. Split ZIP
    let splitZip = work.appendingPathComponent("bundle.zip")
    try AXCore.create(AXCreate(format: .zip, output: splitZip, items: [src],
                               level: 0, splitVolumeSize: splitSize), progress: { _ in })

    let zipPart1 = work.appendingPathComponent("bundle.zip.001")
    let zipPart2 = work.appendingPathComponent("bundle.zip.002")
    let zipPart3 = work.appendingPathComponent("bundle.zip.003")
    check("split ZIP created .001, .002, .003 parts",
          fm.fileExists(atPath: zipPart1.path) && fm.fileExists(atPath: zipPart2.path) && fm.fileExists(atPath: zipPart3.path))

    check("AXCore detects split ZIP kind from .001", AXCore.kind(of: zipPart1) == .zip)

    let listZip = try AXCore.list(zipPart1, password: nil)
    check("AXCore lists files from split ZIP", listZip.entries.contains { $0.path.contains("large.bin") })

    let extractZipDir = work.appendingPathComponent("extracted_split_zip")
    try AXCore.extract(zipPart1, selection: [], to: extractZipDir, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    let recoveredDataZip = try? Data(contentsOf: extractZipDir.appendingPathComponent("split_src/large.bin"))
    check("split ZIP extracted file matches original 700 KB payload", recoveredDataZip == payload)

    // 3b. Split 7z
    let split7z = work.appendingPathComponent("bundle.7z")
    try AXCore.create(AXCreate(format: .sevenZ, output: split7z, items: [src],
                               splitVolumeSize: splitSize), progress: { _ in })

    let sevenZPart1 = work.appendingPathComponent("bundle.7z.001")
    check("split 7z created .001 part", fm.fileExists(atPath: sevenZPart1.path))
    check("AXCore detects split 7z kind from .001", AXCore.kind(of: sevenZPart1) == .sevenZ)

    let extract7zDir = work.appendingPathComponent("extracted_split_7z")
    try AXCore.extract(sevenZPart1, selection: [], to: extract7zDir, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    let recoveredData7z = try? Data(contentsOf: extract7zDir.appendingPathComponent("split_src/large.bin"))
    check("split 7z extracted file matches original 700 KB payload", recoveredData7z == payload)

    // 3c. Split TAR
    let splitTar = work.appendingPathComponent("bundle.tar")
    try AXCore.create(AXCreate(format: .tar, output: splitTar, items: [src],
                               splitVolumeSize: splitSize), progress: { _ in })

    let tarPart1 = work.appendingPathComponent("bundle.tar.001")
    check("split TAR created .001 part", fm.fileExists(atPath: tarPart1.path))
    check("AXCore detects split TAR kind from .001", AXCore.kind(of: tarPart1) == .tar)

    let extractTarDir = work.appendingPathComponent("extracted_split_tar")
    try AXCore.extract(tarPart1, selection: [], to: extractTarDir, overwrite: .all, keepPaths: true, password: nil, progress: { _ in })
    let recoveredDataTar = try? Data(contentsOf: extractTarDir.appendingPathComponent("split_src/large.bin"))
    check("split TAR extracted file matches original 700 KB payload", recoveredDataTar == payload)
} catch {
    check("split archive creation tests", false, "\(error)")
}

// Re-creating a split set under the same name must not leave parts of the older, larger set behind.
do {
    let dir = work.appendingPathComponent("stale_parts"); try fm.createDirectory(at: dir, withIntermediateDirectories: true)
    let out = dir.appendingPathComponent("set.zip")
    func make(_ size: Int) throws {
        let f = dir.appendingPathComponent("src\(size).bin")
        try Data((0..<size).map { _ in UInt8.random(in: 0...255) }).write(to: f)
        var spec = AXCreate(format: .zip, output: out, items: [f], level: 0, password: nil, legacyZipCrypto: false, deleteAfter: false)
        spec.splitVolumeSize = 16_384
        try AXCore.create(spec, progress: { _ in })
    }
    func parts() -> Int { ((try? fm.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasPrefix("set.zip.") }.count }
    try make(200_000)
    let big = parts()
    try make(3_000)
    check("re-creating a split set removes the older, extra parts", big > 2 && parts() == 1, "\(big) -> \(parts())")
    try AXCore.test(dir.appendingPathComponent("set.zip.001"), password: nil, progress: { _ in })
    check("the re-created split set tests clean", true)
} catch {
    check("stale split parts", false, "\(error)")
}

print("\nRESULT: \(pass) passed, \(fail) failed")
exit(fail == 0 ? 0 : 1)

