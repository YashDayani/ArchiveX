import SwiftUI

// MARK: - "Archive name and parameters"

struct AddSheet: View {
    @EnvironmentObject var model: ArchiveModel
    @Environment(\.dismiss) private var dismiss
    @State var draft: AddDraft
    @State private var tabsPass = 0

    init(draft: AddDraft) { _draft = State(initialValue: draft) }

    private let levels = ["Store", "Fastest", "Fast", "Normal", "Good", "Best"]

    private var passwordsMatch: Bool { draft.password == draft.confirm }
    private var valid: Bool { !draft.archivePath.isEmpty && !draft.files.isEmpty && passwordsMatch }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(draft.updatingExisting ? "Add to Archive" : "Create Archive").font(.title3.weight(.semibold))
                .padding([.top, .horizontal], 20).padding(.bottom, 8)

            TabView {
                general.tabItem { Text("General") }
                security.tabItem { Text("Password") }
            }
            .padding(.horizontal, 12)
            .frame(height: 300)
            // macOS draws the tab labels squeezed ("G…", "P…") on the first layout pass and fixes them on the next one,
            // so build the tab view a second time right after the sheet has appeared.
            .id(tabsPass)
            .onAppear { DispatchQueue.main.async { tabsPass = 1 } }

            Divider()
            HStack {
                if !passwordsMatch { Label("Passwords do not match", systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.caption) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(draft.updatingExisting ? "Add" : "Create") {
                    model.create(draft); dismiss()
                }
                .keyboardShortcut(.defaultAction).disabled(!valid)
            }
            .padding(16)
        }
        .frame(width: 540)
    }

    private var general: some View {
        Form {
            HStack {
                TextField("Archive", text: $draft.archivePath)
                Button("Browse…") { if let p = Panels.chooseSaveLocation(current: draft.archivePath) { draft.archivePath = p } }
            }
            Picker("Format", selection: $draft.format) {
                ForEach(ArchiveFormat.allCases) { Text($0.rawValue).tag($0) }
            }
            .disabled(draft.updatingExisting && model.hasArchive && draft.archivePath == model.archiveURL?.path)
            .onChange(of: draft.format) { f in
                draft.archivePath = Self.swapExtension(draft.archivePath, to: f)
                if !f.password { draft.password = ""; draft.confirm = "" }
            }
            if draft.format.level {
                Picker("Compression", selection: $draft.level) {
                    ForEach(0..<6) { Text(levels[$0]).tag($0) }
                }
            }
            if draft.format == .rar {
                Text("RAR archives made by ArchiveX store files without compressing them. Choose 7z for the smallest files.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if draft.format.solid { Toggle("Create solid archive (smaller, slower to edit)", isOn: $draft.solid) }
            Toggle("Test archived files", isOn: $draft.test)
            Toggle("Delete files after archiving", isOn: $draft.deleteAfter)
            Text("\(draft.files.count) item\(draft.files.count == 1 ? "" : "s") to add: \(draft.files.prefix(3).map(\.lastPathComponent).joined(separator: ", "))\(draft.files.count > 3 ? "…" : "")")
                .font(.caption).foregroundStyle(.secondary).lineLimit(2)
            if draft.updatingExisting {
                Text("An archive with this name exists — the files will be added to it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(16)
    }

    private var security: some View {
        Form {
            if draft.format.password {
                SecureField("Enter password", text: $draft.password)
                SecureField("Reenter password", text: $draft.confirm)
                if draft.format.headerEncryption {
                    Toggle("Encrypt file names", isOn: $draft.encryptNames).disabled(draft.password.isEmpty)
                }
                if draft.format == .zip && !draft.password.isEmpty {
                    Toggle("Compatible with macOS Archive Utility (weaker ZipCrypto)", isOn: $draft.legacyZipCrypto)
                }
                Text(draft.format == .zip
                     ? (draft.legacyZipCrypto ? "Legacy ZipCrypto is easy to break. Use it only if you need to open the file in Archive Utility."
                                              : "ZIP archives are encrypted with AES-256. File names stay visible.")
                     : draft.format == .rar
                     ? "RAR archives are encrypted with AES-256. File names stay visible."
                     : "Archives are encrypted with AES-256. Without “Encrypt file names”, people can still see what is inside but cannot read the files.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("\(draft.format.rawValue) archives cannot be password protected. Choose 7z, RAR or ZIP for encryption.")
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
    }

    private static func swapExtension(_ path: String, to f: ArchiveFormat) -> String {
        var p = path
        let lower = p.lowercased()
        for k in ArchiveFormat.allCases.sorted(by: { $0.ext.count > $1.ext.count }) where lower.hasSuffix("." + k.ext) {
            p = String(p.dropLast(k.ext.count + 1)); break
        }
        return p + "." + f.ext
    }
}

// MARK: - "Extraction path and options"

struct ExtractSheet: View {
    @EnvironmentObject var model: ArchiveModel
    @Environment(\.dismiss) private var dismiss
    @State var draft: ExtractDraft

    init(draft: ExtractDraft) { _draft = State(initialValue: draft) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Extract Files").font(.title3.weight(.semibold))
            HStack {
                TextField("Destination folder", text: $draft.destination)
                Button("Browse…") { if let p = Panels.chooseFolder(start: draft.destination) { draft.destination = p } }
            }
            if draft.hasSelection {
                Picker("Files", selection: $draft.onlySelected) {
                    Text("All files").tag(false)
                    Text("Selected files only").tag(true)
                }.pickerStyle(.radioGroup).horizontalRadioGroupLayout()
            }
            Picker("If a file exists", selection: $draft.overwrite) {
                ForEach(ExtractDraft.Overwrite.allCases) { Text($0.rawValue).tag($0) }
            }
            Toggle("Keep folder structure", isOn: $draft.keepPaths)
            Toggle("Show in Finder when finished", isOn: $draft.openAfter)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Extract") { model.extract(draft); dismiss() }
                    .keyboardShortcut(.defaultAction).disabled(draft.destination.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 500)
    }
}

// MARK: - Password

struct PasswordSheet: View {
    @EnvironmentObject var model: ArchiveModel
    @State private var pw = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Password required").font(.title3.weight(.semibold))
            Text("“\(model.title)” is encrypted. Enter the password to continue.")
                .foregroundStyle(.secondary)
            SecureField("Password", text: $pw).onSubmit(submit)
            HStack {
                Spacer()
                Button("Cancel") { model.cancelPassword() }.keyboardShortcut(.cancelAction)
                Button("OK", action: submit).keyboardShortcut(.defaultAction).disabled(pw.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func submit() { guard !pw.isEmpty else { return }; model.submitPassword(pw) }
}

// MARK: - Archive Properties / Info (⌘I)

struct InfoSheet: View {
    let info: ArchiveInfo
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "archivebox.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(info.name).font(.title3.weight(.semibold)).lineLimit(1)
                    Text(info.formatName + " archive").font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
            }

            Divider()

            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                GridRow {
                    Text("Location:").foregroundStyle(.secondary)
                    Text(info.path).lineLimit(1).truncationMode(.middle)
                }
                GridRow {
                    Text("Archive size:").foregroundStyle(.secondary)
                    Text(Fmt.bytes(info.fileSize))
                }
                GridRow {
                    Text("Contents:").foregroundStyle(.secondary)
                    Text("\(info.fileCount) file\(info.fileCount == 1 ? "" : "s"), \(info.folderCount) folder\(info.folderCount == 1 ? "" : "s")")
                }
                GridRow {
                    Text("Unpacked size:").foregroundStyle(.secondary)
                    Text(Fmt.bytes(info.totalUncompressed))
                }
                GridRow {
                    Text("Packed size:").foregroundStyle(.secondary)
                    Text(Fmt.bytes(info.totalPacked))
                }
                GridRow {
                    Text("Compression ratio:").foregroundStyle(.secondary)
                    Text(info.compressionRatio)
                }
                GridRow {
                    Text("Solid archive:").foregroundStyle(.secondary)
                    Text(info.isSolid ? "Yes" : "No")
                }
                GridRow {
                    Text("Encryption:").foregroundStyle(.secondary)
                    Text(info.encryptionDetails)
                }
                if !info.details.isEmpty {
                    GridRow {
                        Text("Format details:").foregroundStyle(.secondary)
                        Text(info.details)
                    }
                }
            }
            .font(.callout)

            Divider()

            HStack {
                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(info.path, forType: .string)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 480)
    }
}

// MARK: - Checksums & Hashes

struct HashSheet: View {
    let results: [ArchiveHasher.Result]
    @Environment(\.dismiss) private var dismiss
    @State private var verifyInput = ""
    @State private var copiedAlgorithm: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "number.square.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(.tint)
                Text(results.count == 1 ? "Checksums: \(results[0].name)" : "Checksums (\(results.count) files)")
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                Spacer()
            }

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(results) { r in
                        VStack(alignment: .leading, spacing: 6) {
                            if results.count > 1 {
                                Text(r.name).font(.headline).lineLimit(1)
                            }
                            hashRow(title: "CRC32", value: r.crc32)
                            hashRow(title: "MD5", value: r.md5)
                            hashRow(title: "SHA-1", value: r.sha1)
                            hashRow(title: "SHA-256", value: r.sha256)
                        }
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.04)))
                    }
                }
            }
            .frame(maxHeight: 280)

            Divider()

            // Hash verification field
            VStack(alignment: .leading, spacing: 6) {
                Text("Verify against expected hash:").font(.caption).foregroundStyle(.secondary)
                HStack {
                    TextField("Paste checksum here to verify…", text: $verifyInput)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                    if !verifyInput.isEmpty {
                        Button { verifyInput = "" } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                if !verifyInput.trimmingCharacters(in: .whitespaces).isEmpty {
                    verificationStatusView
                }
            }

            HStack {
                Button("Copy All") {
                    var text = ""
                    for r in results {
                        text += "\(r.name) (\(Fmt.bytes(r.size)))\n"
                        text += "CRC32:   \(r.crc32)\n"
                        text += "MD5:     \(r.md5)\n"
                        text += "SHA-1:   \(r.sha1)\n"
                        text += "SHA-256: \(r.sha256)\n\n"
                    }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(text.trimmingCharacters(in: .whitespacesAndNewlines), forType: .string)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
    }

    private func hashRow(title: String, value: String) -> some View {
        HStack {
            Text(title).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).frame(width: 58, alignment: .leading)
            Text(value).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            Spacer()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(value, forType: .string)
                copiedAlgorithm = title
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    if copiedAlgorithm == title { copiedAlgorithm = nil }
                }
            } label: {
                Image(systemName: copiedAlgorithm == title ? "checkmark" : "doc.on.doc")
                    .font(.caption)
                    .foregroundStyle(copiedAlgorithm == title ? Color.green : Color.secondary)
            }
            .buttonStyle(.plain)
            .help("Copy \(title)")
        }
    }

    private var verificationStatusView: some View {
        let clean = verifyInput.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var match: (algo: String, file: String)? = nil
        for r in results {
            if r.crc32.lowercased() == clean { match = ("CRC32", r.name); break }
            if r.md5.lowercased() == clean { match = ("MD5", r.name); break }
            if r.sha1.lowercased() == clean { match = ("SHA-1", r.name); break }
            if r.sha256.lowercased() == clean { match = ("SHA-256", r.name); break }
        }
        return HStack(spacing: 6) {
            if let m = match {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text("Verified! Matches \(m.algo) of “\(m.file)”").font(.caption).foregroundStyle(.green)
            } else {
                Image(systemName: "xmark.circle.fill").foregroundStyle(.orange)
                Text("No match found for this hash").font(.caption).foregroundStyle(.orange)
            }
        }
    }
}

// MARK: - Software update

struct UpdateSheet: View {
    @ObservedObject private var updater = Updater.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            switch updater.state {
            case .idle, .checking:
                HStack(spacing: 10) { ProgressView().controlSize(.small); Text("Checking for updates…") }
                buttons { Button("Cancel") { updater.dismiss() }.keyboardShortcut(.cancelAction) }
            case .upToDate:
                Text("ArchiveX is up to date").font(.title3.weight(.semibold))
                Text("You have the latest version (\(updater.currentVersion)).").foregroundStyle(.secondary)
                buttons { Button("OK") { updater.dismiss() }.keyboardShortcut(.defaultAction) }
            case .available(let offer):
                Text("ArchiveX \(offer.version) is available").font(.title3.weight(.semibold))
                Text("You have \(updater.currentVersion). Download size: \(ByteCountFormatter.string(fromByteCount: offer.size, countStyle: .file)).")
                    .foregroundStyle(.secondary)
                ScrollView {
                    Text(Self.notes(offer.notes)).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
                .frame(height: 170).padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
                buttons {
                    Button("Release Page") { NSWorkspace.shared.open(offer.pageURL) }
                    Spacer()
                    Button("Skip This Version") { updater.skip(offer) }
                    Button("Later") { updater.dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Install Update") { updater.install(offer) }.keyboardShortcut(.defaultAction)
                }
            case .working(let text, let fraction):
                Text("Updating ArchiveX").font(.title3.weight(.semibold))
                if let fraction { ProgressView(value: fraction) } else { ProgressView().progressViewStyle(.linear) }
                Text(text).foregroundStyle(.secondary).font(.callout)
            case .failed(let message):
                Label("Couldn’t update", systemImage: "exclamationmark.triangle").font(.title3.weight(.semibold))
                Text(message).fixedSize(horizontal: false, vertical: true)
                buttons { Button("OK") { updater.dismiss() }.keyboardShortcut(.defaultAction) }
            case .revealed(_, let why):
                Text("The new version is ready").font(.title3.weight(.semibold))
                Text("\(why) Quit ArchiveX and drag the new app over the old one (for example into Applications).")
                    .fixedSize(horizontal: false, vertical: true)
                buttons { Button("OK") { updater.dismiss() }.keyboardShortcut(.defaultAction) }
            }
        }
        .padding(20).frame(width: 460)
    }

    private func buttons<C: View>(@ViewBuilder _ content: () -> C) -> some View { HStack { content() }.padding(.top, 4) }

    private static func notes(_ markdown: String) -> AttributedString {
        let text = markdown.isEmpty ? "No release notes." : markdown
        return (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(text)
    }
}
