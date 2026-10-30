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
                commentTab.tabItem { Text("Comment") }
            }
            .padding(.horizontal, 12)
            .frame(height: 350)
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
            if !draft.updatingExisting {
                Picker("Split volumes", selection: $draft.splitPreset) {
                    ForEach(SplitPreset.allCases) { Text($0.rawValue).tag($0) }
                }
                if draft.splitPreset == .custom {
                    HStack {
                        TextField("Volume size", value: $draft.customSplitMB, format: .number)
                            .frame(width: 80)
                        Text("MB").foregroundStyle(.secondary)
                    }
                }
                if draft.splitPreset != .none {
                    Text("Splits output into .001, .002, … volume parts.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
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

    private var commentTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Archive Comment (ZIP)")
                .font(.headline)
            Text("Optional comment embedded in the ZIP central directory header.")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $draft.comment)
                .font(.system(.body, design: .monospaced))
                .padding(4)
                .background(Color(NSColor.textBackgroundColor))
                .cornerRadius(6)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color(NSColor.separatorColor), lineWidth: 1))
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
    @State private var notesHeight: CGFloat = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            switch updater.state {
            case .idle, .checking:
                header("Checking for updates…", "Asking GitHub for the latest release.", spinner: true)
                footer { Spacer(); Button("Cancel") { updater.dismiss() }.keyboardShortcut(.cancelAction) }
            case .upToDate:
                header("ArchiveX is up to date", "You have the latest version, \(updater.currentVersion).", badge: "checkmark.circle.fill", tint: .green)
                footer { Spacer(); Button("OK") { updater.dismiss() }.keyboardShortcut(.defaultAction) }
            case .available(let offer):
                header("A new version of ArchiveX is available",
                       "ArchiveX \(offer.version) is ready to install. You have \(updater.currentVersion) · \(ByteCountFormatter.string(fromByteCount: offer.size, countStyle: .file)) download.")
                Divider()
                changelog(offer)
                Divider()
                footer {
                    Button("Release Page") { NSWorkspace.shared.open(offer.pageURL) }.buttonStyle(.link)
                    Spacer()
                    Button("Skip This Version") { updater.skip(offer) }
                    Button("Later") { updater.dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Install & Restart") { updater.install(offer) }.keyboardShortcut(.defaultAction)
                }
            case .working(let text, let fraction):
                header("Updating ArchiveX", text)
                VStack(alignment: .leading, spacing: 8) {
                    if let fraction {
                        ProgressView(value: fraction)
                        Text("\(Int(fraction * 100))%").font(.caption).foregroundStyle(.secondary).monospacedDigit()
                    } else {
                        ProgressView().progressViewStyle(.linear)
                    }
                    Text("ArchiveX restarts by itself when this is done. Your open archive is not changed.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 24).padding(.bottom, 24)
            case .failed(let message):
                header("The update didn’t finish", message, badge: "exclamationmark.triangle.fill", tint: .orange)
                footer { Spacer(); Button("OK") { updater.dismiss() }.keyboardShortcut(.defaultAction) }
            case .revealed:
                header("The new version is ready", "ArchiveX can’t replace itself where it is installed, so the new version is shown in Finder. Quit ArchiveX and drag the new app over the old one (for example into Applications).",
                       badge: "folder.fill", tint: .blue)
                footer { Spacer(); Button("OK") { updater.dismiss() }.keyboardShortcut(.defaultAction) }
            }
        }
        .frame(width: 500)
    }

    // MARK: pieces

    private func header(_ title: String, _ subtitle: String?, badge: String? = nil, tint: Color = .accentColor, spinner: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable().frame(width: 60, height: 60)
                .overlay(alignment: .bottomTrailing) {
                    if let badge {
                        Image(systemName: badge).font(.system(size: 22)).foregroundStyle(tint)
                            .background(Circle().fill(Color(nsColor: .windowBackgroundColor)).padding(2))
                            .offset(x: 6, y: 6)
                    }
                }
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(title).font(.title3.weight(.semibold))
                    if spinner { ProgressView().controlSize(.small) }
                }
                if let subtitle {
                    Text(subtitle).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(24)
    }

    private func footer<C: View>(@ViewBuilder _ content: () -> C) -> some View {
        HStack(spacing: 10) { content() }.padding(.horizontal, 24).padding(.vertical, 16)
    }

    private func changelog(_ offer: UpdateOffer) -> some View {
        let lines = ReleaseNotes.parse(offer.notes)
        return VStack(alignment: .leading, spacing: 8) {
            Text("What’s new in \(offer.version)").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    if lines.isEmpty {
                        Text("Bug fixes and improvements.").foregroundStyle(.secondary)
                    }
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, line in row(line) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(GeometryReader { Color.clear.preference(key: NotesHeightKey.self, value: $0.size.height) })
            }
            .frame(height: min(max(notesHeight, 40), 230))
            .onPreferenceChange(NotesHeightKey.self) { notesHeight = $0 }
        }
        .padding(.horizontal, 24).padding(.vertical, 16)
    }

    @ViewBuilder private func row(_ line: ReleaseNotes.Line) -> some View {
        switch line {
        case .heading(let t):
            Text(Self.inline(t)).font(.callout.weight(.semibold)).padding(.top, 6)
        case .bullet(let t):
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("•").foregroundStyle(.secondary)
                Text(Self.inline(t)).fixedSize(horizontal: false, vertical: true)
            }
            .font(.callout)
        case .text(let t):
            Text(Self.inline(t)).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private static func inline(_ s: String) -> AttributedString {
        (try? AttributedString(markdown: s, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(s)
    }
}

private struct NotesHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}
