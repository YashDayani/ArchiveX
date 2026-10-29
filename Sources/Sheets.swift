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
