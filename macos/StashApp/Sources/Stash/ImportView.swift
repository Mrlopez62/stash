import AppKit
import SwiftUI

/// What an export file holds, as `import_preview` describes it: never
/// passwords, only names, kinds, usernames, and websites.
struct ImportPreview: Decodable {
    struct Entry: Decodable, Identifiable {
        let index: Int
        let title: String
        let name: String
        let kind: ItemKind
        let username: String?
        let website: String?
        let subtitle: String?
        let warnings: [String]
        var id: Int { index }
    }
    struct Skipped: Decodable, Hashable {
        let title: String
        let why: String
    }
    let format: String
    let entries: [Entry]
    let skipped: [Skipped]
}

struct ImportResult: Decodable {
    struct Renamed: Decodable, Hashable { let from: String; let to: String }
    struct Failed: Decodable, Hashable { let title: String; let why: String }
    let added: [ItemKind]
    let same: Int
    let renamed: [Renamed]
    let failed: [Failed]
}

/// The export file being imported (a sheet is open while it's set).
struct ImportFile: Identifiable {
    let url: URL
    var id: String { url.path }
}

extension [ItemKind] {
    /// "12 logins, 2 cards".
    var summary: String {
        let counts = Dictionary(grouping: self, by: { $0 }).mapValues(\.count)
        return ItemKind.allCases.compactMap { kind in
            guard let n = counts[kind] else { return nil }
            let noun = kind == .note ? "note" : kind.title.lowercased()
            return "\(n) \(noun)\(n == 1 ? "" : "s")"
        }.joined(separator: ", ")
    }
}

extension AppModel {
    /// File → Import: choose an export file, then review it in a sheet.
    func chooseImportFile() {
        guard case .unlocked = screen else { return }
        let panel = NSOpenPanel()
        panel.title = "Import passwords"
        panel.message = "Choose an export from Chrome, Safari, Firefox, 1Password, Bitwarden, or another password manager."
        panel.prompt = "Review"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            importFile = ImportFile(url: url)
        }
    }
}

struct ImportView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let file: ImportFile

    private enum Stage {
        case loading
        case failed(String)
        case review(ImportPreview)
        case importing(ImportPreview)
        case done(ImportResult)
    }

    @ViewState private var stage: Stage = .loading
    @ViewState private var selected: Set<Int> = []
    @ViewState private var showSkipped = false
    @ViewState private var deleted = false
    @ViewState private var deleteError: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color.surfaceRaised)
                    .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Color.line))
                    .overlay(Image(systemName: "square.and.arrow.down")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Color.inkSecondary))
                    .frame(width: 34, height: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Import")
                        .font(.plex(17, weight: .semibold))
                        .foregroundStyle(Color.ink)
                    Text(file.url.lastPathComponent)
                        .font(.mono(11.5))
                        .foregroundStyle(Color.inkTertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.top, 22)
            .padding(.bottom, 16)

            content
        }
        .frame(width: 600)
        .frame(minHeight: 300, idealHeight: 600, maxHeight: 760)
        .background(Color.canvas)
        .task { await load() }
    }

    @ViewBuilder private var content: some View {
        switch stage {
        case .loading:
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            footer { Button("Cancel") { dismiss() }.buttonStyle(SecondaryButtonStyle()) }
        case .failed(let why):
            Label(why, systemImage: "exclamationmark.circle")
                .font(.plex(13))
                .foregroundStyle(Color.danger)
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            footer { Button("Close") { dismiss() }.buttonStyle(SecondaryButtonStyle()) }
        case .review(let preview), .importing(let preview):
            review(preview)
        case .done(let result):
            done(result)
        }
    }

    // MARK: Review

    private func review(_ preview: ImportPreview) -> some View {
        let busy = if case .importing = stage { true } else { false }
        let chosen = preview.entries.filter { selected.contains($0.index) }
        return VStack(spacing: 0) {
            HStack {
                Text("Found \(preview.entries.count) item\(preview.entries.count == 1 ? "" : "s") in this \(preview.format) export: \(preview.entries.map(\.kind).summary)")
                    .font(.plex(13))
                    .foregroundStyle(Color.inkSecondary)
                Spacer()
                Button(selected.count == preview.entries.count ? "Select None" : "Select All") {
                    selected = selected.count == preview.entries.count ? [] : Set(preview.entries.map(\.index))
                }
                .buttonStyle(.link)
                .font(.plex(12.5))
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 10)

            ScrollView {
                VStack(spacing: 0) {
                    ForEach(preview.entries) { entry in
                        row(entry)
                        Rectangle().fill(Color.line).frame(height: 1)
                    }
                    if !preview.skipped.isEmpty {
                        DisclosureGroup(isExpanded: $showSkipped) {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(preview.skipped, id: \.self) { s in
                                    (Text(s.title).font(.plex(12.5, weight: .medium)).foregroundStyle(Color.ink)
                                        + Text("  \(s.why)").font(.plex(12)).foregroundStyle(Color.inkSecondary))
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.top, 6)
                        } label: {
                            Text("\(preview.skipped.count) won't be imported")
                                .font(.plex(12.5, weight: .medium))
                                .foregroundStyle(Color.inkSecondary)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                    }
                }
                .background(Color.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.line))
                .padding(.horizontal, 24)
                .padding(.bottom, 16)
            }
            .disabled(busy)

            footer {
                Text("Nothing in your vault is replaced.")
                    .font(.plex(12))
                    .foregroundStyle(Color.inkTertiary)
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button(busy ? "Importing…" : "Import \(chosen.count) Item\(chosen.count == 1 ? "" : "s")") {
                    Task { await runImport(preview) }
                }
                .buttonStyle(PrimaryButtonStyle())
                .keyboardShortcut(.defaultAction)
                .disabled(chosen.isEmpty || busy)
            }
        }
    }

    private func row(_ entry: ImportPreview.Entry) -> some View {
        let on = Binding(
            get: { selected.contains(entry.index) },
            set: { if $0 { selected.insert(entry.index) } else { selected.remove(entry.index) } })
        return HStack(alignment: .top, spacing: 12) {
            Toggle("", isOn: on).toggleStyle(.checkbox).labelsHidden().padding(.top, 8)
            ItemIcon(kind: entry.kind, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title)
                    .font(.plex(13.5, weight: .semibold))
                    .foregroundStyle(Color.ink)
                    .lineLimit(1)
                Text(detail(entry))
                    .font(.plex(12))
                    .foregroundStyle(Color.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                ForEach(entry.warnings, id: \.self) { w in
                    Label(w, systemImage: "exclamationmark.triangle")
                        .font(.plex(11.5))
                        .foregroundStyle(Color.amberText)
                }
            }
            Spacer(minLength: 8)
            Text(entry.name)
                .font(.mono(11.5))
                .foregroundStyle(Color.inkTertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 170, alignment: .trailing)
                .padding(.top, 2)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .onTapGesture { on.wrappedValue.toggle() }
    }

    private func detail(_ e: ImportPreview.Entry) -> String {
        [e.kind.title, e.subtitle ?? e.username, e.website.flatMap { URL(string: $0)?.host ?? $0 }]
            .compactMap { $0 }
            .joined(separator: " · ")
    }

    // MARK: Done

    private func done(_ result: ImportResult) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Label(
                        result.added.isEmpty
                            ? "Nothing new to import"
                            : "Imported \(result.added.count) item\(result.added.count == 1 ? "" : "s"): \(result.added.summary)",
                        systemImage: "checkmark.circle.fill")
                        .font(.plex(15, weight: .semibold))
                        .foregroundStyle(Color.ink)
                        .symbolRenderingMode(.multicolor)
                    if result.same > 0 {
                        Text("\(result.same) already in your vault, left as they are.")
                            .font(.plex(13)).foregroundStyle(Color.inkSecondary)
                    }
                    ForEach(result.renamed, id: \.self) { r in
                        Text("\(r.from) was taken, so it's \(r.to)")
                            .font(.plex(12.5)).foregroundStyle(Color.inkSecondary)
                    }
                    ForEach(result.failed, id: \.self) { f in
                        Label("Couldn't add “\(f.title)”: \(f.why)", systemImage: "exclamationmark.circle")
                            .font(.plex(12.5)).foregroundStyle(Color.danger)
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Label(deleted ? "Deleted \(file.url.lastPathComponent)." : "\(file.url.lastPathComponent) still holds those passwords in plain text.",
                              systemImage: deleted ? "trash" : "exclamationmark.shield")
                            .font(.plex(13, weight: .medium))
                            .foregroundStyle(deleted ? Color.inkSecondary : Color.amberText)
                        if !deleted {
                            Text("Anyone, or any app, that can read your files can read it. Delete it now that your passwords are in stash.")
                                .font(.plex(12.5))
                                .foregroundStyle(Color.inkSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        if let deleteError {
                            Text(deleteError).font(.plex(12)).foregroundStyle(Color.danger)
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(deleted ? Color.surface : Color.amberTint, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.line))
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 16)
            }
            footer {
                Spacer()
                if deleted {
                    Button("Done") { dismiss() }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("Keep File") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle())
                        .keyboardShortcut(.cancelAction)
                    Button("Delete File") { deleteFile() }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
    }

    // MARK: -

    private func footer(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(spacing: 0) {
            Rectangle().fill(Color.line).frame(height: 1)
            HStack(spacing: 10) { content() }
                .padding(.horizontal, 24)
                .padding(.vertical, 14)
        }
        .background(Color.surface)
    }

    private func load() async {
        do {
            guard let backend = model.backend else { return }
            let preview = try await backend.importPreview(path: file.url.path)
            selected = Set(preview.entries.map(\.index))
            stage = .review(preview)
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    private func runImport(_ preview: ImportPreview) async {
        stage = .importing(preview)
        guard let result = await model.importItems(path: file.url.path, indices: selected.sorted()) else {
            stage = .review(preview)
            if let error = model.error { deleteError = error }
            return
        }
        stage = .done(result)
    }

    private func deleteFile() {
        do {
            // Removed outright, not moved to the Trash, where it would
            // still be readable.
            try FileManager.default.removeItem(at: file.url)
            deleted = true
            deleteError = nil
        } catch {
            deleteError = "Couldn't delete it: \(error.localizedDescription)"
        }
    }
}
