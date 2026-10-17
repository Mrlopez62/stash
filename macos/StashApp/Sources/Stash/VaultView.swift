import SwiftUI

struct VaultView: View {
    @EnvironmentObject var model: AppModel
    @ViewState private var editor: EditorTarget?

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(
                get: { model.selection },
                set: { name in Task { await model.select(name) } })
            ) {
                ForEach(model.filtered) { item in
                    ItemRow(item: item).tag(item.id)
                }
            }
            .searchable(text: $model.search, placement: .sidebar, prompt: "Search")
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .overlay {
                if model.items.isEmpty {
                    EmptyVault { editor = .new($0) }
                }
            }
        } detail: {
            if let detail = model.detail {
                ItemDetailView(detail: detail, onEdit: { editor = .edit(detail) })
                    .id(detail.name)
            } else {
                Text(model.items.isEmpty ? "" : "Select an item")
                    .foregroundStyle(Color.redacted)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.vaultInk)
            }
        }
        .toolbar {
            ToolbarItem {
                Menu {
                    ForEach(ItemKind.allCases) { kind in
                        Button { editor = .new(kind) } label: { Label(kind.title, systemImage: kind.symbol) }
                    }
                } label: {
                    Label("New Item", systemImage: "plus")
                }
            }
            ToolbarItem {
                Button { Task { await model.lock() } } label: { Label("Lock", systemImage: "lock") }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
        .sheet(item: $editor) { target in
            ItemEditorView(target: target)
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                Toast(text: toast)
                    .padding(.bottom, 20)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.toast)
    }
}

struct ItemRow: View {
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 10) {
            ItemIcon(kind: item.kind, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)
                Text(item.username ?? item.folder ?? item.kind.title)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if item.hasOtp {
                Image(systemName: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help("Has 2FA")
            }
        }
        .padding(.vertical, 3)
    }
}

struct ItemIcon: View {
    let kind: ItemKind
    var size: CGFloat = 32

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
            .fill(Color.enclave)
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
                    .strokeBorder(Color.border))
            .overlay(
                Image(systemName: kind.symbol)
                    .font(.system(size: size * 0.45, weight: .semibold))
                    .foregroundStyle(kind == .secret ? Color.keyholeAmber : Color.plaintext))
            .frame(width: size, height: size)
    }
}

struct EmptyVault: View {
    let create: (ItemKind) -> Void

    var body: some View {
        VStack(spacing: 14) {
            StashMark(size: 48)
            Text("Your vault is empty")
                .font(.headline)
            Text("Add an API token, a login, or a note.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                ForEach(ItemKind.allCases) { kind in
                    Button(kind.title) { create(kind) }
                }
            }
        }
        .padding()
    }
}

struct Toast: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "checkmark.circle.fill")
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(Color.success)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(Color.enclave, in: Capsule())
            .overlay(Capsule().strokeBorder(Color.border))
            .shadow(radius: 8, y: 4)
    }
}
