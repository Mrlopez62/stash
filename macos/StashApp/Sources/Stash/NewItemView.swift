import SwiftUI

extension ItemKind {
    /// One line for the "New Item" picker: what this kind is for.
    var blurb: String {
        switch self {
        case .login: "A website or app account: username, password, and 2FA codes"
        case .secret: "An API key, token, or other single value for your code"
        case .note: "Private text, like recovery codes or a Wi-Fi password"
        case .card: "A credit or debit card, checked for typos as you type"
        case .bank: "Routing and account numbers, or an IBAN and SWIFT code"
        case .ssh: "Generate or import a key for SSH logins and git signing"
        }
    }
}

/// "New Item": first pick what to save, then fill in that kind's form, in
/// the same sheet. `suggested` is preselected (the category you're viewing).
struct NewItemFlow: View {
    let suggested: ItemKind
    @ViewState private var picked: ItemKind?

    var body: some View {
        if let picked {
            ItemEditorView(target: .new(picked), onBack: { self.picked = nil })
        } else {
            NewItemChooser(suggested: suggested) { picked = $0 }
        }
    }
}

struct NewItemChooser: View {
    @Environment(\.dismiss) private var dismiss
    let suggested: ItemKind
    let choose: (ItemKind) -> Void

    @ViewState private var selection: ItemKind?
    @FocusState private var focused: Bool

    private let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
    private var current: ItemKind { selection ?? suggested }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("New Item")
                    .font(.plex(17, weight: .semibold))
                    .foregroundStyle(Color.ink)
                Text("What do you want to save?")
                    .font(.plex(13))
                    .foregroundStyle(Color.inkSecondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 24)
            .padding(.top, 22)
            .padding(.bottom, 16)

            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(ItemKind.allCases) { kind in
                    KindTile(kind: kind, selected: kind == current) {
                        choose(kind)
                    }
                    .onHover { if $0 { selection = kind } }
                }
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 20)
            .focusable()
            .focusEffectDisabled()
            .focused($focused)
            .onKeyPress(.leftArrow) { move(-1) }
            .onKeyPress(.rightArrow) { move(1) }
            .onKeyPress(.upArrow) { move(-2) }
            .onKeyPress(.downArrow) { move(2) }

            Rectangle().fill(Color.line).frame(height: 1)
            HStack(spacing: 10) {
                Text("Use the arrow keys and Return, or click one")
                    .font(.plex(12))
                    .foregroundStyle(Color.inkTertiary)
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button("Continue") { choose(current) }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 14)
            .background(Color.surface)
        }
        .frame(width: 540)
        .background(Color.canvas)
        .onAppear { focused = true }
    }

    private func move(_ step: Int) -> KeyPress.Result {
        let all = ItemKind.allCases
        guard let i = all.firstIndex(of: current) else { return .ignored }
        let next = i + step
        if all.indices.contains(next) { selection = all[next] }
        return .handled
    }
}

private struct KindTile: View {
    let kind: ItemKind
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                ItemIcon(kind: kind, size: 34)
                VStack(alignment: .leading, spacing: 3) {
                    Text(kind.title)
                        .font(.plex(14, weight: .semibold))
                        .foregroundStyle(Color.ink)
                    Text(kind.blurb)
                        .font(.plex(12))
                        .foregroundStyle(Color.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
            }
            .padding(14)
            .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
            .background(
                selected ? Color.amberTint : Color.surface,
                in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(selected ? Color.keyholeAmber.opacity(0.7) : Color.line,
                                  lineWidth: selected ? 1.5 : 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("New \(kind.title): \(kind.blurb)")
    }
}
