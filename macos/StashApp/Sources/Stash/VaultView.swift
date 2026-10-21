import SwiftUI

/// Widths the main window is built from.
enum VaultLayout {
    static let sidebar: CGFloat = 232
    static let itemsMin: CGFloat = 500
    static let inspector: CGFloat = 340
    static let minWindowWidth = sidebar + 1 + itemsMin
    /// Below this the inspector floats over the table instead of sitting beside it.
    static let dockedInspectorWidth = minWindowWidth + 1 + inspector
}

/// The main window: sidebar, item table, and an inspector for the selection.
struct VaultView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        GeometryReader { geo in
            let width = geo.size.width
            let open = model.detail != nil
            // Room for everything: sidebar, table, inspector side by side.
            // Less room: tuck the sidebar away while an item is open (it
            // comes back when you close it). Least room: float the inspector.
            let showSidebar = !open || width >= VaultLayout.dockedInspectorWidth
            let docked = width >= (showSidebar ? VaultLayout.dockedInspectorWidth
                                                : VaultLayout.itemsMin + 1 + VaultLayout.inspector)
            ZStack(alignment: .trailing) {
                HStack(spacing: 0) {
                    if showSidebar {
                        Sidebar()
                            .frame(width: VaultLayout.sidebar)
                            .transition(.move(edge: .leading))
                        Rectangle().fill(Color.line).frame(width: 1)
                    }
                    ItemsPane()
                        .frame(minWidth: VaultLayout.itemsMin, maxWidth: .infinity)
                    if docked, let detail = model.detail {
                        Rectangle().fill(Color.line).frame(width: 1)
                        inspector(detail)
                    }
                }
                // The narrowest windows: float the inspector over the table.
                if !docked, let detail = model.detail {
                    inspector(detail)
                        .overlay(alignment: .leading) { Rectangle().fill(Color.line).frame(width: 1) }
                        .shadow(color: .black.opacity(0.35), radius: 28, x: -8)
                }
            }
            .animation(.easeOut(duration: 0.18), value: showSidebar)
        }
        .background(Color.canvas)
        .animation(.easeOut(duration: 0.18), value: model.detail?.name)
        .sheet(item: $model.importFile) { ImportView(file: $0) }
        .sheet(item: $model.editor) { target in
            if case .choose(let suggested) = target {
                NewItemFlow(suggested: suggested)
            } else {
                ItemEditorView(target: target)
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                Toast(text: toast)
                    .padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.toast)
    }
}

// MARK: - Sidebar

extension VaultView {
    fileprivate func inspector(_ detail: ItemDetail) -> some View {
        InspectorView(detail: detail, onEdit: { model.editor = .edit(detail) })
            .frame(width: VaultLayout.inspector)
            .id(detail.name)
            .transition(.move(edge: .trailing).combined(with: .opacity))
    }
}

struct Sidebar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 9) {
                StashMark(size: 26)
                Wordmark(size: 19)
            }
            .padding(.horizontal, 18)
            .padding(.top, 44) // clear of the window controls
            .padding(.bottom, 22)

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    SidebarSection(title: "Vault") {
                        row(.all, "tray.full")
                        row(.kind(.login), ItemKind.login.symbol)
                        row(.kind(.secret), ItemKind.secret.symbol)
                        row(.kind(.note), ItemKind.note.symbol)
                        row(.kind(.card), ItemKind.card.symbol)
                        row(.kind(.bank), ItemKind.bank.symbol)
                        row(.kind(.ssh), ItemKind.ssh.symbol)
                    }
                    if !model.folders.isEmpty {
                        SidebarSection(title: "Folders") {
                            ForEach(model.folders, id: \.self) { row(.folder($0), "folder") }
                        }
                    }
                }
                .padding(.horizontal, 10)
            }

            Spacer(minLength: 0)
            VStack(alignment: .leading, spacing: 8) {
                Rectangle().fill(Color.line).frame(height: 1)
                Button { Task { await model.lock() } } label: {
                    HStack(spacing: 9) {
                        Image(systemName: "lock").frame(width: 18)
                        Text("Lock stash")
                        Spacer()
                        Keycap(keys: "⇧⌘L")
                    }
                    .font(.plex(13, weight: .medium))
                    .foregroundStyle(Color.inkSecondary)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 6)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
            .padding(.bottom, 12)
        }
        .background(Color.sidebar)
    }

    private func row(_ filter: AppModel.Filter, _ symbol: String) -> some View {
        SidebarRow(
            symbol: symbol,
            title: filter.title,
            count: model.count(filter),
            selected: model.filter == filter
        ) {
            model.filter = filter
        }
    }
}

struct SidebarSection<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    @ViewState private var expanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Button { withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() } } label: {
                // Chevron in the icon column, so the title lines up with row titles.
                HStack(spacing: 9) {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .rotationEffect(.degrees(expanded ? 0 : -90))
                        .foregroundStyle(Color.inkTertiary)
                        .frame(width: 18)
                    Eyebrow(text: title)
                }
                .padding(.horizontal, 8)
                .padding(.bottom, 4)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded { content }
        }
    }
}

struct SidebarRow: View {
    let symbol: String
    let title: String
    let count: Int
    let selected: Bool
    let action: () -> Void
    @ViewState private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: symbol)
                    .font(.system(size: 12.5, weight: .medium))
                    .frame(width: 18)
                    .foregroundStyle(selected ? Color.amberText : Color.inkSecondary)
                Text(title)
                    .font(.plex(13, weight: selected ? .semibold : .regular))
                    .foregroundStyle(Color.ink)
                    .lineLimit(1)
                Spacer()
                Text("\(count)")
                    .font(.mono(11.5))
                    .foregroundStyle(Color.inkTertiary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(
                selected ? Color.amberTint : (hovering ? Color.hover : .clear),
                in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

// MARK: - Items

struct ItemsPane: View {
    @EnvironmentObject var model: AppModel
    /// Measured on the pane itself (sized by the window), not the table,
    /// whose content would otherwise feed back into its own width.
    @ViewState private var width: CGFloat = 1000

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .center) {
                Text(model.filter.title)
                    .font(.plex(24, weight: .semibold))
                    .foregroundStyle(Color.ink)
                Spacer()
                // First pick the kind (the category you're viewing is
                // preselected), then fill in that kind's form.
                Button {
                    model.editor = .choose(model.suggestedKind)
                } label: {
                    Label("New Item", systemImage: "plus")
                }
                .buttonStyle(PrimaryButtonStyle())
                .fixedSize()
                .keyboardShortcut("n", modifiers: .command)
            }
            .padding(.horizontal, 28)
            .padding(.top, 36)
            .padding(.bottom, 18)

            Rectangle().fill(Color.line).frame(height: 1).padding(.horizontal, 28)

            Card {
                VStack(spacing: 0) {
                    HStack(spacing: 14) {
                        (Text("\(model.filtered.count)").font(.plex(13, weight: .semibold))
                            + Text(" of ").font(.plex(13))
                            + Text("\(model.scopeCount)").font(.plex(13, weight: .semibold))
                            + Text(model.scopeCount == 1 ? " item" : " items").font(.plex(13)))
                            .foregroundStyle(Color.inkSecondary)
                            .fixedSize()
                        SearchField(prompt: "Search \(model.filter.title.lowercased())", text: $model.search)
                            .frame(maxWidth: 300)
                        Spacer()
                        Menu {
                            Picker("Sort", selection: $model.sort) {
                                Text("Name").tag(AppModel.Sort.name)
                                Text("Recently updated").tag(AppModel.Sort.updated)
                            }
                            .pickerStyle(.inline)
                        } label: {
                            Label(model.sort == .name ? "Name" : "Recent", systemImage: "arrow.up.arrow.down")
                                .font(.plex(12.5, weight: .medium))
                        }
                        .menuStyle(.borderlessButton)
                        .fixedSize()
                        .tint(Color.inkSecondary)
                        .foregroundStyle(Color.inkSecondary)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)

                    // 28pt page padding on each side, plus the card's border.
                    ItemTable(columns: Columns(width: width - 58))
                }
            }
            .padding(.horizontal, 28)
            .padding(.top, 22)
            .padding(.bottom, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(GeometryReader { geo in
            Color.clear
                .onAppear { width = geo.size.width }
                .onChange(of: geo.size.width) { width = $1 }
        })
    }
}

/// Column widths, shared by the header and the rows.
private enum Col {
    static let kind: CGFloat = 78
    static let user: CGFloat = 180
    static let site: CGFloat = 170
    static let otp: CGFloat = 36
    static let updated: CGFloat = 76
}

/// Which optional columns fit, keeping at least 260pt for the name. As the
/// table narrows (e.g. with the inspector open) it drops website first, then
/// kind (the icon already shows it), then username, then updated.
struct Columns: Equatable {
    var kind = true
    var user = true
    var site = true
    var updated = true

    init(width: CGFloat) {
        site = width >= 890
        user = width >= 620
        kind = width >= 710 || width < 620
        updated = width >= 520
    }
}

struct ItemTable: View {
    @EnvironmentObject var model: AppModel
    let columns: Columns

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Eyebrow(text: "Name").frame(maxWidth: .infinity, alignment: .leading)
                if columns.kind { Eyebrow(text: "Kind").frame(width: Col.kind, alignment: .leading) }
                if columns.user { Eyebrow(text: "Username").frame(width: Col.user, alignment: .leading) }
                if columns.site { Eyebrow(text: "Website").frame(width: Col.site, alignment: .leading) }
                Eyebrow(text: "2FA").frame(width: Col.otp, alignment: .center)
                if columns.updated { Eyebrow(text: "Updated").frame(width: Col.updated, alignment: .trailing) }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 9)
            .background(Color.surfaceRaised)
            .overlay(alignment: .top) { Rectangle().fill(Color.line).frame(height: 1) }
            .overlay(alignment: .bottom) { Rectangle().fill(Color.line).frame(height: 1) }

            if model.items.isEmpty {
                EmptyVault(create: { model.editor = .choose(model.suggestedKind) },
                           importFile: { model.chooseImportFile() })
                    .frame(maxWidth: .infinity, minHeight: 280)
            } else if model.filtered.isEmpty {
                Text("No items match “\(model.search)”")
                    .font(.plex(13))
                    .foregroundStyle(Color.inkTertiary)
                    .frame(maxWidth: .infinity, minHeight: 160)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.filtered) { item in
                            ItemTableRow(item: item, selected: model.selection == item.id, columns: columns)
                                .onTapGesture { Task { await model.select(model.selection == item.id ? nil : item.id) } }
                            Rectangle().fill(Color.line.opacity(0.6)).frame(height: 1).padding(.leading, 53)
                        }
                    }
                }
            }
        }
    }
}

struct ItemTableRow: View {
    @EnvironmentObject var model: AppModel
    let item: ItemSummary
    let selected: Bool
    let columns: Columns
    @ViewState private var hovering = false

    var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 11) {
                ItemIcon(kind: item.kind, size: 26)
                (Text(item.folder.map { "\($0)/" } ?? "").foregroundStyle(Color.inkTertiary)
                    + Text(item.title).foregroundStyle(Color.ink))
                    .font(.mono(13, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 4)
            }
            .frame(minWidth: 200, maxWidth: .infinity, alignment: .leading)
            .overlay(alignment: .trailing) {
                // Notes have nothing to copy from the table.
                if hovering && item.kind != .note { RowActions(item: item) }
            }

            if columns.kind { KindBadge(kind: item.kind).frame(width: Col.kind, alignment: .leading) }
            if columns.user {
                // Cards and bank accounts show "Visa •••• 4242" here.
                Text(item.username ?? item.subtitle ?? "—")
                    .font(.plex(13))
                    .foregroundStyle(item.username == nil && item.subtitle == nil ? Color.inkTertiary : Color.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: Col.user, alignment: .leading)
            }
            if columns.site {
                Text(item.url.flatMap { URL(string: $0)?.host() } ?? "—")
                    .font(.plex(13))
                    .foregroundStyle(item.url == nil ? Color.inkTertiary : Color.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: Col.site, alignment: .leading)
            }
            Group {
                if item.hasOtp {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(Color.success, Color.successTint)
                        .symbolRenderingMode(.palette)
                        .help("Has 2FA")
                } else {
                    Text("")
                }
            }
            .frame(width: Col.otp, alignment: .center)
            if columns.updated {
                Text(relative(item.updated))
                    .font(.mono(11.5))
                    .foregroundStyle(Color.inkTertiary)
                    .lineLimit(1)
                    .frame(width: Col.updated, alignment: .trailing)
            }
        }
        .padding(.horizontal, 16)
        .frame(height: 44)
        .background(selected ? Color.amberTint : (hovering ? Color.hover : Color.surface))
        .overlay(alignment: .leading) {
            if selected { Rectangle().fill(Color.keyholeAmber).frame(width: 3) }
        }
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }
}

/// Copy buttons that appear on hover, so the common case needs no clicks
/// into the item.
struct RowActions: View {
    @EnvironmentObject var model: AppModel
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 0) {
            if let username = item.username {
                IconButton("person.crop.circle", help: "Copy username") { model.copyPlain(username, label: "username") }
            }
            if item.kind != .note {
                IconButton("doc.on.doc", help: {
                    switch item.kind {
                    case .login: "Copy password"
                    case .card: "Copy card number"
                    case .bank: "Copy account number"
                    case .ssh: "Copy public key"
                    default: "Copy value"
                    }
                }()) {
                    Task {
                        if await model.copyPrimary(item) {
                            model.flash(item.kind == .ssh
                                ? "Copied \(item.title)'s public key"
                                : "Copied \(item.title) · clears in \(Int(Clipboard.clearAfter))s")
                        }
                    }
                }
            }
            if item.hasOtp {
                IconButton("clock", help: "Copy 2FA code") {
                    Task { if await model.copyOTP(for: item) { model.flash("Copied 2FA code") } }
                }
            }
        }
        .padding(2)
        .background(Color.surface, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Color.line))
    }
}

struct KindBadge: View {
    let kind: ItemKind

    var body: some View {
        switch kind {
        case .login: Badge(text: "Login")
        // Neutral: the amber tile already marks a secret.
        case .secret: Badge(text: "Secret")
        case .note: Badge(text: "Note")
        case .card: Badge(text: "Card")
        case .bank: Badge(text: "Bank")
        case .ssh: Badge(text: "SSH")
        }
    }
}

struct ItemIcon: View {
    let kind: ItemKind
    var size: CGFloat = 32

    var body: some View {
        // The kind shows in the glyph, not in a heavy tile.
        RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
            .fill(kind == .secret ? Color.amberTint : Color.surfaceRaised)
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                    .strokeBorder(kind == .secret ? Color.keyholeAmber.opacity(0.35) : Color.line))
            .overlay(
                Image(systemName: kind.symbol)
                    .font(.system(size: size * 0.44, weight: .semibold))
                    .foregroundStyle(kind == .secret ? Color.amberText : Color.inkSecondary))
            .frame(width: size, height: size)
    }
}

struct EmptyVault: View {
    let create: () -> Void
    let importFile: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            StashMark(size: 44)
            Text("Your vault is empty")
                .font(.plex(16, weight: .semibold))
                .foregroundStyle(Color.ink)
            Text("Add a login, an API token, a card, a bank account, an SSH key, or a note.")
                .font(.plex(13))
                .foregroundStyle(Color.inkSecondary)
                .multilineTextAlignment(.center)
            HStack(spacing: 8) {
                Button {
                    create()
                } label: {
                    Label("New Item", systemImage: "plus")
                }
                .buttonStyle(PrimaryButtonStyle())
                Button {
                    importFile()
                } label: {
                    Label("Import…", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(SecondaryButtonStyle())
            }
            Text("Moving from Chrome, Safari, 1Password, or Bitwarden? Export your passwords there, then import the file.")
                .font(.plex(12))
                .foregroundStyle(Color.inkTertiary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
        }
        .padding(32)
    }
}

struct Toast: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "checkmark.circle.fill")
            .font(.plex(13, weight: .medium))
            .foregroundStyle(Color.plaintext)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(Color.vaultInk, in: Capsule())
            .overlay(Capsule().strokeBorder(Color.white.opacity(0.08)))
            .shadow(color: .black.opacity(0.18), radius: 14, y: 6)
    }
}
