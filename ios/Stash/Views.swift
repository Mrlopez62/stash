import SwiftUI
import UniformTypeIdentifiers

struct RootView: View {
    @EnvironmentObject var model: PhoneModel
    /// The unlock animation has started to show the vault.
    @State private var revealing = false

    var body: some View {
        Group {
            switch model.screen {
            case .welcome: WelcomeView()
            case .locked: LockView()
            case .unlocked: VaultListView()
            }
        }
        // The vault starts slightly large, and settles as it's revealed.
        .scaleEffect(model.unlocking && !revealing ? 1.04 : 1)
        .overlay {
            if model.unlocking {
                UnlockCurtain(start: model.unlockFromLockMark ? model.lockMarkCenter : nil) {
                    withAnimation(.spring(response: 0.62, dampingFraction: 0.9)) { revealing = true }
                } finished: {
                    model.unlocking = false
                    revealing = false
                }
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                Label(toast, systemImage: "checkmark.circle.fill")
                    .font(.plex(14, weight: .medium))
                    .foregroundStyle(Color.plaintext)
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(Color.vaultInk, in: Capsule())
                    .padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .alert("Replace the vault on this iPhone?", isPresented: Binding(
            get: { model.pendingImport && model.canAskToReplace }, set: { _ in })
        ) {
            Button("Replace", role: .destructive) { model.installStaged() }
            Button("Cancel", role: .cancel) { model.cancelImport() }
        } message: {
            Text(model.madeHere
                 ? "The cards and bank accounts you added on this iPhone are deleted for good and swapped for the ones in the new file. This is the only copy of them."
                 : "The cards and bank accounts here are swapped for the ones in the new file. Face ID is set up again after you unlock it.")
        }
    }
}

// MARK: - Welcome

struct WelcomeView: View {
    @EnvironmentObject var model: PhoneModel
    @State private var choosing = false
    @State private var creating = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 10) {
                    StashMark(size: 64)
                    Wordmark(size: 34)
                    Text("Your logins, cards, and bank accounts, with Face ID.")
                        .font(.plex(17))
                        .foregroundStyle(Color.inkSecondary)
                }
                VStack(alignment: .leading, spacing: 14) {
                    Text("Bring them from your Mac")
                        .font(.plex(15, weight: .semibold))
                        .foregroundStyle(Color.ink)
                    step(1, "On your Mac, run:", code: "stash export --phone ~/Desktop/phone.stashvault")
                    step(2, "AirDrop phone.stashvault to this iPhone and open it in stash. Or, in Finder, drop it on this iPhone under Files → stash.")
                    step(3, "Unlock it with the password you chose. stash then offers Face ID.")
                    step(4, "Delete the file from your Mac's Desktop.")
                }
                .padding(18)
                .background(Color.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.line))

                Button {
                    choosing = true
                } label: {
                    Label("Choose a .stashvault File", systemImage: "folder")
                        .font(.plex(16, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .tint(.keyholeAmber)
                .foregroundStyle(Color.vaultInk)

                VStack(spacing: 6) {
                    Button("Skip") { model.error = nil; creating = true }
                        .font(.plex(16, weight: .semibold))
                        .foregroundStyle(Color.ink)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                    Text("No Mac or file: make a vault here and add everything on this iPhone.")
                        .font(.plex(13))
                        .foregroundStyle(Color.inkSecondary)
                        .multilineTextAlignment(.center)
                }

                if let error = model.error, !creating {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.plex(14)).foregroundStyle(Color.danger)
                }
            }
            .padding(24)
        }
        .background(Color.canvas.ignoresSafeArea())
        .sheet(isPresented: $creating) { CreateVaultView().sheetGuarded() }
        #if DEBUG
        .task {
            // Simulator checks only (never in release builds).
            if SimHooks.shows("create") { creating = true }
            if let pw = SimHooks.createPassword {
                await model.createVault(password: pw)
                try? model.addItem(fields: ["kind": "login", "username": "samus@example.com", "password": "Sample-Only-Password1",
                                            "website": "https://github.com", "otp": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"],
                                   folder: "logins", nickname: "", suggested: "github")
                try? model.addItem(fields: ["kind": "card", "cardholder": "Samus Aran", "number": "4242424242424242",
                                               "expiry": "08/27", "cvv": "123", "billing_zip": "12345"],
                                      folder: "cards", nickname: "", suggested: "visa-4242")
                try? model.addItem(fields: ["kind": "card", "cardholder": "Samus Aran", "number": "5555555555554444",
                                               "expiry": "11/28", "cvv": "456"],
                                      folder: "cards", nickname: "", suggested: "mastercard-4444")
                try? model.addItem(fields: ["kind": "bank", "bank": "Chase", "holder": "Samus Aran", "account_type": "checking",
                                               "routing": "021000021", "account_number": "000123456789"],
                                      folder: "banks", nickname: "", suggested: "chase-6789")
            }
        }
        #endif
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.stashVault, .data]) { result in
            if case .success(let url) = result { model.received(url) }
        }
    }

    private func step(_ n: Int, _ text: String, code: String? = nil) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(n)")
                .font(.mono(13, weight: .semibold))
                .foregroundStyle(Color.ink)
                .frame(width: 24, height: 24)
                .background(Color.surfaceRaised, in: Circle())
                .overlay(Circle().strokeBorder(Color.line))
            VStack(alignment: .leading, spacing: 6) {
                Text(text).font(.plex(15)).foregroundStyle(Color.ink)
                if let code {
                    Text(code)
                        .font(.mono(12.5))
                        .foregroundStyle(Color.inkSecondary)
                        .textSelection(.enabled)
                }
            }
        }
    }
}

// MARK: - Lock

struct LockView: View {
    #if DEBUG
    @MainActor private static var simUnlocked = false
    #endif
    @EnvironmentObject var model: PhoneModel
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            StashMark(size: UnlockCurtain.lockMarkSize)
                .background(GeometryReader { geo in
                    Color.clear
                        .onAppear { model.lockMarkCenter = center(of: geo) }
                        .onChange(of: geo.frame(in: .global)) { model.lockMarkCenter = center(of: geo) }
                })
            VStack(spacing: 6) {
                Wordmark(size: 30)
                Text("Your vault, one glance away.").font(.plex(15)).foregroundStyle(Color.inkSecondary)
            }
            if model.faceIDEnrolled {
                Button {
                    Task { await model.unlockWithFaceID() }
                } label: {
                    Label("Unlock with Face ID", systemImage: "faceid")
                        .font(.plex(16, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .tint(.keyholeAmber)
                .foregroundStyle(Color.vaultInk)
            }
            HStack {
                SecureField("Vault password", text: $password)
                    .textContentType(.password)
                    .focused($focused)
                    .tint(.keyholeAmber) // the cursor
                    .submitLabel(.go)
                    .onSubmit(submit)
                    .font(.plex(16))
                Button(action: submit) {
                    Image(systemName: "arrow.right.circle.fill").font(.system(size: 26))
                }
                // Amber only when it's the main way in.
                .tint(model.faceIDEnrolled ? .inkSecondary : .keyholeAmber)
                .disabled(password.isEmpty || model.busy)
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(Color.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.line))

            if model.busy { ProgressView() }
            if let error = model.error {
                Label(error, systemImage: "exclamationmark.circle")
                    .font(.plex(14)).foregroundStyle(Color.danger)
                    .multilineTextAlignment(.center)
            }
            Spacer()
            Spacer()
        }
        .padding(.horizontal, 28)
        .background(Color.canvas.ignoresSafeArea())
        .task {
            #if DEBUG
            // Simulator screenshots only (never in release builds).
            if !Self.simUnlocked, let pw = SimHooks.password {
                // Once: a later lock has to stay locked for that to be checkable.
                Self.simUnlocked = true
                await model.unlock(password: pw)
                return
            }
            #endif
            await model.offerFaceIDIfDue()
            if !model.faceIDEnrolled { focused = true }
        }
    }

    private func center(of geo: GeometryProxy) -> CGPoint {
        let frame = geo.frame(in: .global)
        return CGPoint(x: frame.midX, y: frame.midY)
    }

    private func submit() {
        let pw = password
        password = ""
        Task { await model.unlock(password: pw) }
    }
}

// MARK: - List

struct VaultListView: View {
    @EnvironmentObject var model: PhoneModel
    @State private var showingSettings = false
    @State private var deleting: PhoneItem?
    @State private var path: [PhoneItem] = []
    @State private var adding: AddKind?
    @State private var search = ""

    private func matching(_ items: [PhoneItem]) -> [PhoneItem] {
        guard !search.isEmpty else { return items }
        return items.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || ($0.subtitle?.localizedCaseInsensitiveContains(search) ?? false)
        }
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                section("Cards", matching(model.cards))
                section("Bank Accounts", matching(model.banks))
                section("Logins", matching(model.logins))
                if model.items.isEmpty {
                    Text(model.madeHere
                         ? "Nothing here yet. Tap + to add a login, card, or bank account."
                         : "Nothing in this vault yet.")
                        .foregroundStyle(Color.inkSecondary)
                }
            }
            .searchable(text: $search, prompt: "Search")
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .scrollContentBackground(.hidden)
            .background(Color.canvas)
            .navigationTitle("stash")
            .navigationBarTitleDisplayMode(.inline)
            .navigationDestination(for: PhoneItem.self) { DetailView(item: $0) }
            #if DEBUG
            .onAppear {
                // Simulator screenshots only (never in release builds).
                if let name = SimHooks.open,
                   let item = model.items.first(where: { $0.name == name }) {
                    path = [item]
                }
                if SimHooks.shows("add-card") { adding = .card }
                if SimHooks.shows("add-bank") { adding = .bank }
                if SimHooks.shows("add-login") { adding = .login }
                if SimHooks.shows("settings") { showingSettings = true }
                if SimHooks.shows("delete") { deleting = model.items.first }
                if SimHooks.shows("ask-face-id") { model.askAboutFaceID = true }
            }
            #endif
            .toolbar {
                ToolbarItem(placement: .principal) { Wordmark(size: 19) }
                ToolbarItem(placement: .topBarLeading) {
                    Button { showingSettings = true } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if model.madeHere {
                        Menu {
                            Button("Add a Login", systemImage: "person.badge.key") { adding = .login }
                            Button("Add a Card", systemImage: "creditcard") { adding = .card }
                            Button("Add a Bank Account", systemImage: "building.columns") { adding = .bank }
                        } label: {
                            Label("Add", systemImage: "plus")
                        }
                    }
                    Button { model.lock() } label: { Label("Lock", systemImage: "lock.fill") }
                }
            }
            .sheet(item: $adding) { kind in
                Group {
                    switch kind {
                    case .login: LoginFormView()
                    case .card: AddPaymentView(kind: .card)
                    case .bank: AddPaymentView(kind: .bank)
                    }
                }
                .sheetGuarded()
            }
            .sheet(isPresented: $showingSettings) { SettingsView().sheetGuarded() }
            // An alert, not a dialog: a dialog would point at some other row.
            .alert("Delete \(deleting?.title ?? "this")?", isPresented: Binding(
                get: { deleting != nil }, set: { if !$0 { deleting = nil } }), presenting: deleting) { item in
                Button("Delete", role: .destructive) { _ = model.removeItem(item.name) }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("This is the only copy, and it can't be undone.")
            }
            .alert("Use Face ID to unlock stash?", isPresented: Binding(
                get: { model.askAboutFaceID && !model.unlocking }, set: { _ in })
            ) {
                Button("Use Face ID") { model.answerFaceIDQuestion(useIt: true) }
                Button("Not Now", role: .cancel) { model.answerFaceIDQuestion(useIt: false) }
            } message: {
                Text("Anyone whose face is set up on this iPhone could open your vault. You can change this any time in Settings.")
            }
            .alert("Something went wrong", isPresented: Binding(
                get: { model.error != nil }, set: { if !$0 { model.error = nil } })
            ) {
                Button("OK", role: .cancel) { model.error = nil }
            } message: {
                Text(model.error ?? "")
            }
        }
    }

    @ViewBuilder
    private func section(_ title: String, _ items: [PhoneItem]) -> some View {
        if !items.isEmpty {
            Section(title) { ForEach(items) { row($0) } }
        }
    }

    private func row(_ item: PhoneItem) -> some View {
        NavigationLink(value: item) {
            HStack(spacing: 12) {
                Image(systemName: item.kind.symbol)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(Color.inkSecondary)
                    .frame(width: 36, height: 36)
                    .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title).font(.mono(15, weight: .semibold)).foregroundStyle(Color.ink)
                    if let subtitle = item.subtitle {
                        Text(subtitle).font(.plex(13)).foregroundStyle(Color.inkSecondary)
                    }
                }
            }
            .padding(.vertical, 2)
        }
        .listRowBackground(Color.surface)
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            // Only where the vault can be changed. It asks first, so this has
            // no destructive role: that would animate the row away right now.
            if model.madeHere {
                Button {
                    deleting = item
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .tint(.red)
            }
        }
    }
}
