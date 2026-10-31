import SwiftUI
import UniformTypeIdentifiers

struct RootView: View {
    @EnvironmentObject var model: PhoneModel

    var body: some View {
        Group {
            switch model.screen {
            case .welcome: WelcomeView()
            case .locked: LockView()
            case .unlocked: VaultListView()
            }
        }
        .overlay {
            if model.unlocking { UnlockCurtain { model.unlocking = false } }
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
                    step(3, "Unlock it with the password you chose. After that, Face ID.")
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
        .sheet(isPresented: $creating) { CreateVaultView().privacyCovered() }
        #if DEBUG
        .task {
            // Simulator checks only (never in release builds).
            let env = ProcessInfo.processInfo.environment
            if env["STASH_SIM_SHOW"] == "create" { creating = true }
            if let pw = env["STASH_SIM_CREATE"] {
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
    @EnvironmentObject var model: PhoneModel
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            StashMark(size: 76)
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
            if let pw = ProcessInfo.processInfo.environment["STASH_SIM_PASSWORD"] {
                await model.unlock(password: pw)
                return
            }
            #endif
            await model.offerFaceIDIfDue()
            if !model.faceIDEnrolled { focused = true }
        }
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
    @State private var confirmRemove = false
    @State private var choosing = false
    @State private var path: [PhoneItem] = []
    @State private var adding: PaymentKind?
    @State private var addingLogin = false
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
                let env = ProcessInfo.processInfo.environment
                if let name = env["STASH_SIM_OPEN"],
                   let item = model.items.first(where: { $0.name == name }) {
                    path = [item]
                }
                if env["STASH_SIM_SHOW"] == "add-card" { adding = .card }
                if env["STASH_SIM_SHOW"] == "add-bank" { adding = .bank }
                if env["STASH_SIM_SHOW"] == "add-login" { addingLogin = true }
            }
            #endif
            .toolbar {
                ToolbarItem(placement: .principal) { Wordmark(size: 19) }
                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        if FaceIDKeys.available {
                            Toggle("Unlock with Face ID", isOn: Binding(
                                get: { model.faceIDEnrolled }, set: { model.setFaceID($0) }))
                        }
                        Button("Replace with a New File…", systemImage: "arrow.triangle.2.circlepath") { choosing = true }
                        Button("Remove from This iPhone", systemImage: "trash", role: .destructive) { confirmRemove = true }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if model.madeHere {
                        Menu {
                            Button("Add a Login", systemImage: "person.badge.key") { addingLogin = true }
                            Button("Add a Card", systemImage: "creditcard") { adding = .card }
                            Button("Add a Bank Account", systemImage: "building.columns") { adding = .bank }
                        } label: {
                            Label("Add", systemImage: "plus")
                        }
                    }
                    Button { model.lock() } label: { Label("Lock", systemImage: "lock.fill") }
                }
            }
            .sheet(item: $adding) { AddPaymentView(kind: $0).privacyCovered() }
            .sheet(isPresented: $addingLogin) { LoginFormView().privacyCovered() }
            .fileImporter(isPresented: $choosing, allowedContentTypes: [.stashVault, .data]) { result in
                if case .success(let url) = result { model.received(url) }
            }
            .alert("Something went wrong", isPresented: Binding(
                get: { model.error != nil }, set: { if !$0 { model.error = nil } })
            ) {
                Button("OK", role: .cancel) { model.error = nil }
            } message: {
                Text(model.error ?? "")
            }
            .confirmationDialog("Remove this vault from this iPhone?",
                                isPresented: $confirmRemove, titleVisibility: .visible) {
                Button("Remove", role: .destructive) { model.removeVault() }
            } message: {
                Text(model.madeHere
                     ? "This is the only copy of them, and it can't be undone."
                     : "They stay in your vault on your Mac.")
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
    }
}

// MARK: - Detail

struct DetailView: View {
    @EnvironmentObject var model: PhoneModel
    let item: PhoneItem
    @State private var detail: PhoneDetail?
    /// Revealed values, by label; hidden again after 30 seconds.
    @State private var shown: [String: String] = [:]
    @State private var confirmDelete = false
    @State private var editing = false
    @State private var finish: CardFinish?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            if let detail {
                if let face = detail.card {
                    CardFaceView(face: face,
                                 cardholder: detail.value("cardholder"),
                                 expiry: detail.value("expiry"),
                                 revealCVV: { model.reveal(item.name, "cvv") },
                                 finish: finish)
                        .padding(.vertical, 8)
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets())
                    Section("Card Color") {
                        CardColorPicker(selection: Binding(get: { finish }, set: { new in
                            finish = new
                            model.setCardColor(item.name, new)
                        }))
                        .listRowBackground(Color.surface)
                    }
                }
                Section {
                    ForEach(detail.fields) { field in
                        if field.kind == .otp {
                            OTPRow(name: item.name)
                        } else {
                            fieldRow(field)
                        }
                    }
                }
                if detail.hasNotes {
                    Section { fieldRow(FieldInfo(label: "notes", kind: .concealed, value: nil)) }
                }
                if model.madeHere {
                    Section {
                        Button("Delete", role: .destructive) { confirmDelete = true }
                            .listRowBackground(Color.surface)
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.canvas)
        .navigationTitle(item.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text(item.title).font(.mono(15, weight: .semibold)).foregroundStyle(Color.ink)
            }
            if model.madeHere {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Edit") { editing = true }
                }
            }
        }
        .sheet(isPresented: $editing) {
            Group {
                if item.kind == .login {
                    LoginFormView(editing: item, onSaved: saved)
                } else {
                    AddPaymentView(kind: item.kind == .bank ? .bank : .card, editing: item, onSaved: saved)
                }
            }
            .privacyCovered()
        }
        #if DEBUG
        .onAppear {
            // Simulator checks only (never in release builds).
            let env = ProcessInfo.processInfo.environment
            if env["STASH_SIM_SHOW"] == "edit" { editing = true }
        }
        #endif
        .confirmationDialog("Delete \(item.title)?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if model.removeItem(item.name) { dismiss() }
            }
        } message: {
            Text("This is the only copy, and it can't be undone.")
        }
        .onAppear {
            detail = model.detail(item.name)
            finish = detail?.cardColor.flatMap(CardFinish.init(rawValue:))
            #if DEBUG
            if let color = ProcessInfo.processInfo.environment["STASH_SIM_COLOR"] { finish = CardFinish(rawValue: color) }
            #endif
        }
        .onDisappear { shown = [:] }
    }

    private func saved(_ name: String) {
        shown = [:]
        // A new nickname is a new item: back to the list to find it.
        if name == item.name { detail = model.detail(name) } else { dismiss() }
    }

    /// Where a saved website opens: web addresses only.
    private func link(_ value: String?) -> URL? {
        guard let value, !value.isEmpty else { return nil }
        let url = URL(string: value.contains("://") ? value : "https://\(value)")
        return ["http", "https"].contains(url?.scheme?.lowercased()) ? url : nil
    }

    private func fieldRow(_ field: FieldInfo) -> some View {
        let value = field.value ?? shown[field.label]
        return HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(displayLabel(field.label))
                    .font(.plex(12.5, weight: .medium))
                    .foregroundStyle(Color.inkSecondary)
                Text(value ?? "••••••••••••")
                    .font(.mono(16))
                    .foregroundStyle(Color.ink)
                    .textSelection(.enabled)
            }
            Spacer()
            if field.kind == .url, let url = link(field.value) {
                Link(destination: url) {
                    Image(systemName: "arrow.up.right.square")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Open website")
            }
            if field.value == nil {
                Button {
                    toggle(field.label)
                } label: {
                    Image(systemName: shown[field.label] == nil ? "eye" : "eye.slash")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(shown[field.label] == nil ? "Show \(field.label)" : "Hide \(field.label)")
            }
            Button {
                if let v = field.value ?? model.reveal(item.name, field.label) {
                    model.copy(v, label: field.label)
                }
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Copy \(field.label)")
        }
        .listRowBackground(Color.surface)
    }

    private func displayLabel(_ label: String) -> String {
        switch label {
        case "number": "Card Number"
        case "cvv": "Security Code"
        case "pin": "PIN"
        case "iban": "IBAN"
        case "swift": "SWIFT"
        case "billing zip": "Billing ZIP"
        case "routing number": "Routing Number"
        default: label.capitalized
        }
    }

    private func toggle(_ label: String) {
        if shown[label] != nil {
            shown[label] = nil
            return
        }
        guard let value = model.reveal(item.name, label) else { return }
        shown[label] = value
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(30))
            shown[label] = nil
        }
    }
}

/// A login's 2FA code, kept current, with the time it has left.
struct OTPRow: View {
    @EnvironmentObject var model: PhoneModel
    let name: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            let otp = model.otp(name)
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("2FA Code")
                        .font(.plex(12.5, weight: .medium))
                        .foregroundStyle(Color.inkSecondary)
                    Text(otp.map { grouped($0.code) } ?? "——— ———")
                        .font(.mono(20, weight: .semibold))
                        .foregroundStyle(Color.ink)
                        .contentTransition(.numericText())
                }
                Spacer()
                if let otp {
                    ZStack {
                        Circle().stroke(Color.line, lineWidth: 2.5)
                        Circle()
                            .trim(from: 0, to: CGFloat(otp.remaining) / CGFloat(max(otp.period, 1)))
                            .stroke(otp.remaining <= 5 ? Color.danger : Color.inkSecondary,
                                    style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(otp.remaining)")
                            .font(.mono(10.5, weight: .medium))
                            .foregroundStyle(Color.inkSecondary)
                    }
                    .frame(width: 28, height: 28)
                    .accessibilityLabel("\(otp.remaining) seconds left")
                }
                Button {
                    if let code = model.otp(name)?.code { model.copy(code, label: "2FA code") }
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Copy 2FA code")
            }
        }
        .listRowBackground(Color.surface)
    }

    private func grouped(_ code: String) -> String {
        let middle = code.count / 2
        return "\(code.prefix(middle)) \(code.suffix(code.count - middle))"
    }
}
