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
        .alert("Replace the vault on this iPhone?", isPresented: $model.pendingImport) {
            Button("Replace", role: .destructive) { model.installStaged() }
            Button("Cancel", role: .cancel) { model.cancelImport() }
        } message: {
            Text("The cards and bank accounts here are swapped for the ones in the new file. Face ID is set up again after you unlock it.")
        }
    }
}

// MARK: - Welcome

struct WelcomeView: View {
    @EnvironmentObject var model: PhoneModel
    @State private var choosing = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 10) {
                    StashMark(size: 64)
                    Wordmark(size: 34)
                    Text("Your cards and bank accounts, from your Mac, with Face ID.")
                        .font(.plex(17))
                        .foregroundStyle(Color.inkSecondary)
                }
                VStack(alignment: .leading, spacing: 14) {
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

                if let error = model.error {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.plex(14)).foregroundStyle(Color.danger)
                }
            }
            .padding(24)
        }
        .background(Color.canvas.ignoresSafeArea())
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
                Text("Your cards, one glance away.").font(.plex(15)).foregroundStyle(Color.inkSecondary)
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

    var body: some View {
        NavigationStack(path: $path) {
            List {
                if !model.cards.isEmpty {
                    Section("Cards") { ForEach(model.cards) { row($0) } }
                }
                if !model.banks.isEmpty {
                    Section("Bank Accounts") { ForEach(model.banks) { row($0) } }
                }
                if model.items.isEmpty {
                    Text("No cards or bank accounts in this vault.").foregroundStyle(Color.inkSecondary)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color.canvas)
            .navigationTitle("stash")
            .navigationBarTitleDisplayMode(.inline)
            .navigationDestination(for: PhoneItem.self) { DetailView(item: $0) }
            #if DEBUG
            .onAppear {
                // Simulator screenshots only (never in release builds).
                if let name = ProcessInfo.processInfo.environment["STASH_SIM_OPEN"],
                   let item = model.items.first(where: { $0.name == name }) {
                    path = [item]
                }
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
                ToolbarItem(placement: .topBarTrailing) {
                    Button { model.lock() } label: { Label("Lock", systemImage: "lock.fill") }
                }
            }
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
            .confirmationDialog("Remove your cards and bank accounts from this iPhone?",
                                isPresented: $confirmRemove, titleVisibility: .visible) {
                Button("Remove", role: .destructive) { model.removeVault() }
            } message: {
                Text("They stay in your vault on your Mac.")
            }
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

    var body: some View {
        List {
            if let detail {
                if let face = detail.card {
                    CardFaceView(face: face,
                                 cardholder: detail.value("cardholder"),
                                 expiry: detail.value("expiry"),
                                 revealCVV: { model.reveal(item.name, "cvv") })
                        .padding(.vertical, 8)
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets())
                }
                Section {
                    ForEach(detail.fields) { field in fieldRow(field) }
                }
                if detail.hasNotes {
                    Section { fieldRow(FieldInfo(label: "notes", kind: .concealed, value: nil)) }
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
        }
        .onAppear { detail = model.detail(item.name) }
        .onDisappear { shown = [:] }
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
