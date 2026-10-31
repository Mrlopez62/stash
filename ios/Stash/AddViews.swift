import SwiftUI

// Making a vault on this iPhone, and adding to it. Every field here turns off
// autocorrect, so numbers and names stay out of the keyboard's memory.

// MARK: - New vault

struct CreateVaultView: View {
    @EnvironmentObject var model: PhoneModel
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirm = ""

    private static let minimumLength = 8

    private var problem: String? {
        if !password.isEmpty, password.count < Self.minimumLength {
            return "Use at least \(Self.minimumLength) characters."
        }
        if !confirm.isEmpty, confirm != password { return "The passwords don't match." }
        return nil
    }

    private var ready: Bool {
        password.count >= Self.minimumLength && confirm == password && !model.busy
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Password", text: $password)
                        .textContentType(.newPassword)
                    SecureField("Confirm password", text: $confirm)
                        .textContentType(.newPassword)
                } header: {
                    Text("Choose a password")
                } footer: {
                    if let problem {
                        Text(problem).foregroundStyle(Color.danger)
                    } else {
                        Text("You'll type it if Face ID isn't available. Nobody can reset it for you.")
                    }
                }
                .listRowBackground(Color.surface)

                Section {
                    Button {
                        Task { await model.createVault(password: password) }
                    } label: {
                        HStack {
                            if model.busy { ProgressView().tint(Color.vaultInk) }
                            Text("Create Vault")
                                .font(.plex(16, weight: .semibold))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.keyholeAmber)
                    .foregroundStyle(Color.vaultInk)
                    .disabled(!ready)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                } footer: {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("This vault lives only on this iPhone. It isn't in iCloud or any backup, so a lost phone, or a lost password once Face ID stops working, means starting over.")
                        if let error = model.error {
                            Text(error).foregroundStyle(Color.danger)
                        }
                    }
                    .padding(.top, 10)
                }
            }
            .font(.plex(16))
            .tint(.keyholeAmber) // the cursor
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .scrollContentBackground(.hidden)
            .background(Color.canvas)
            .navigationTitle("New Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .tint(.inkSecondary)
                        .disabled(model.busy)
                }
            }
            .interactiveDismissDisabled(model.busy)
        }
    }
}

// MARK: - New card or bank account

enum PaymentKind: Identifiable {
    case card, bank
    var id: Self { self }
}

struct AddPaymentView: View {
    @EnvironmentObject var model: PhoneModel
    @Environment(\.dismiss) private var dismiss
    let kind: PaymentKind
    /// The item being changed; nil adds a new one.
    var editing: PhoneItem?
    /// After saving, with the item's name.
    var onSaved: (String) -> Void = { _ in }
    @State private var loaded = false

    @State private var nickname = ""
    @State private var error: String?
    // Card
    @State private var number = ""
    @State private var cardColor: CardFinish?
    @State private var cardholder = ""
    @State private var expiry = ""
    @State private var cvv = ""
    @State private var billingZip = ""
    // Bank
    @State private var bank = ""
    @State private var holder = ""
    @State private var accountType = "checking"
    @State private var routing = ""
    @State private var accountNumber = ""
    @State private var iban = ""
    @State private var swift = ""
    // Both
    @State private var pin = ""

    var body: some View {
        NavigationStack {
            Form {
                if kind == .card, editing == nil {
                    Section {
                        PremiumCard(
                            content: CardContent(
                                brand: PaymentHints.brand(number),
                                number: CardNumberDisplay.preview(number, reveal: false),
                                cardholder: cardholder.isEmpty ? nil : cardholder,
                                expiry: expiry.isEmpty ? nil : expiry,
                                finish: cardColor),
                            interactive: false, sheenOnAppear: false)
                            .frame(maxWidth: .infinity)
                            .listRowBackground(Color.clear)
                            .listRowInsets(EdgeInsets())
                    }
                    Section("Card Color") {
                        CardColorPicker(selection: $cardColor)
                            .listRowBackground(Color.surface)
                    }
                }
                switch kind {
                case .card: cardFields
                case .bank: bankFields
                }
                Section {
                    TextField(suggestedName, text: $nickname)
                } header: {
                    Text("Nickname")
                }
                .listRowBackground(Color.surface)
            }
            .font(.plex(16))
            .tint(.keyholeAmber) // the cursor
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .scrollContentBackground(.hidden)
            .background(Color.canvas)
            #if DEBUG
            // Simulator checks only (never in release builds).
            .onAppear {
                if let typed = ProcessInfo.processInfo.environment["STASH_SIM_NUMBER"] { number = typed }
                if let typed = ProcessInfo.processInfo.environment["STASH_SIM_EXPIRY"] { expiry = typed }
            }
            #endif
            .onAppear(perform: fill)
            // Not in the form: it could be scrolled out of sight.
            .alert("Couldn't Save", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(error ?? "")
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.tint(.inkSecondary)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save)
                        .fontWeight(.semibold)
                        .tint(.keyholeAmber)
                        .disabled(!canSave)
                }
            }
        }
    }

    private var cardFields: some View {
        Group {
            Section {
                TextField("Card number", text: $number)
                    .keyboardType(.numberPad)
                    .font(.mono(16))
                    .onChange(of: number) { _, new in
                        let grouped = CardNumberDisplay.typed(new)
                        if grouped != new { number = grouped }
                    }
                TextField("Name on card", text: $cardholder)
                    .textInputAutocapitalization(.words)
                TextField("Expiry (MM/YY)", text: $expiry)
                    .keyboardType(.numberPad)
                    .font(.mono(16))
                    .onChange(of: expiry) { _, new in
                        let formatted = PaymentHints.formatExpiry(new)
                        if formatted != new { expiry = formatted }
                    }
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    if let status = PaymentHints.cardStatus(number) {
                        CardStatusLine(ok: status.ok, brand: status.brand, text: status.text, note: status.note)
                            .foregroundStyle(Color.inkSecondary)
                    }
                    if let status = PaymentHints.expiryStatus(expiry) {
                        HStack(spacing: 6) {
                            Text("Expiry").foregroundStyle(Color.inkSecondary)
                            CheckLine(ok: status.ok, text: status.text)
                        }
                    }
                }
            }
            .listRowBackground(Color.surface)
            Section {
                SecureField("Security code", text: $cvv)
                    .keyboardType(.numberPad)
                SecureField("PIN", text: $pin)
                    .keyboardType(.numberPad)
                TextField("Billing ZIP", text: $billingZip)
                    .keyboardType(.numbersAndPunctuation)
            }
            .listRowBackground(Color.surface)
        }
    }

    private var bankFields: some View {
        Group {
            Section {
                TextField("Bank", text: $bank)
                    .textInputAutocapitalization(.words)
                TextField("Account holder", text: $holder)
                    .textInputAutocapitalization(.words)
                Picker("Account type", selection: $accountType) {
                    Text("Checking").tag("checking")
                    Text("Savings").tag("savings")
                }
                .tint(.inkSecondary)
            }
            .listRowBackground(Color.surface)
            Section {
                TextField("Routing number", text: $routing)
                    .keyboardType(.numberPad)
                    .font(.mono(16))
                SecureField("Account number", text: $accountNumber)
                    .keyboardType(.numberPad)
            } footer: {
                if !routing.isEmpty, PaymentHints.digits(routing).count >= 9, !PaymentHints.routingOK(routing) {
                    Text("Check the routing number for a typo.").foregroundStyle(Color.danger)
                }
            }
            .listRowBackground(Color.surface)
            Section("International") {
                TextField("IBAN", text: $iban)
                    .textInputAutocapitalization(.characters)
                    .font(.mono(16))
                TextField("SWIFT", text: $swift)
                    .textInputAutocapitalization(.characters)
                    .font(.mono(16))
            }
            .listRowBackground(Color.surface)
            Section {
                SecureField("PIN", text: $pin)
                    .keyboardType(.numberPad)
            }
            .listRowBackground(Color.surface)
        }
    }

    private var title: String {
        switch (kind, editing) {
        case (.card, nil): "New Card"
        case (.bank, nil): "New Bank Account"
        case (.card, _): "Edit Card"
        case (.bank, _): "Edit Bank Account"
        }
    }

    /// Start from what's saved when editing. Values are fetched only now.
    private func fill() {
        guard let editing, !loaded else { return }
        loaded = true
        let saved = model.editableValues(editing.name)
        nickname = editing.title
        pin = saved["pin"] ?? ""
        switch kind {
        case .card:
            number = saved["number"] ?? ""
            cardholder = saved["cardholder"] ?? ""
            expiry = saved["expiry"] ?? ""
            cvv = saved["cvv"] ?? ""
            billingZip = saved["billing zip"] ?? ""
        case .bank:
            bank = saved["bank"] ?? ""
            holder = saved["account holder"] ?? ""
            accountType = saved["account type"] ?? accountType
            routing = saved["routing number"] ?? ""
            accountNumber = saved["account number"] ?? ""
            iban = saved["iban"] ?? ""
            swift = saved["swift"] ?? ""
        }
    }

    private var canSave: Bool {
        switch kind {
        // A half-typed date or an impossible one can't be saved.
        case .card: !number.isEmpty && (expiry.isEmpty || PaymentHints.expiryStatus(expiry)?.blocks == false)
        case .bank: !(routing.isEmpty && accountNumber.isEmpty && iban.isEmpty)
        }
    }

    /// "visa-4242", "chase-6789": what it's called without a nickname.
    private var suggestedName: String {
        switch kind {
        case .card:
            let last4 = String(PaymentHints.digits(number).suffix(4))
            return PhoneModel.slug("\(PaymentHints.brand(number) ?? "card") \(last4)")
        case .bank:
            let last4 = String((accountNumber.isEmpty ? iban : accountNumber).suffix(4))
            return PhoneModel.slug("\(bank.isEmpty ? "bank" : bank) \(last4)")
        }
    }

    private func save() {
        let fields: [String: String] = switch kind {
        case .card:
            ["kind": "card", "number": number, "cardholder": cardholder, "expiry": expiry,
             "cvv": cvv, "pin": pin, "billing_zip": billingZip, "card_color": cardColor?.rawValue ?? ""]
        case .bank:
            ["kind": "bank", "bank": bank, "holder": holder, "account_type": accountType, "routing": routing,
             "account_number": accountNumber, "iban": iban, "swift": swift, "pin": pin]
        }
        let folder = kind == .card ? "cards" : "banks"
        do {
            if let editing {
                var changes = fields
                // Set from the card's own screen when editing.
                changes["card_color"] = nil
                onSaved(try model.updateItem(editing, fields: changes, folder: folder, nickname: nickname))
            } else {
                try model.addItem(fields: fields, folder: folder, nickname: nickname, suggested: suggestedName)
            }
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

// MARK: - Card color

struct CardColorPicker: View {
    @Binding var selection: CardFinish?

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 14) {
                swatch(nil, top: Color(hex: 0x3A4250), bottom: .vaultInk, title: "Automatic")
                // Lit from the glow, so colors this dark can be told apart.
                ForEach(CardFinish.allCases) { swatch($0, top: $0.glow, bottom: $0.bottom, title: $0.title) }
            }
            .padding(.vertical, 6)
            .padding(.horizontal, 3)
        }
    }

    private func swatch(_ finish: CardFinish?, top: Color, bottom: Color, title: String) -> some View {
        Button {
            selection = finish
        } label: {
            VStack(spacing: 6) {
                Circle()
                    .fill(LinearGradient(colors: [top, bottom], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .overlay(Circle().strokeBorder(Color.white.opacity(0.18), lineWidth: 0.5))
                    .frame(width: 34, height: 34)
                    .padding(3)
                    .overlay(Circle().strokeBorder(selection == finish ? Color.keyholeAmber : .clear, lineWidth: 2))
                Text(title)
                    .font(.plex(11, weight: selection == finish ? .semibold : .regular))
                    .foregroundStyle(selection == finish ? Color.ink : Color.inkSecondary)
                    .fixedSize()
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityAddTraits(selection == finish ? .isSelected : [])
    }
}

// MARK: - Login

struct LoginFormView: View {
    @EnvironmentObject var model: PhoneModel
    @Environment(\.dismiss) private var dismiss
    /// The login being changed; nil adds a new one.
    var editing: PhoneItem?
    /// After saving, with the item's name.
    var onSaved: (String) -> Void = { _ in }

    @State private var loaded = false
    @State private var website = ""
    @State private var username = ""
    @State private var password = ""
    @State private var showPassword = false
    @State private var setupKey = ""
    /// It has 2FA already. The secret isn't read back: it stays or goes.
    @State private var hasOTP = false
    @State private var removeOTP = false
    @State private var nickname = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Website", text: $website)
                        .keyboardType(.URL)
                    TextField("Username or email", text: $username)
                        .keyboardType(.emailAddress)
                }
                .listRowBackground(Color.surface)

                Section {
                    HStack {
                        Group {
                            if showPassword {
                                TextField("Password", text: $password)
                            } else {
                                SecureField("Password", text: $password)
                            }
                        }
                        .font(.mono(16))
                        Button {
                            showPassword.toggle()
                        } label: {
                            Image(systemName: showPassword ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .tint(.inkSecondary)
                        .accessibilityLabel(showPassword ? "Hide password" : "Show password")
                    }
                    Button(action: generate) {
                        Label("Generate a Strong Password", systemImage: "wand.and.stars")
                            .foregroundStyle(Color.ink)
                    }
                }
                .listRowBackground(Color.surface)

                Section {
                    if hasOTP && !removeOTP {
                        LabeledContent("2FA", value: "On")
                        Button("Remove 2FA", role: .destructive) { removeOTP = true }
                    } else {
                        SecureField("Setup key (optional)", text: $setupKey)
                    }
                } header: {
                    Text("Two-Factor Code")
                } footer: {
                    if !hasOTP || removeOTP {
                        Text("The key or otpauth:// link a site gives you when you turn on 2FA. stash then shows the codes.")
                    }
                }
                .listRowBackground(Color.surface)

                Section {
                    TextField(suggestedName, text: $nickname)
                } header: {
                    Text("Nickname")
                }
                .listRowBackground(Color.surface)
            }
            .font(.plex(16))
            .tint(.keyholeAmber) // the cursor
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .scrollContentBackground(.hidden)
            .background(Color.canvas)
            .onAppear(perform: fill)
            // Not in the form: it could be scrolled out of sight.
            .alert("Couldn't Save", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(error ?? "")
            }
            .navigationTitle(editing == nil ? "New Login" : "Edit Login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.tint(.inkSecondary)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save)
                        .fontWeight(.semibold)
                        .tint(.keyholeAmber)
                        .disabled(password.isEmpty)
                }
            }
        }
    }

    /// "https://www.github.com/login" → "github".
    private var suggestedName: String {
        var host = website.lowercased()
        if let range = host.range(of: "://") { host = String(host[range.upperBound...]) }
        host = String(host.prefix { $0 != "/" && $0 != ":" })
        if host.hasPrefix("www.") { host = String(host.dropFirst(4)) }
        let site = PhoneModel.slug(String(host.prefix { $0 != "." }))
        return site.isEmpty ? "login" : site
    }

    private func fill() {
        guard let editing, !loaded else { return }
        loaded = true
        let saved = model.editableValues(editing.name)
        nickname = editing.title
        website = saved["website"] ?? ""
        username = saved["username"] ?? ""
        password = saved["password"] ?? ""
        hasOTP = model.detail(editing.name)?.hasOTP ?? false
    }

    private func generate() {
        do {
            password = try VaultCore.generatePassword()
            showPassword = true
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func save() {
        var fields = ["kind": "login", "username": username, "password": password, "website": website]
        if !setupKey.isEmpty {
            fields["otp"] = setupKey
        } else if removeOTP {
            fields["otp"] = ""
        }
        do {
            if let editing {
                onSaved(try model.updateItem(editing, fields: fields, folder: "logins", nickname: nickname))
            } else {
                try model.addItem(fields: fields, folder: "logins", nickname: nickname, suggested: suggestedName)
            }
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
