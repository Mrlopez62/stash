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
                switch kind {
                case .card: cardFields
                case .bank: bankFields
                }
                Section {
                    TextField(suggestedName, text: $nickname)
                } header: {
                    Text("Nickname")
                } footer: {
                    if let error {
                        Text(error).foregroundStyle(Color.danger)
                    }
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
            }
            #endif
            .onAppear(perform: fill)
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
                if let status = PaymentHints.cardStatus(number) {
                    CardStatusLine(brand: status.brand, text: status.text, note: status.note)
                        .foregroundStyle(status.ok ? Color.inkSecondary : Color.danger)
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
        case .card: !number.isEmpty
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
             "cvv": cvv, "pin": pin, "billing_zip": billingZip]
        case .bank:
            ["kind": "bank", "bank": bank, "holder": holder, "account_type": accountType, "routing": routing,
             "account_number": accountNumber, "iban": iban, "swift": swift, "pin": pin]
        }
        let folder = kind == .card ? "cards" : "banks"
        do {
            if let editing {
                onSaved(try model.updatePayment(editing, fields: fields, folder: folder, nickname: nickname))
            } else {
                try model.addPayment(fields: fields, folder: folder, nickname: nickname, suggested: suggestedName)
            }
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
