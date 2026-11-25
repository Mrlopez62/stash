import SwiftUI
import UniformTypeIdentifiers

enum EditorTarget: Identifiable {
    /// Pick what kind of item to create first (this one preselected).
    case choose(ItemKind)
    case new(ItemKind)
    case edit(ItemDetail)

    var id: String {
        switch self {
        case .choose: "choose"
        case .new(let kind): "new-\(kind.rawValue)"
        case .edit(let detail): "edit-\(detail.name)"
        }
    }
}

/// Create or edit an item. Secret fields you don't touch are sent as "keep",
/// so editing never loads passwords or 2FA secrets into the app.
struct ItemEditorView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let target: EditorTarget
    /// Back to the "New Item" picker, when this form was opened from it.
    var onBack: (() -> Void)? = nil

    @ViewState private var kind: ItemKind = .login
    @ViewState private var name = ""
    @ViewState private var username = ""
    @ViewState private var website = ""
    @ViewState private var secret = ""
    @ViewState private var otp = ""
    @ViewState private var hadOTP = false
    @ViewState private var removeOTP = false
    @ViewState private var notes = ""
    @ViewState private var notesLoaded = false
    @ViewState private var hadNotes = false
    /// Visible custom fields (editable) and hidden ones (kept as they are).
    @ViewState private var custom: [CustomField] = []
    @ViewState private var keptHidden: [FieldInfo] = []
    @ViewState private var secretLabel = "value"
    @ViewState private var showGenerator = false
    @ViewState private var showSecret = false
    // Payment cards. Sensitive values are empty unless being changed.
    @ViewState private var cardholder = ""
    @ViewState private var cardNumber = ""
    @ViewState private var expiry = ""
    @ViewState private var cvv = ""
    @ViewState private var pin = ""
    @ViewState private var billingZip = ""
    /// The card's color; nil lets its network pick.
    @ViewState private var cardColor: CardFinish?
    @ViewState private var showCardNumber = false
    @FocusState private var cvvFocused: Bool
    /// Which sensitive payment fields the item already has (kept if untouched).
    @ViewState private var storedSensitive: Set<String> = []

    @ViewState private var sshComment = ""
    @ViewState private var sshImporting = false
    @ViewState private var sshFile: URL?
    @ViewState private var sshPassphrase = ""
    @ViewState private var sshNeedsPassphrase = false
    // Bank accounts.
    @ViewState private var bankName = ""
    @ViewState private var holder = ""
    @ViewState private var accountType = "checking"
    @ViewState private var routing = ""
    @ViewState private var accountNumber = ""
    @ViewState private var iban = ""
    @ViewState private var swift = ""
    /// The result of the last QR scan, shown under the 2FA field.
    @ViewState private var qrStatus: QRStatus?
    @ViewState private var dropTargeted = false
    /// Set once Create/Save is pressed with something missing: from then on
    /// each field with a problem shows it in red, until it's fixed.
    @ViewState private var showErrors = false

    private var isNew: Bool { if case .new = target { true } else { false } }
    private var original: ItemDetail? { if case .edit(let d) = target { d } else { nil } }

    var body: some View {
        ScrollViewReader { proxy in
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                ItemIcon(kind: kind, size: 34)
                Text(isNew ? "New \(kind.title)" : "Edit \(original?.name ?? "")")
                    .font(.plex(17, weight: .semibold))
                    .foregroundStyle(Color.ink)
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.top, 22)
            .padding(.bottom, 16)

            ScrollView {
                VStack(spacing: 16) {
                    Card(padding: 16, fill: true) {
                        VStack(alignment: .leading, spacing: 14) {
                            LabeledInput("Name", hint: "Use a slash for folders, like work/aws", error: error(.name)) {
                                FieldBox {
                                    TextField("", text: $name, prompt: Text(namePlaceholder).foregroundStyle(Color.inkTertiary))
                                }
                            }
                            .id(FormField.name)
                            if kind == .login {
                                LabeledInput("Username") {
                                    FieldBox(mono: false) {
                                        TextField("", text: $username, prompt: Text("you@example.com").foregroundStyle(Color.inkTertiary))
                                    }
                                }
                            }
                            switch kind {
                            case .login, .secret: secretInput
                            case .card: cardInputs
                            case .bank: bankInputs
                            case .ssh: sshInputs
                            case .note: EmptyView()
                            }
                            if kind == .login {
                                LabeledInput("Website") {
                                    FieldBox(mono: false) {
                                        TextField("", text: $website, prompt: Text("https://").foregroundStyle(Color.inkTertiary))
                                    }
                                }
                                otpInput
                            }
                        }
                    }

                    Card(padding: 16, fill: true) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Notes").font(.plex(11.5, weight: .medium))
                                .foregroundStyle(error(.notes) == nil ? Color.inkTertiary : Color.danger)
                            if hadNotes && !notesLoaded {
                                Button {
                                    Task {
                                        notes = await model.reveal("notes") ?? ""
                                        notesLoaded = true
                                    }
                                } label: {
                                    Label("Edit notes", systemImage: "eye")
                                }
                                .buttonStyle(SecondaryButtonStyle())
                            } else {
                                TextEditor(text: $notes)
                                    .font(.plex(13.5))
                                    .scrollContentBackground(.hidden)
                                    .padding(8)
                                    .frame(minHeight: kind == .note ? 180 : 72)
                                    .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        .strokeBorder(error(.notes) == nil ? Color.line : Color.danger))
                            }
                            if let message = error(.notes) { FieldError(message) }
                        }
                    }
                    .id(FormField.notes)

                    if kind != .note && kind != .ssh {
                        Card(padding: 16, fill: true) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("More fields").font(.plex(11.5, weight: .medium)).foregroundStyle(Color.inkTertiary)
                                ForEach($custom) { $field in
                                    HStack(spacing: 8) {
                                        FieldBox(mono: false) {
                                            TextField("", text: $field.label, prompt: Text("Label").foregroundStyle(Color.inkTertiary))
                                        }
                                        .environment(\.fieldInvalid, showErrors && field.label.trimmingCharacters(in: .whitespaces).isEmpty)
                                        .frame(width: 150)
                                        FieldBox {
                                            TextField("", text: $field.value, prompt: Text("Value").foregroundStyle(Color.inkTertiary))
                                        } trailing: {
                                            IconButton("trash", help: "Remove field") {
                                                custom.removeAll { $0.id == field.id }
                                            }
                                        }
                                    }
                                }
                                ForEach(keptHidden) { f in
                                    HStack {
                                        Text(displayLabel(f.label)).font(.plex(13)).foregroundStyle(Color.ink)
                                        Spacer()
                                        Text("Hidden, kept as is").font(.plex(12)).foregroundStyle(Color.inkTertiary)
                                    }
                                }
                                if let message = error(.customLabels) { FieldError(message) }
                                Button { custom.append(CustomField()) } label: {
                                    Label("Add field", systemImage: "plus")
                                }
                                .buttonStyle(SecondaryButtonStyle())
                                Text("For visible details like a recovery email. Keep secrets in their own item.")
                                    .font(.plex(11.5))
                                    .foregroundStyle(Color.inkTertiary)
                            }
                        }
                        .id(FormField.customLabels)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 20)
            }

            VStack(spacing: 0) {
                // A hint that the form scrolls under the footer.
                LinearGradient(colors: [Color.canvas.opacity(0), Color.canvas], startPoint: .top, endPoint: .bottom)
                    .frame(height: 14)
                    .offset(y: -14)
                    .padding(.bottom, -14)
                    .allowsHitTesting(false)
                Rectangle().fill(Color.line).frame(height: 1)
                HStack(spacing: 10) {
                    if let error = model.error {
                        Label(error, systemImage: "exclamationmark.circle")
                            .font(.plex(12))
                            .foregroundStyle(Color.danger)
                            .lineLimit(2)
                    } else if showErrors, let problem {
                        Label(issues.count > 1 ? "Fix the \(issues.count) fields marked in red." : problem,
                              systemImage: "exclamationmark.circle.fill")
                            .font(.plex(12, weight: .medium))
                            .foregroundStyle(Color.danger)
                            .lineLimit(2)
                    } else if let problem {
                        Text(problem).font(.plex(12)).foregroundStyle(Color.inkTertiary)
                    }
                    Spacer()
                    if let onBack {
                        Button {
                            model.error = nil
                            showErrors = false
                            onBack()
                        } label: {
                            Label("Back", systemImage: "chevron.left")
                        }
                        .buttonStyle(SecondaryButtonStyle())
                    }
                    Button("Cancel") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle())
                        .keyboardShortcut(.cancelAction)
                    // Not disabled when something's missing: pressing it shows
                    // what to fix instead of leaving the user guessing.
                    Button(isNew ? "Create" : "Save") { attemptSave(proxy) }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                        .disabled(model.busy)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 14)
            }
            .background(Color.surface)
        }
        }
        .frame(width: 540)
        .frame(minHeight: 420, idealHeight: kind == .login ? 760 : 560, maxHeight: 820)
        .background(Color.canvas)
        .onAppear(perform: load)
    }

    private var namePlaceholder: String {
        switch kind {
        case .login: "github"
        case .secret: "openai/api-key"
        case .note: "notes/wifi"
        case .card: "cards/visa"
        case .bank: "banks/chase-checking"
        case .ssh: "ssh/github"
        }
    }

    private func keepPrompt(_ label: String, _ empty: String = "") -> Text {
        Text(storedSensitive.contains(label) ? "Unchanged" : empty).foregroundStyle(Color.inkTertiary)
    }

    /// The live card above the form: it fills in as you type, and turns over
    /// while you enter the security code.
    private var cardPreview: some View {
        let editingFace: CardFace? = if case .edit(let d) = target { d.card } else { nil }
        let brand = PaymentHints.brand(cardNumber) ?? (cardNumber.isEmpty ? editingFace?.brand : nil)
        let number = cardNumber.isEmpty && editingFace != nil
            ? CardNumberDisplay.preview("000000000000" + editingFace!.last4, reveal: false)
            : CardNumberDisplay.preview(cardNumber, reveal: showCardNumber)
        let code = String(repeating: "•", count: min(cvv.count, 4))
        return PremiumCard(
            content: CardContent(
                brand: brand,
                number: number,
                cardholder: cardholder.isEmpty ? nil : cardholder,
                expiry: expiry.isEmpty ? nil : expiry,
                cvv: code.isEmpty ? nil : code,
                finish: cardColor),
            flipped: cvvFocused,
            interactive: false,
            sheenOnAppear: true,
            maxWidth: 300)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .accessibilityHidden(true)
    }

    @ViewBuilder private var cardInputs: some View {
        cardPreview
        LabeledInput("Card color") {
            CardFinishPicker(selection: $cardColor)
        }
        LabeledInput("Cardholder") {
            FieldBox(mono: false) {
                TextField("", text: $cardholder, prompt: Text("Name on the card").foregroundStyle(Color.inkTertiary))
            }
        }
        LabeledInput("Card number", error: error(.cardNumber)) {
            VStack(alignment: .leading, spacing: 6) {
                FieldBox {
                    Group {
                        if showCardNumber {
                            TextField("", text: $cardNumber, prompt: keepPrompt("number", "1234 5678 9012 3456"))
                        } else {
                            SecureField("", text: $cardNumber, prompt: keepPrompt("number", "1234 5678 9012 3456"))
                        }
                    }
                } trailing: {
                    IconButton(showCardNumber ? "eye.slash" : "eye", help: showCardNumber ? "Hide" : "Show") {
                        showCardNumber.toggle()
                    }
                }
                if error(.cardNumber) == nil, let status = PaymentHints.cardStatus(cardNumber) {
                    CardStatusLine(ok: status.ok, brand: status.brand, text: status.text, note: status.note)
                        .font(.plex(11.5, weight: .medium))
                        .foregroundStyle(Color.inkSecondary)
                }
            }
        }
        .id(FormField.cardNumber)
        HStack(alignment: .top, spacing: 12) {
            LabeledInput("Expires", invalid: error(.expiry) != nil) {
                FieldBox {
                    TextField("", text: $expiry, prompt: Text("MM/YY").foregroundStyle(Color.inkTertiary))
                        .onChange(of: expiry) { _, new in
                            let formatted = PaymentHints.formatExpiry(new)
                            if !new.contains("/") && formatted != new { expiry = formatted }
                        }
                }
            }
            LabeledInput("Security code", invalid: error(.cvv) != nil) {
                FieldBox { SecureField("", text: $cvv, prompt: keepPrompt("cvv", "CVV")).focused($cvvFocused) }
            }
            .id(FormField.cvv)
            LabeledInput("PIN") {
                FieldBox { SecureField("", text: $pin, prompt: keepPrompt("pin", "Optional")) }
            }
        }
        .id(FormField.expiry)
        // The row's columns are too narrow for a message, so expiry and
        // security code problems are spelled out under the whole row.
        if let message = error(.expiry) {
            FieldError(message)
        } else if let status = PaymentHints.expiryStatus(expiry) {
            CheckLine(ok: status.ok, text: status.text)
                .font(.plex(11.5, weight: .medium))
        }
        if let message = error(.cvv) { FieldError(message) }
        LabeledInput("Billing ZIP or postal code") {
            FieldBox { TextField("", text: $billingZip, prompt: Text("Optional").foregroundStyle(Color.inkTertiary)) }
        }
    }

    @ViewBuilder private var bankInputs: some View {
        HStack(alignment: .top, spacing: 12) {
            LabeledInput("Bank") {
                FieldBox(mono: false) {
                    TextField("", text: $bankName, prompt: Text("Chase").foregroundStyle(Color.inkTertiary))
                }
            }
            LabeledInput("Account type") {
                Picker("", selection: $accountType) {
                    Text("Checking").tag("checking")
                    Text("Savings").tag("savings")
                    Text("Business").tag("business")
                    Text("Other").tag("other")
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .frame(width: 140)
            }
        }
        LabeledInput("Account holder") {
            FieldBox(mono: false) {
                TextField("", text: $holder, prompt: Text("Name on the account").foregroundStyle(Color.inkTertiary))
            }
        }
        LabeledInput("Routing number", hint: routingHint, error: error(.routing)) {
            FieldBox { TextField("", text: $routing, prompt: Text("9 digits (US)").foregroundStyle(Color.inkTertiary)) }
        }
        .id(FormField.routing)
        LabeledInput("Account number", error: error(.accountNumber)) {
            FieldBox { SecureField("", text: $accountNumber, prompt: keepPrompt("account number")) }
        }
        .id(FormField.accountNumber)
        HStack(alignment: .top, spacing: 12) {
            LabeledInput("IBAN", error: error(.iban)) {
                FieldBox { SecureField("", text: $iban, prompt: keepPrompt("iban", "Optional, outside the US")) }
            }
            .id(FormField.iban)
            LabeledInput("SWIFT/BIC") {
                FieldBox { TextField("", text: $swift, prompt: Text("Optional").foregroundStyle(Color.inkTertiary)) }
            }
            .frame(width: 150)
        }
    }

    private var routingHint: String? {
        let d = PaymentHints.digits(routing)
        guard !d.isEmpty else { return nil }
        if d.count < 9 { return nil }
        return PaymentHints.routingOK(d) ? "Routing number checks out" : "That routing number doesn't check out; look for a typo"
    }

    private var secretInput: some View {
        LabeledInput(kind == .login ? "Password" : "Value", error: error(.secret)) {
            FieldBox {
                Group {
                    if showSecret {
                        TextField("", text: $secret, prompt: Text(isNew ? "" : "Unchanged").foregroundStyle(Color.inkTertiary))
                    } else {
                        SecureField("", text: $secret, prompt: Text(isNew ? "" : "Unchanged").foregroundStyle(Color.inkTertiary))
                    }
                }
            } trailing: {
                IconButton(showSecret ? "eye.slash" : "eye", help: showSecret ? "Hide" : "Show") { showSecret.toggle() }
                if kind == .login {
                    IconButton("dice", help: "Generate a password") { showGenerator = true }
                        .popover(isPresented: $showGenerator, arrowEdge: .trailing) {
                            GeneratorView { secret = $0; showSecret = true; showGenerator = false }
                        }
                }
            }
        }
        .id(FormField.secret)
    }

    private var otpInput: some View {
        LabeledInput(
            hadOTP && !removeOTP ? "Two-factor" : "Two-factor (optional)",
            hint: qrStatus == nil ? "Scan the site's 2FA QR code, drop a screenshot of it here, or paste its setup key" : nil
        ) {
            VStack(alignment: .leading, spacing: 6) {
                FieldBox {
                    SecureField("", text: $otp, prompt: Text(hadOTP && !removeOTP ? "Unchanged" : "otpauth://… or setup key").foregroundStyle(Color.inkTertiary))
                } trailing: {
                    Menu {
                        Button { Task { await scan { try await QRScanner.scanScreen() } } } label: {
                            Label("Scan QR Code on Screen", systemImage: "qrcode.viewfinder")
                        }
                        Button { Task { await scan { try QRScanner.fromPasteboard() } } } label: {
                            Label("Paste QR Code Image", systemImage: "doc.on.clipboard")
                        }
                        Button { Task { await scan { try QRScanner.chooseFile() } } } label: {
                            Label("Choose Image…", systemImage: "photo")
                        }
                    } label: {
                        Label("Scan QR", systemImage: "qrcode.viewfinder")
                            .font(.plex(12, weight: .medium))
                            .padding(.horizontal, 8)
                            .frame(height: 26)
                            .background(Color.surface, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Color.line))
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .tint(Color.inkSecondary)
                    .foregroundStyle(Color.inkSecondary)
                    .help("Set up 2FA from the site's QR code")
                    if hadOTP && !removeOTP {
                        IconButton("trash", help: "Remove two-factor") { removeOTP = true; otp = ""; qrStatus = nil }
                    }
                }
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(Color.keyholeAmber, style: StrokeStyle(lineWidth: 1.5, dash: [5, 3]))
                        .opacity(dropTargeted ? 1 : 0))
                .onDrop(of: [.image, .fileURL], isTargeted: $dropTargeted, perform: dropped)
                if let qrStatus {
                    Label(qrStatus.text, systemImage: qrStatus.ok ? "checkmark.circle.fill" : "exclamationmark.circle")
                        .font(.plex(11.5, weight: qrStatus.ok ? .medium : .regular))
                        .foregroundStyle(qrStatus.ok ? Color.success : Color.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    /// Run a QR source and apply what it finds: the secret, plus a name and
    /// username for new items that don't have them yet.
    private func scan(_ source: () async throws -> OTPSetup?) async {
        do {
            guard let setup = try await source() else { return }
            apply(setup)
        } catch {
            qrStatus = QRStatus(ok: false, text: error.localizedDescription)
        }
    }

    private func apply(_ setup: OTPSetup) {
        otp = setup.uri
        removeOTP = false
        if isNew && name.trimmingCharacters(in: .whitespaces).isEmpty, let suggested = setup.suggestedName {
            name = suggested
        }
        if kind == .login && username.isEmpty, let account = setup.account {
            username = account
        }
        let who = [setup.issuer, setup.account].compactMap { $0 }.joined(separator: " · ")
        qrStatus = QRStatus(ok: true, text: who.isEmpty ? "Found a 2FA setup code" : "Found 2FA for \(who)")
    }

    private func dropped(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        if provider.canLoadObject(ofClass: URL.self) {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in await scan { try QRScanner.fromFile(url) } }
            }
            return true
        }
        _ = provider.loadDataRepresentation(for: .image) { data, _ in
            guard let data, let image = NSImage(data: data)?.cgImage(forProposedRect: nil, context: nil, hints: nil)
            else { return }
            Task { @MainActor in await scan { try QRScanner.setup(in: image) } }
        }
        return true
    }

    /// Everything that stops a save, in the order the fields appear.
    private var issues: [FormIssue] {
        var found: [FormIssue] = []
        func add(_ field: FormField, _ message: String) { found.append(FormIssue(field: field, message: message)) }

        let trimmed = name.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { add(.name, "Give it a name.") }
        else if trimmed.contains(" ") { add(.name, "Names can't contain spaces (try github or work/aws).") }
        if kind == .ssh && isNew && sshImporting {
            if sshFile == nil { add(.sshFile, "Choose the private key file to import.") }
            else if sshNeedsPassphrase && sshPassphrase.isEmpty { add(.sshPassphrase, "Enter the key file's passphrase.") }
        }
        // Only logins and secrets have a single secret value; cards and bank
        // accounts are checked field by field below.
        if isNew && (kind == .login || kind == .secret) && secret.isEmpty {
            add(.secret, kind == .login ? "Enter or generate a password." : "Enter the secret's value.")
        }
        if kind == .note && notes.isEmpty && !(hadNotes && !notesLoaded) { add(.notes, "Write the note.") }
        if kind == .card {
            if isNew && cardNumber.isEmpty { add(.cardNumber, "Enter the card number.") }
            else if let message = PaymentHints.cardNumberProblem(cardNumber) { add(.cardNumber, message) }
            if !expiry.isEmpty && expiry.range(of: #"^\d{1,2}/(\d{2}|\d{4})$"#, options: .regularExpression) == nil {
                add(.expiry, "Use MM/YY for the expiry date.")
            } else if let status = PaymentHints.expiryStatus(expiry), status.blocks {
                add(.expiry, status.text)
            }
            // Untouched on an edit, the stored number decides the brand.
            let editingBrand: String? = if case .edit(let d) = target { d.card?.brand } else { nil }
            let brand = PaymentHints.brand(cardNumber) ?? (cardNumber.isEmpty ? editingBrand : nil)
            if let message = PaymentHints.cvvProblem(cvv, brand: brand) { add(.cvv, message) }
        }
        if kind == .bank {
            if !routing.isEmpty && !PaymentHints.routingOK(routing) { add(.routing, "Check the routing number for a typo.") }
            let hasStored = storedSensitive.contains("account number") || storedSensitive.contains("iban")
            if accountNumber.isEmpty && iban.isEmpty && !hasStored { add(.accountNumber, "Enter an account number or an IBAN.") }
            if !iban.isEmpty && !PaymentHints.ibanOK(iban) { add(.iban, "That IBAN doesn't check out; look for a typo.") }
        }
        if custom.contains(where: { $0.label.trimmingCharacters(in: .whitespaces).isEmpty }) {
            add(.customLabels, "Every field needs a label.")
        }
        return found
    }

    /// The first thing to fix, shown as a quiet hint before Create is pressed.
    private var problem: String? { issues.first?.message }

    /// The red message under a field, once Create has been pressed.
    private func error(_ field: FormField) -> String? {
        guard showErrors else { return nil }
        return issues.first { $0.field == field }?.message
    }

    /// Save, or point out what's missing: every field with a problem turns
    /// red, and the form scrolls to the first one.
    private func attemptSave(_ proxy: ScrollViewProxy) {
        if let first = issues.first {
            showErrors = true
            withAnimation(.easeInOut(duration: 0.25)) { proxy.scrollTo(first.field, anchor: .center) }
            return
        }
        Task { await save() }
    }

    private func load() {
        model.error = nil
        switch target {
        case .choose(let k), .new(let k):
            kind = k
        case .edit(let d):
            kind = d.kind
            name = d.name
            hadNotes = d.hasNotes
            let standard = ["username", "password", "website", "one-time password"]
            for (i, f) in d.fields.enumerated() {
                switch (d.kind, f.label) {
                case (.login, "username"): username = f.value ?? ""
                case (.login, "website"): website = f.value ?? ""
                case (.login, _) where f.kind == .otp && !hadOTP: hadOTP = true
                case (.login, "password"): break
                case (.secret, _) where i == 0: secretLabel = f.label
                case (.card, "cardholder"): cardholder = f.value ?? ""
                case (.card, "expiry"): expiry = f.value ?? ""
                case (.card, "billing zip"): billingZip = f.value ?? ""
                case (.card, CardFinish.fieldLabel): cardColor = f.value.flatMap(CardFinish.init(rawValue:))
                case (.card, "number"), (.card, "cvv"), (.card, "pin"),
                     (.bank, "account number"), (.bank, "iban"), (.bank, "pin"):
                    storedSensitive.insert(f.label)
                case (.bank, "bank"): bankName = f.value ?? ""
                case (.bank, "account holder"): holder = f.value ?? ""
                case (.bank, "account type"): accountType = f.value ?? "checking"
                case (.bank, "routing number"): routing = f.value ?? ""
                case (.bank, "swift"): swift = f.value ?? ""
                // The key can't be edited here; it's kept as is (and its
                // public half is re-derived on save).
                case (.ssh, _): keptHidden.append(f)
                default:
                    if f.kind.isSensitive {
                        keptHidden.append(f)
                    } else if !standard.contains(f.label) || d.kind != .login {
                        custom.append(CustomField(label: f.label, value: f.value ?? "", kind: f.kind))
                    }
                }
            }
        }
    }

    private func save() async {
        if kind == .ssh && isNew {
            await saveNewSSHKey()
            return
        }
        var fields: [SaveField] = []
        let keepOrNew = { (value: String) -> String? in value.isEmpty ? nil : value }
        switch kind {
        case .login:
            if !username.isEmpty {
                fields.append(.init(label: "username", kind: username.contains("@") ? .email : .text, value: username))
            }
            fields.append(.init(label: "password", kind: .concealed, value: isNew ? secret : keepOrNew(secret)))
            if !website.isEmpty { fields.append(.init(label: "website", kind: .url, value: website)) }
            if !otp.isEmpty {
                fields.append(.init(label: "one-time password", kind: .otp, value: otp))
            } else if hadOTP && !removeOTP {
                fields.append(.init(label: "one-time password", kind: .otp, value: nil))
            }
        case .secret:
            fields.append(.init(label: secretLabel, kind: .concealed, value: isNew ? secret : keepOrNew(secret)))
        case .card:
            appendText("cardholder", cardholder, to: &fields)
            appendSecret("number", cardNumber, to: &fields)
            appendText("expiry", expiry, to: &fields)
            appendSecret("cvv", cvv, to: &fields)
            appendSecret("pin", pin, to: &fields)
            appendText("billing zip", billingZip, to: &fields)
            // Left out for "Automatic", which removes a saved color.
            if let cardColor { appendText(CardFinish.fieldLabel, cardColor.rawValue, to: &fields) }
        case .bank:
            appendText("bank", bankName, to: &fields)
            appendText("account holder", holder, to: &fields)
            appendText("account type", accountType, to: &fields)
            appendText("routing number", routing, to: &fields)
            appendSecret("account number", accountNumber, to: &fields)
            appendSecret("iban", iban, to: &fields)
            appendText("swift", swift, to: &fields)
            appendSecret("pin", pin, to: &fields)
        case .note, .ssh:
            break
        }
        if kind == .ssh {
            fields += keptHidden.map { .init(label: $0.label, kind: $0.kind, value: nil) }
        } else if kind != .note {
            fields += custom.map { .init(label: $0.label.trimmingCharacters(in: .whitespaces), kind: $0.kind, value: $0.value) }
            fields += keptHidden.map { .init(label: $0.label, kind: $0.kind, value: nil) }
        }
        let request = SaveRequest(
            name: name.trimmingCharacters(in: .whitespaces),
            originalName: original?.name,
            kind: kind,
            fields: fields,
            notes: (notesLoaded || !hadNotes) ? notes : nil)
        if await model.save(request) {
            secret = ""
            otp = ""
            cardNumber = ""
            cvv = ""
            pin = ""
            accountNumber = ""
            iban = ""
            dismiss()
        }
    }

    @ViewBuilder private var sshInputs: some View {
        if isNew {
            Picker("", selection: $sshImporting) {
                Text("Generate a new key").tag(false)
                Text("Import a key file").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if sshImporting {
                LabeledInput("Private key file", hint: "Usually ~/.ssh/id_ed25519. Ed25519 keys in OpenSSH format.", error: error(.sshFile)) {
                    HStack(spacing: 10) {
                        Button {
                            chooseSSHFile()
                        } label: {
                            Label(sshFile == nil ? "Choose File…" : "Choose Another…", systemImage: "folder")
                        }
                        .buttonStyle(SecondaryButtonStyle())
                        if let sshFile {
                            Text(sshFile.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                                .font(.mono(12))
                                .foregroundStyle(Color.inkSecondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
                .id(FormField.sshFile)
                if sshNeedsPassphrase {
                    LabeledInput("Passphrase", hint: "Only used to read the file. In stash, the vault protects the key.", error: error(.sshPassphrase)) {
                        FieldBox { SecureField("", text: $sshPassphrase, prompt: Text("The key file's passphrase").foregroundStyle(Color.inkTertiary)) }
                    }
                    .id(FormField.sshPassphrase)
                }
            } else {
                LabeledInput("Comment", hint: "Shown at the end of the public key, like you@laptop.") {
                    FieldBox(mono: false) {
                        TextField("", text: $sshComment, prompt: Text(name.isEmpty ? "you@laptop" : name).foregroundStyle(Color.inkTertiary))
                    }
                }
                Label("A new Ed25519 key, made on this Mac. Only its public half ever leaves stash.", systemImage: "lock.shield")
                    .font(.plex(12))
                    .foregroundStyle(Color.inkSecondary)
            }
        } else {
            Label("The key itself can't be changed. To replace it, make or import a new one.", systemImage: "lock")
                .font(.plex(12))
                .foregroundStyle(Color.inkSecondary)
        }
    }

    private func chooseSSHFile() {
        let panel = NSOpenPanel()
        panel.message = "Choose an SSH private key (the file without .pub)"
        panel.showsHiddenFiles = true
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        sshFile = url
        sshNeedsPassphrase = false
        sshPassphrase = ""
        model.error = nil
    }

    private func saveNewSSHKey() async {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        let result: (ok: Bool, needsPassphrase: Bool)
        if sshImporting, let sshFile {
            guard let text = try? String(contentsOf: sshFile, encoding: .utf8) else {
                model.error = "Couldn't read \(sshFile.lastPathComponent)."
                return
            }
            let passphrase = sshPassphrase.isEmpty ? nil : sshPassphrase
            result = await model.addSSHKey(name: trimmed) {
                try await $0.sshImport(name: trimmed, key: text, passphrase: passphrase)
            }
        } else {
            let comment = sshComment.trimmingCharacters(in: .whitespaces)
            result = await model.addSSHKey(name: trimmed) {
                try await $0.sshGenerate(name: trimmed, comment: comment.isEmpty ? nil : comment)
            }
        }
        if result.needsPassphrase {
            // Ask for it rather than showing an error.
            if !sshNeedsPassphrase { model.error = nil }
            sshNeedsPassphrase = true
        }
        if result.ok {
            sshPassphrase = ""
            dismiss()
        }
    }

    private func appendText(_ label: String, _ value: String, to fields: inout [SaveField]) {
        let v = value.trimmingCharacters(in: .whitespaces)
        if !v.isEmpty { fields.append(.init(label: label, kind: .text, value: v)) }
    }

    /// A new value if typed; "keep" if the item already has one; else nothing.
    private func appendSecret(_ label: String, _ value: String, to fields: inout [SaveField]) {
        if !value.isEmpty {
            fields.append(.init(label: label, kind: .concealed, value: value))
        } else if storedSensitive.contains(label) {
            fields.append(.init(label: label, kind: .concealed, value: nil))
        }
    }
}

struct QRStatus: Equatable {
    var ok: Bool
    var text: String
}

struct CustomField: Identifiable {
    let id = UUID()
    var label = ""
    var value = ""
    var kind: FieldKind = .text
}

struct GeneratorView: View {
    @EnvironmentObject var model: AppModel
    let use: (String) -> Void
    @ViewState private var length = 24.0
    @ViewState private var symbols = true
    @ViewState private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Password generator").font(.plex(13, weight: .semibold)).foregroundStyle(Color.ink)
            Text(password.isEmpty ? " " : password)
                .font(.mono(14, weight: .medium))
                .foregroundStyle(Color.ink)
                .textSelection(.enabled)
                .frame(width: 300, alignment: .leading)
                .padding(10)
                .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.line))
            HStack {
                Text("Length").font(.plex(12)).foregroundStyle(Color.inkSecondary)
                Slider(value: $length, in: 12...64, step: 1)
                Text("\(Int(length))").font(.mono(12)).foregroundStyle(Color.ink).frame(width: 24, alignment: .trailing)
            }
            Toggle("Include symbols", isOn: $symbols).font(.plex(12.5))
            HStack {
                Button { Task { await regenerate() } } label: { Label("Regenerate", systemImage: "arrow.clockwise") }
                    .buttonStyle(SecondaryButtonStyle())
                Spacer()
                Button("Use Password") { use(password) }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(password.isEmpty)
            }
        }
        .padding(16)
        .background(Color.surface)
        .task(id: "\(Int(length))-\(symbols)") { await regenerate() }
    }

    private func regenerate() async {
        password = await model.generate(length: Int(length), symbols: symbols) ?? ""
    }
}

/// The colors a card can be, as swatches: "Automatic" lets the card's
/// network pick. The same choices as on the iPhone.
struct CardFinishPicker: View {
    @Binding var selection: CardFinish?

    var body: some View {
        HStack(spacing: 10) {
            swatch(nil, top: Color(hex: 0x3A4250), bottom: .vaultInk, title: "Automatic")
            // Lit from the glow, so colors this dark can be told apart.
            ForEach(CardFinish.allCases) { swatch($0, top: $0.glow, bottom: $0.bottom, title: $0.title) }
        }
    }

    private func swatch(_ finish: CardFinish?, top: Color, bottom: Color, title: String) -> some View {
        let selected = selection == finish
        return Button {
            selection = finish
        } label: {
            Circle()
                .fill(LinearGradient(colors: [top, bottom], startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay(Circle().strokeBorder(Color.white.opacity(0.18), lineWidth: 0.5))
                .frame(width: 26, height: 26)
                .padding(3)
                .overlay(Circle().strokeBorder(selected ? Color.keyholeAmber : .clear, lineWidth: 2))
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .help(title)
        .accessibilityLabel("\(title) card color")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// A label above an input, with an optional hint below. With an error, the
/// label and the input's border turn red and the error replaces the hint.
struct LabeledInput<Content: View>: View {
    let label: String
    var hint: String?
    var error: String?
    /// Red without a message of its own, for a field whose message is shown
    /// elsewhere (like the expiry date, under its row).
    var invalid = false
    @ViewBuilder var content: Content

    init(_ label: String, hint: String? = nil, error: String? = nil, invalid: Bool = false, @ViewBuilder content: () -> Content) {
        self.label = label
        self.hint = hint
        self.error = error
        self.invalid = invalid
        self.content = content()
    }

    private var isInvalid: Bool { invalid || error != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.plex(11.5, weight: .medium)).foregroundStyle(isInvalid ? Color.danger : Color.inkTertiary)
            content
                .environment(\.fieldInvalid, isInvalid)
            if let error {
                FieldError(error)
            } else if let hint {
                Text(hint).font(.plex(11)).foregroundStyle(Color.inkTertiary)
            }
        }
        .animation(.easeOut(duration: 0.15), value: error)
    }
}

/// A red line under a field saying what to fix.
struct FieldError: View {
    let message: String
    init(_ message: String) { self.message = message }

    var body: some View {
        Label(message, systemImage: "exclamationmark.circle.fill")
            .font(.plex(11.5, weight: .medium))
            .foregroundStyle(Color.danger)
            .fixedSize(horizontal: false, vertical: true)
            .transition(.opacity)
            .accessibilityLabel("Error: \(message)")
    }
}

/// The fields the editor can point at when something stops a save.
enum FormField: Hashable {
    case name, secret, notes, cardNumber, expiry, cvv, routing, accountNumber, iban, sshFile, sshPassphrase, customLabels
}

struct FormIssue: Equatable {
    let field: FormField
    let message: String
}
