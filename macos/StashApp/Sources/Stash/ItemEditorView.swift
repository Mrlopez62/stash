import SwiftUI
import UniformTypeIdentifiers

enum EditorTarget: Identifiable {
    case new(ItemKind)
    case edit(ItemDetail)

    var id: String {
        switch self {
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
    /// The result of the last QR scan, shown under the 2FA field.
    @ViewState private var qrStatus: QRStatus?
    @ViewState private var dropTargeted = false

    private var isNew: Bool { if case .new = target { true } else { false } }
    private var original: ItemDetail? { if case .edit(let d) = target { d } else { nil } }

    var body: some View {
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
                            LabeledInput("Name", hint: "Use a slash for folders, like work/aws") {
                                FieldBox {
                                    TextField("", text: $name, prompt: Text("github").foregroundStyle(Color.inkTertiary))
                                }
                            }
                            if kind == .login {
                                LabeledInput("Username") {
                                    FieldBox(mono: false) {
                                        TextField("", text: $username, prompt: Text("you@example.com").foregroundStyle(Color.inkTertiary))
                                    }
                                }
                            }
                            if kind != .note { secretInput }
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
                            Text("Notes").font(.plex(11.5, weight: .medium)).foregroundStyle(Color.inkTertiary)
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
                                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.line))
                            }
                        }
                    }

                    if kind != .note {
                        Card(padding: 16, fill: true) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("More fields").font(.plex(11.5, weight: .medium)).foregroundStyle(Color.inkTertiary)
                                ForEach($custom) { $field in
                                    HStack(spacing: 8) {
                                        FieldBox(mono: false) {
                                            TextField("", text: $field.label, prompt: Text("Label").foregroundStyle(Color.inkTertiary))
                                        }
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
                                Button { custom.append(CustomField()) } label: {
                                    Label("Add field", systemImage: "plus")
                                }
                                .buttonStyle(SecondaryButtonStyle())
                                Text("For visible details like a recovery email. Keep secrets in their own item.")
                                    .font(.plex(11.5))
                                    .foregroundStyle(Color.inkTertiary)
                            }
                        }
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
                    } else if let problem {
                        Text(problem).font(.plex(12)).foregroundStyle(Color.inkTertiary)
                    }
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle())
                        .keyboardShortcut(.cancelAction)
                    Button(isNew ? "Create" : "Save") { Task { await save() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                        .disabled(problem != nil || model.busy)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 14)
            }
            .background(Color.surface)
        }
        .frame(width: 540)
        .frame(minHeight: 420, idealHeight: kind == .login ? 760 : 560, maxHeight: 820)
        .background(Color.canvas)
        .onAppear(perform: load)
    }

    private var secretInput: some View {
        LabeledInput(kind == .login ? "Password" : "Value") {
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

    private var problem: String? {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "Give it a name." }
        if trimmed.contains(" ") { return "Names can't contain spaces (try github or work/aws)." }
        if isNew && kind != .note && secret.isEmpty {
            return kind == .login ? "Enter or generate a password." : "Enter the secret's value."
        }
        if kind == .note && notes.isEmpty && !(hadNotes && !notesLoaded) { return "Write the note." }
        if custom.contains(where: { $0.label.trimmingCharacters(in: .whitespaces).isEmpty }) {
            return "Every field needs a label."
        }
        return nil
    }

    private func load() {
        model.error = nil
        switch target {
        case .new(let k):
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
        case .note:
            break
        }
        if kind != .note {
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
            dismiss()
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

/// A label above an input, with an optional hint below.
struct LabeledInput<Content: View>: View {
    let label: String
    var hint: String?
    @ViewBuilder var content: Content

    init(_ label: String, hint: String? = nil, @ViewBuilder content: () -> Content) {
        self.label = label
        self.hint = hint
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.plex(11.5, weight: .medium)).foregroundStyle(Color.inkTertiary)
            content
            if let hint {
                Text(hint).font(.plex(11)).foregroundStyle(Color.inkTertiary)
            }
        }
    }
}
