import SwiftUI

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

    private var isNew: Bool { if case .new = target { true } else { false } }
    private var original: ItemDetail? { if case .edit(let d) = target { d } else { nil } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                ItemIcon(kind: kind, size: 36)
                Text(isNew ? "New \(kind.title)" : "Edit \(original?.name ?? "")")
                    .font(.system(size: 17, weight: .semibold))
            }
            .padding(20)

            Form {
                TextField("Name", text: $name, prompt: Text("e.g. github or work/aws"))
                    .font(.mono(13))

                if kind == .login {
                    TextField("Username", text: $username)
                }
                if kind != .note {
                    LabeledContent(kind == .login ? "Password" : "Value") {
                        HStack {
                            Group {
                                if showSecret {
                                    TextField("", text: $secret, prompt: Text(isNew ? "" : "Unchanged"))
                                } else {
                                    SecureField("", text: $secret, prompt: Text(isNew ? "" : "Unchanged"))
                                }
                            }
                            .font(.mono(13))
                            Button { showSecret.toggle() } label: {
                                Image(systemName: showSecret ? "eye.slash" : "eye")
                            }
                            .buttonStyle(.borderless)
                            if kind == .login {
                                Button { showGenerator = true } label: {
                                    Image(systemName: "dice")
                                }
                                .buttonStyle(.borderless)
                                .help("Generate a password")
                                .popover(isPresented: $showGenerator) {
                                    GeneratorView { secret = $0; showSecret = true; showGenerator = false }
                                }
                            }
                        }
                    }
                }
                if kind == .login {
                    TextField("Website", text: $website, prompt: Text("https://"))
                    LabeledContent("2FA") {
                        if hadOTP && !removeOTP {
                            HStack {
                                SecureField("", text: $otp, prompt: Text("Unchanged"))
                                Button("Remove") { removeOTP = true; otp = "" }
                                    .buttonStyle(.borderless)
                            }
                        } else {
                            SecureField("", text: $otp, prompt: Text("otpauth:// URI or setup key (optional)"))
                        }
                    }
                }

                Section("Notes") {
                    if hadNotes && !notesLoaded {
                        Button("Edit notes…") {
                            Task {
                                notes = await model.reveal("notes") ?? ""
                                notesLoaded = true
                            }
                        }
                    } else {
                        TextEditor(text: $notes)
                            .font(.system(size: 13))
                            .frame(minHeight: kind == .note ? 160 : 60)
                    }
                }

                if kind != .note {
                    Section("More fields") {
                        ForEach($custom) { $field in
                            HStack {
                                TextField("Label", text: $field.label).frame(width: 140)
                                TextField("Value", text: $field.value)
                                Button { custom.removeAll { $0.id == field.id } } label: {
                                    Image(systemName: "minus.circle")
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                        ForEach(keptHidden) { f in
                            LabeledContent(f.label) { Text("hidden · kept").foregroundStyle(.secondary) }
                        }
                        Button("Add field") { custom.append(CustomField()) }
                            .buttonStyle(.borderless)
                    }
                }
            }
            .formStyle(.grouped)

            if let error = model.error {
                Text(error).font(.callout).foregroundStyle(.red).padding(.horizontal, 20)
            }
            HStack {
                if let problem {
                    Text(problem).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Create" : "Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(AmberButtonStyle())
                    .disabled(problem != nil || model.busy)
            }
            .padding(20)
        }
        .frame(width: 520, height: 600)
        .onAppear(perform: load)
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
            Text(password.isEmpty ? " " : password)
                .font(.mono(15, weight: .medium))
                .textSelection(.enabled)
                .frame(width: 300, alignment: .leading)
                .padding(10)
                .background(Color.enclave, in: RoundedRectangle(cornerRadius: 8))
            HStack {
                Text("Length \(Int(length))").font(.mono(12)).frame(width: 80, alignment: .leading)
                Slider(value: $length, in: 12...64, step: 1)
            }
            Toggle("Symbols", isOn: $symbols)
            HStack {
                Button("Regenerate") { Task { await regenerate() } }
                Spacer()
                Button("Use Password") { use(password) }
                    .buttonStyle(AmberButtonStyle())
                    .disabled(password.isEmpty)
            }
        }
        .padding(16)
        .task(id: "\(Int(length))-\(symbols)") { await regenerate() }
    }

    private func regenerate() async {
        password = await model.generate(length: Int(length), symbols: symbols) ?? ""
    }
}
