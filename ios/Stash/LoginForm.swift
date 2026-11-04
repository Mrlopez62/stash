import SwiftUI

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
    /// The generator's settings, shown once you've used it.
    @State private var generated = false
    @State private var length = 24
    @State private var symbols = true
    @State private var setupKey = ""
    /// It has 2FA already. The secret isn't read back: it stays or goes.
    @State private var hasOTP = false
    @State private var removeOTP = false
    @State private var scanning = false
    @State private var scannedKey = false
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
                        Label(generated ? "Generate Another" : "Generate a Strong Password", systemImage: "wand.and.stars")
                            .foregroundStyle(Color.ink)
                    }
                    if generated {
                        Stepper("Length: \(length)", value: $length, in: 8...64)
                            .onChange(of: length) { generate() }
                        Toggle("Symbols", isOn: $symbols)
                            .onChange(of: symbols) { generate() }
                    }
                } footer: {
                    if generated {
                        Text("Letters and numbers\(symbols ? ", plus symbols like ! ? = ( ) ; : and -" : ""). If a site refuses it, try fewer characters or turn off symbols.")
                    }
                }
                .listRowBackground(Color.surface)

                Section {
                    if hasOTP && !removeOTP {
                        LabeledContent("2FA", value: "On")
                        Button("Remove 2FA", role: .destructive) { removeOTP = true }
                    } else if scannedKey {
                        CheckLine(ok: true, text: "QR code scanned. Save to turn on 2FA.")
                        Button("Clear", role: .destructive) {
                            setupKey = ""
                            scannedKey = false
                        }
                    } else {
                        Button {
                            scanning = true
                        } label: {
                            Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                                .foregroundStyle(Color.ink)
                        }
                        SecureField("Or paste the setup key", text: $setupKey)
                    }
                } header: {
                    Text("Two-Factor Code")
                } footer: {
                    if (!hasOTP || removeOTP) && !scannedKey {
                        Text("Optional. Turn on 2FA with an authenticator app on the site, then scan the QR code it shows. stash then shows the codes.")
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
            #if DEBUG
            .onAppear {
                // Simulator checks only (never in release builds).
                if SimHooks.generate { generate() }
                if SimHooks.scan != nil { scanning = true }
                if let code = SimHooks.scannedCode { scanned(code) }
            }
            #endif
            .fullScreenCover(isPresented: $scanning) {
                QRScannerView { code in
                    scanned(code)
                    scanning = false
                }
                .sheetGuarded()
            }
            .sensoryFeedback(.success, trigger: scannedKey) { _, new in new }
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
    private var suggestedName: String { ItemText.site(fromWebsite: website) ?? "login" }

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

    /// Keep a checked code. Its label can name the site and account, so fill
    /// those in if they're still empty, as suggestions you can change.
    private func scanned(_ code: String) {
        setupKey = code
        scannedKey = true
        let label = ItemText.otpLabel(code)
        if nickname.isEmpty, let issuer = label.issuer { nickname = ItemText.slug(issuer) }
        if username.isEmpty, let account = label.account { username = account }
    }

    private func generate() {
        do {
            password = try VaultCore.generatePassword(length: length, symbols: symbols)
            showPassword = true
            generated = true
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
