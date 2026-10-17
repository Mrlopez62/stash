import SwiftUI

struct LockView: View {
    @EnvironmentObject var model: AppModel
    @ViewState private var password = ""
    @FocusState private var focused: Bool

    private var touchID: Bool {
        (model.status?.touchIdEnabled ?? false) && (model.status?.touchIdAvailable ?? false)
    }

    var body: some View {
        VStack(spacing: 28) {
            Spacer()
            HStack(spacing: 16) {
                StashMark(size: 72)
                Wordmark(size: 56)
            }
            Text("Your secrets, one fingerprint away.")
                .font(.system(size: 15))
                .foregroundStyle(Color.secondaryText)

            VStack(spacing: 12) {
                if touchID {
                    Button {
                        Task { await model.unlockWithTouchID() }
                    } label: {
                        Label("Unlock with Touch ID", systemImage: "touchid")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(AmberButtonStyle())
                    .keyboardShortcut(.defaultAction)

                    Text("or enter your master password")
                        .font(.caption)
                        .foregroundStyle(Color.redacted)
                }
                HStack(spacing: 8) {
                    SecureField("Master password", text: $password)
                        .textFieldStyle(.plain)
                        .font(.mono(14))
                        .padding(10)
                        .background(Color.enclave, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.border))
                        .focused($focused)
                        .onSubmit(submitPassword)
                    if !touchID {
                        Button("Unlock", action: submitPassword)
                            .buttonStyle(AmberButtonStyle())
                            .disabled(password.isEmpty)
                    }
                }
            }
            .frame(width: 340)

            if let error = model.error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .frame(width: 340)
            }
            Spacer()
            Text(model.status?.vaultPath ?? "")
                .font(.mono(11))
                .foregroundStyle(Color.redacted)
                .padding(.bottom, 16)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.vaultInk)
        .disabled(model.busy)
        .task {
            if touchID {
                await model.unlockWithTouchID()
            } else {
                focused = true
            }
        }
    }

    private func submitPassword() {
        guard !password.isEmpty else { return }
        let pw = password
        password = ""
        Task { await model.unlock(password: pw) }
    }
}

struct CreateVaultView: View {
    @EnvironmentObject var model: AppModel
    @ViewState private var password = ""
    @ViewState private var confirm = ""

    private var problem: String? {
        if password.count < 8 { return "Use at least 8 characters — a long passphrase is best." }
        if password != confirm { return "The passwords don't match." }
        return nil
    }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            HStack(spacing: 16) {
                StashMark(size: 64)
                Wordmark(size: 48)
            }
            Text("Create your vault")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(Color.plaintext)
            Text("Choose a master password. It's the one thing stash can't recover for you, so make it memorable and long.")
                .font(.callout)
                .foregroundStyle(Color.secondaryText)
                .multilineTextAlignment(.center)
                .frame(width: 360)
            VStack(spacing: 10) {
                SecureField("Master password", text: $password)
                SecureField("Confirm master password", text: $confirm)
            }
            .textFieldStyle(.roundedBorder)
            .frame(width: 340)
            Button("Create Vault") {
                let pw = password
                password = ""
                confirm = ""
                Task { await model.createVault(password: pw) }
            }
            .buttonStyle(AmberButtonStyle())
            .disabled(problem != nil)
            Text(problem ?? model.error ?? " ")
                .font(.caption)
                .foregroundStyle(model.error != nil ? .red : Color.redacted)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.vaultInk)
    }
}

/// The primary action: amber, used sparingly.
struct AmberButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: .semibold))
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .foregroundStyle(Color.vaultInk)
            .background(
                Color.keyholeAmber.opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.4),
                in: RoundedRectangle(cornerRadius: 8))
    }
}
