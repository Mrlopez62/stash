import SwiftUI

/// A centered card on the canvas, shared by the lock and create screens.
private struct GateCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack {
            Spacer()
            Card(padding: 36) {
                VStack(spacing: 22) { content }
                    .frame(width: 340)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.canvas)
    }
}

private struct Brand: View {
    var body: some View {
        VStack(spacing: 14) {
            StashMark(size: 64)
            Wordmark(size: 34)
        }
    }
}

struct LockView: View {
    @EnvironmentObject var model: AppModel
    @ViewState private var password = ""
    @FocusState private var focused: Bool

    private var touchID: Bool {
        (model.status?.touchIdEnabled ?? false) && (model.status?.touchIdAvailable ?? false)
    }

    var body: some View {
        GateCard {
            Brand()
            Text("Your secrets, one fingerprint away.")
                .font(.plex(14))
                .foregroundStyle(Color.inkSecondary)

            VStack(spacing: 14) {
                if touchID {
                    Button {
                        Task { await model.unlockWithTouchID() }
                    } label: {
                        Label("Unlock with Touch ID", systemImage: "touchid")
                    }
                    .buttonStyle(PrimaryButtonStyle(wide: true))
                    .keyboardShortcut(.defaultAction)

                    HStack(spacing: 10) {
                        Rectangle().fill(Color.line).frame(height: 1)
                        Text("or").font(.plex(12)).foregroundStyle(Color.inkTertiary)
                        Rectangle().fill(Color.line).frame(height: 1)
                    }
                }
                FieldBox(icon: "lock", mono: false) {
                    SecureField("", text: $password, prompt: Text("Master password").font(.plex(13.5)).foregroundStyle(Color.inkTertiary))
                        .focused($focused)
                        .onSubmit(submitPassword)
                }
                if !touchID {
                    Button("Unlock", action: submitPassword)
                        .buttonStyle(PrimaryButtonStyle(wide: true))
                        .disabled(password.isEmpty)
                }
            }

            if let error = model.error {
                Label(error, systemImage: "exclamationmark.circle")
                    .font(.plex(12.5))
                    .foregroundStyle(Color.danger)
                    .multilineTextAlignment(.center)
            }

            Text(model.status?.vaultPath ?? "")
                .font(.mono(11))
                .foregroundStyle(Color.inkTertiary)
        }
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
        if password.count < 8 { return "Use at least 8 characters. A long passphrase is best." }
        if password != confirm { return "The passwords don't match." }
        return nil
    }

    var body: some View {
        GateCard {
            Brand()
            VStack(spacing: 6) {
                Text("Create your vault")
                    .font(.plex(18, weight: .semibold))
                    .foregroundStyle(Color.ink)
                Text("Your master password is the one thing stash can't recover, so make it long and memorable.")
                    .font(.plex(13))
                    .foregroundStyle(Color.inkSecondary)
                    .multilineTextAlignment(.center)
            }
            VStack(spacing: 10) {
                FieldBox(icon: "lock", mono: false) {
                    SecureField("", text: $password, prompt: Text("Master password").font(.plex(13.5)).foregroundStyle(Color.inkTertiary))
                }
                FieldBox(icon: "lock", mono: false) {
                    SecureField("", text: $confirm, prompt: Text("Confirm master password").font(.plex(13.5)).foregroundStyle(Color.inkTertiary))
                }
            }
            Button("Create Vault") {
                let pw = password
                password = ""
                confirm = ""
                Task { await model.createVault(password: pw) }
            }
            .buttonStyle(PrimaryButtonStyle(wide: true))
            .disabled(problem != nil)
            Text(model.error ?? problem ?? " ")
                .font(.plex(12))
                .foregroundStyle(model.error != nil ? Color.danger : Color.inkTertiary)
                .multilineTextAlignment(.center)
        }
    }
}
