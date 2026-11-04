import SwiftUI

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var model: PhoneModel
    @Environment(\.dismiss) private var dismiss
    @State private var choosing = false
    @State private var confirmRemove = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if FaceIDKeys.available {
                        Toggle("Unlock with Face ID", isOn: Binding(
                            get: { model.faceIDEnrolled }, set: { model.setFaceID($0) }))
                            .tint(.keyholeAmber)
                    } else {
                        LabeledContent("Unlock with Face ID", value: "Not available")
                    }
                } footer: {
                    Text(model.faceIDEnrolled
                         ? "stash asks for Face ID when you open it. Your password still works."
                         : "stash asks for your vault password every time you open it.")
                }
                .listRowBackground(Color.surface)

                Section("This Vault") {
                    Button {
                        choosing = true
                    } label: {
                        Label("Replace with a New File…", systemImage: "arrow.triangle.2.circlepath")
                            .foregroundStyle(Color.ink)
                    }
                    Button("Remove from This iPhone", systemImage: "trash", role: .destructive) { confirmRemove = true }
                }
                .listRowBackground(Color.surface)
            }
            .font(.plex(16))
            .scrollContentBackground(.hidden)
            .background(Color.canvas)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.tint(.inkSecondary)
                }
            }
            .fileImporter(isPresented: $choosing, allowedContentTypes: [.stashVault, .data]) { result in
                if case .success(let url) = result {
                    // Replacing asks first, and that question needs this sheet gone.
                    dismiss()
                    model.received(url)
                }
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
}
