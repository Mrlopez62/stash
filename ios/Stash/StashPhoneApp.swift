import SwiftUI

@main
struct StashPhoneApp: App {
    @StateObject private var model = PhoneModel()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                // AirDrop, "Open in stash" from Files, or a tap on the file.
                .onOpenURL { model.received($0) }
                // Hidden from the app switcher's snapshot.
                .overlay { if phase != .active { PrivacyCover() } }
                .onChange(of: phase) { _, new in
                    switch new {
                    case .background: model.lock()
                    case .active: model.checkInbox()
                    default: break
                    }
                }
                .tint(.keyholeAmber)
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color.canvas.ignoresSafeArea()
            StashMark(size: 72)
        }
    }
}
