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
                .privacyCovered()
                .onChange(of: phase) { _, new in
                    switch new {
                    case .background: model.wentToBackground()
                    case .active:
                        model.checkInbox()
                        Task { await model.offerFaceIDIfDue() }
                    default: break
                    }
                }
                // Neutral: amber is for primary actions, set where they are.
                .tint(.inkSecondary)
        }
    }
}

/// Hidden from the app switcher's snapshot. A sheet sits above the view it
/// came from, so each sheet needs this too.
struct PrivacyCovered: ViewModifier {
    @Environment(\.scenePhase) private var phase

    func body(content: Content) -> some View {
        content.overlay { if phase != .active { PrivacyCover() } }
    }
}

extension View {
    func privacyCovered() -> some View { modifier(PrivacyCovered()) }
}

struct PrivacyCover: View {
    var body: some View {
        // The size and place the unlock animation starts from, so one flows
        // into the other.
        ZStack {
            Color.canvas
            StashMark(size: UnlockCurtain.markSize)
        }
        .ignoresSafeArea()
    }
}
