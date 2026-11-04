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

/// For everything shown over the vault, which can outlive the screen it came
/// from when the app is in the background. Locking takes the content, and any
/// values typed or fetched into it, away at once, and the sheet closes itself.
struct SheetGuarded: ViewModifier {
    @EnvironmentObject private var model: PhoneModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var phase

    func body(content: Content) -> some View {
        Group {
            if model.screen == .locked {
                PrivacyCover()
            } else {
                content.modifier(PrivacyCovered())
            }
        }
        .onChange(of: model.screen) { _, new in
            if new == .locked { dismiss() }
        }
        // A dismissal asked for in the background may not have happened yet.
        .onChange(of: phase) { _, new in
            if new == .active, model.screen == .locked { dismiss() }
        }
    }
}

extension View {
    func privacyCovered() -> some View { modifier(PrivacyCovered()) }
    func sheetGuarded() -> some View { modifier(SheetGuarded()) }
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
