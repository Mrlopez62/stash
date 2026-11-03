// Simulator checks only: settings read from `STASH_SIM_*` environment
// variables (pass them to `xcrun simctl launch` with `SIMCTL_CHILD_` in
// front). None of this is compiled into a release build. The card's fixed
// tilt, STASH_SIM_TILT, lives with the card in CardVisuals.swift, which the
// Mac app shares.

#if DEBUG
import Foundation

enum SimHooks {
    private static func value(_ name: String) -> String? {
        ProcessInfo.processInfo.environment["STASH_SIM_\(name)"]
    }

    /// Unlock with this password, once.
    static var password: String? { value("PASSWORD") }
    /// Make a vault with this password, with sample items.
    static var createPassword: String? { value("CREATE") }
    /// Open this item once unlocked.
    static var open: String? { value("OPEN") }
    /// Show a screen: create, add-card, add-bank, add-login, settings,
    /// delete, ask-face-id, or edit.
    static func shows(_ screen: String) -> Bool { value("SHOW") == screen }
    /// Type these into the card form.
    static var cardNumber: String? { value("NUMBER") }
    static var expiry: String? { value("EXPIRY") }
    /// Generate a password in the login form.
    static var generate: Bool { value("GENERATE") != nil }
    /// Open the QR scanner; "viewfinder" shows it without a camera.
    static var scan: String? { value("SCAN") }
    /// Accept this as a scanned 2FA code.
    static var scannedCode: String? { value("QR") }
    /// Show the open card in this color, without saving it.
    static var color: String? { value("COLOR") }
}
#endif
