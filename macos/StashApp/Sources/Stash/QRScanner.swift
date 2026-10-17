// Read 2FA setup QR codes: from the screen, the clipboard, or an image file.
//
// Everything happens on this Mac: Vision decodes the QR, and captured
// images live only in memory, never on disk. The decoded otpauth:// URI is
// checked by the backend on save, like a pasted one.

import AppKit
import ScreenCaptureKit
import UniformTypeIdentifiers
import Vision

/// What a 2FA QR code holds: `otpauth://totp/Issuer:account?secret=…&issuer=…`.
struct OTPSetup: Equatable {
    var uri: String
    var issuer: String?
    var account: String?

    /// Parse an otpauth:// TOTP URI, or nil if it isn't one.
    init?(uri raw: String) {
        let uri = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: uri),
              components.scheme?.lowercased() == "otpauth",
              components.host?.lowercased() == "totp",
              components.queryItems?.contains(where: { $0.name.lowercased() == "secret" && !($0.value ?? "").isEmpty }) == true
        else { return nil }
        self.uri = uri
        let label = String(components.path.drop(while: { $0 == "/" }))
        let parts = label.split(separator: ":", maxSplits: 1).map {
            String($0).trimmingCharacters(in: .whitespaces)
        }
        issuer = components.queryItems?.first { $0.name.lowercased() == "issuer" }?.value
            ?? (parts.count == 2 ? parts[0] : nil)
        account = parts.count == 2 ? parts[1] : parts.first.flatMap { $0.isEmpty ? nil : $0 }
    }

    /// A stash item name from the issuer: "GitHub" → "github".
    var suggestedName: String? {
        guard let issuer else { return nil }
        let slug = issuer.lowercased()
            .map { $0.isLetter || $0.isNumber ? $0 : "-" }
            .reduce(into: "") { s, c in if !(c == "-" && s.hasSuffix("-")) { s.append(c) } }
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return slug.isEmpty ? nil : String(slug.prefix(60))
    }
}

enum QRScanError: LocalizedError {
    case noCode
    case notTwoFactor
    case needsPermission
    case unreadableImage

    var errorDescription: String? {
        switch self {
        case .noCode: "No QR code found. Make sure the whole code is visible, then try again."
        case .notTwoFactor: "That QR code isn't a 2FA setup code."
        case .needsPermission:
            "stash needs Screen Recording permission to scan the screen. Allow it in System Settings → Privacy & Security → Screen & System Audio Recording, then try again. Or paste a screenshot instead."
        case .unreadableImage: "That file isn't an image stash can read."
        }
    }
}

enum QRScanner {
    /// All QR payloads in an image.
    static func payloads(in image: CGImage) -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try? VNImageRequestHandler(cgImage: image).perform([request])
        return (request.results ?? []).compactMap(\.payloadStringValue)
    }

    /// The first 2FA setup code in an image.
    static func setup(in image: CGImage) throws -> OTPSetup {
        let found = payloads(in: image)
        guard !found.isEmpty else { throw QRScanError.noCode }
        guard let setup = found.lazy.compactMap(OTPSetup.init(uri:)).first else {
            throw QRScanError.notTwoFactor
        }
        return setup
    }

    /// Scan every display, leaving stash's own windows out of the capture so
    /// a QR code behind them is still found.
    @MainActor
    static func scanScreen() async throws -> OTPSetup {
        if !CGPreflightScreenCaptureAccess() {
            // Shows the system prompt the first time; the user grants it in
            // System Settings and tries again.
            _ = CGRequestScreenCaptureAccess()
            throw QRScanError.needsPermission
        }
        let content: SCShareableContent
        do {
            content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        } catch {
            throw QRScanError.needsPermission
        }
        let me = content.applications.filter { $0.processID == ProcessInfo.processInfo.processIdentifier }
        var sawCode = false
        for display in content.displays {
            let filter = SCContentFilter(display: display, excludingApplications: me, exceptingWindows: [])
            let config = SCStreamConfiguration()
            // Full resolution, so small QR codes still decode.
            let scale = NSScreen.screens.first { $0.displayID == display.displayID }?.backingScaleFactor ?? 2
            config.width = Int(CGFloat(display.width) * scale)
            config.height = Int(CGFloat(display.height) * scale)
            config.showsCursor = false
            guard let image = try? await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config)
            else { continue }
            do {
                return try setup(in: image)
            } catch QRScanError.notTwoFactor {
                sawCode = true
            } catch {}
        }
        throw sawCode ? QRScanError.notTwoFactor : QRScanError.noCode
    }

    /// A QR code image on the clipboard (e.g. a ⌃⇧⌘4 screenshot).
    static func fromPasteboard() throws -> OTPSetup {
        let pb = NSPasteboard.general
        if let text = pb.string(forType: .string), let setup = OTPSetup(uri: text) {
            return setup
        }
        guard let image = NSImage(pasteboard: pb)?.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            throw QRScanError.noCode
        }
        return try setup(in: image)
    }

    static func fromFile(_ url: URL) throws -> OTPSetup {
        guard let image = NSImage(contentsOf: url)?.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            throw QRScanError.unreadableImage
        }
        return try setup(in: image)
    }

    @MainActor
    static func chooseFile() throws -> OTPSetup? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.message = "Choose a screenshot of the 2FA QR code"
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return try fromFile(url)
    }
}

private extension NSScreen {
    var displayID: CGDirectDisplayID? {
        deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? CGDirectDisplayID
    }
}
