import SwiftUI
import UIKit
import UniformTypeIdentifiers

extension UTType {
    /// A `.stashvault` file, from `stash export --phone`.
    static let stashVault = UTType(exportedAs: "io.github.mrlopez62.stash.vault", conformingTo: .data)
}

/// Everything the phone app knows. Its vault is a copy of the one
/// `stash export --phone` wrote on the Mac, kept in the app's private
/// storage with complete file protection.
@MainActor
final class PhoneModel: ObservableObject {
    enum Screen { case welcome, locked, unlocked }

    @Published var screen: Screen
    @Published var items: [PhoneItem] = []
    @Published var error: String?
    @Published var busy = false
    @Published var toast: String?
    /// A vault file waiting to replace the current one (asks first).
    @Published var pendingImport: URL?
    @Published var faceIDEnrolled = FaceIDKeys.enrolled

    private var core: VaultCore?

    nonisolated static var vaultURL: URL { URL.applicationSupportDirectory.appending(path: "vault.stashvault") }
    /// Files dropped into stash from Finder or the Files app.
    nonisolated static var inbox: URL { URL.documentsDirectory }

    init() {
        screen = FileManager.default.fileExists(atPath: Self.vaultURL.path) ? .locked : .welcome
    }

    var cards: [PhoneItem] { items.filter { $0.kind == .card } }
    var banks: [PhoneItem] { items.filter { $0.kind == .bank } }

    // MARK: Getting the vault

    /// A `.stashvault` file arrived (AirDrop, Files, Finder): import it,
    /// asking first if it would replace the vault already here.
    func received(_ url: URL) {
        if screen == .welcome {
            importVault(from: url)
        } else {
            pendingImport = url
        }
    }

    /// Look in the folder Finder and the Files app drop files into.
    func checkInbox() {
        let files = (try? FileManager.default.contentsOfDirectory(at: Self.inbox, includingPropertiesForKeys: nil)) ?? []
        if let file = files.first(where: { $0.pathExtension == "stashvault" }) {
            received(file)
        }
    }

    func importVault(from url: URL) {
        pendingImport = nil
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            lock()
            let fm = FileManager.default
            try fm.createDirectory(at: Self.vaultURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let staging = Self.vaultURL.appendingPathExtension("new")
            try? fm.removeItem(at: staging)
            try fm.copyItem(at: url, to: staging)
            try (staging as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey)
            if fm.fileExists(atPath: Self.vaultURL.path) {
                _ = try fm.replaceItemAt(Self.vaultURL, withItemAt: staging)
            } else {
                try fm.moveItem(at: staging, to: Self.vaultURL)
            }
            // New keys: Face ID has to be set up again for this vault.
            FaceIDKeys.forget()
            faceIDEnrolled = false
            // Don't leave a second copy lying around.
            if url.path.hasPrefix(Self.inbox.path) || url.path.contains("/Inbox/") {
                try? fm.removeItem(at: url)
            }
            screen = .locked
            error = nil
            flash("Vault added. Unlock it with its password.")
        } catch {
            self.error = "Couldn't add that file: \(error.localizedDescription)"
        }
    }

    /// Remove the vault (and Face ID) from this iPhone.
    func removeVault() {
        lock()
        try? FileManager.default.removeItem(at: Self.vaultURL)
        FaceIDKeys.forget()
        faceIDEnrolled = false
        screen = .welcome
    }

    // MARK: Locking

    func unlock(password: String) async {
        guard !password.isEmpty else { return }
        await open { try VaultCore.open(path: Self.vaultURL, password: password) }
        // First unlock with the password: offer Face ID from now on.
        if screen == .unlocked, FaceIDKeys.available, !FaceIDKeys.enrolled, let keys = core?.copyKeys() {
            do {
                try FaceIDKeys.enroll(keys)
                faceIDEnrolled = true
            } catch {
                self.error = "Face ID couldn't be set up: \(error.localizedDescription)"
            }
        }
    }

    func unlockWithFaceID() async {
        do {
            let keys = try await FaceIDKeys.unlock(reason: "Unlock your cards and bank accounts")
            await open { try VaultCore.open(path: Self.vaultURL, keys: keys) }
        } catch is CancellationError {
        } catch {
            faceIDEnrolled = FaceIDKeys.enrolled
            self.error = error.localizedDescription
        }
    }

    private func open(_ make: @escaping @Sendable () throws -> VaultCore) async {
        busy = true
        defer { busy = false }
        do {
            // Argon2 takes a moment: keep the screen responsive.
            let opened = try await Task.detached(priority: .userInitiated) { try make() }.value
            core = opened
            items = try opened.list()
            screen = .unlocked
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func lock() {
        core?.close()
        core = nil
        items = []
        if screen == .unlocked { screen = .locked }
    }

    func setFaceID(_ on: Bool) {
        if on, let keys = core?.copyKeys() {
            do {
                try FaceIDKeys.enroll(keys)
            } catch {
                self.error = "Face ID couldn't be set up: \(error.localizedDescription)"
            }
        } else if !on {
            FaceIDKeys.forget()
        }
        faceIDEnrolled = FaceIDKeys.enrolled
    }

    // MARK: Items

    func detail(_ name: String) -> PhoneDetail? {
        do {
            return try core?.item(name)
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }

    func reveal(_ name: String, _ field: String) -> String? {
        do {
            return try core?.reveal(name, field: field)
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }

    /// Copy a value: kept on this iPhone (no Universal Clipboard) and
    /// cleared after a minute.
    func copy(_ value: String, label: String) {
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: value]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
        flash("Copied \(label) · clears in 60s")
    }

    func flash(_ message: String) {
        withAnimation { toast = message }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2.2))
            if toast == message { withAnimation { toast = nil } }
        }
    }
}
