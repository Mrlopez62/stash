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
    /// A checked vault file is waiting to replace the current one (asks first).
    @Published var pendingImport = false
    @Published var faceIDEnrolled = FaceIDKeys.enrolled

    private var core: VaultCore?
    /// Ask for Face ID without a tap: only when the app opens or you come
    /// back to it. After you lock it, it waits for "Unlock with Face ID".
    private var offerFaceID = true

    nonisolated static var vaultURL: URL { URL.applicationSupportDirectory.appending(path: "vault.stashvault") }
    /// An incoming file, while it's checked and waits to be confirmed.
    nonisolated static var stagedURL: URL { URL.applicationSupportDirectory.appending(path: "incoming.stashvault") }
    /// Files dropped into stash from Finder or the Files app.
    nonisolated static var inbox: URL { URL.documentsDirectory }

    init() {
        screen = FileManager.default.fileExists(atPath: Self.vaultURL.path) ? .locked : .welcome
    }

    var cards: [PhoneItem] { items.filter { $0.kind == .card } }
    var banks: [PhoneItem] { items.filter { $0.kind == .bank } }

    // MARK: Getting the vault

    /// A file arrived (AirDrop, Files, Finder). It's copied aside and checked
    /// first, so nothing that isn't a vault can ever replace the one here.
    /// Replacing asks first; the first vault just goes in.
    func received(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: Self.vaultURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? fm.removeItem(at: Self.stagedURL)
            try fm.copyItem(at: url, to: Self.stagedURL)
            try Self.protect(Self.stagedURL)
            try VaultCore.check(path: Self.stagedURL)
            error = nil
            if screen == .welcome {
                installStaged()
            } else {
                pendingImport = true
            }
        } catch {
            try? fm.removeItem(at: Self.stagedURL)
            self.error = error.localizedDescription
        }
        // The app has its own copy now: don't leave another lying around, or
        // ask about this file again next time.
        let path = url.resolvingSymlinksInPath().path
        if path.hasPrefix(Self.inbox.resolvingSymlinksInPath().path) || path.contains("/Inbox/") {
            try? fm.removeItem(at: url)
        }
    }

    /// Look in the folder Finder and the Files app drop files into.
    func checkInbox() {
        let files = (try? FileManager.default.contentsOfDirectory(at: Self.inbox, includingPropertiesForKeys: nil)) ?? []
        if let file = files.first(where: { $0.pathExtension == "stashvault" }) {
            received(file)
        }
    }

    /// Keep the vault in the checked copy, replacing any there.
    func installStaged() {
        pendingImport = false
        let fm = FileManager.default
        do {
            lock()
            if fm.fileExists(atPath: Self.vaultURL.path) {
                _ = try fm.replaceItemAt(Self.vaultURL, withItemAt: Self.stagedURL)
            } else {
                try fm.moveItem(at: Self.stagedURL, to: Self.vaultURL)
            }
            try Self.protect(Self.vaultURL)
            // New keys: Face ID has to be set up again for this vault.
            FaceIDKeys.forget()
            faceIDEnrolled = false
            screen = .locked
            error = nil
            flash("Vault added. Unlock it with its password.")
        } catch {
            self.error = "Couldn't add that file: \(error.localizedDescription)"
        }
    }

    func cancelImport() {
        pendingImport = false
        try? FileManager.default.removeItem(at: Self.stagedURL)
    }

    /// Readable only while the phone is unlocked, and left out of iCloud and
    /// computer backups, where only the vault's password would protect it.
    /// A new phone gets a new export instead.
    nonisolated static func protect(_ url: URL) throws {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
        try (url as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey)
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
        offerFaceID = false
        core?.close()
        core = nil
        items = []
        if screen == .unlocked { screen = .locked }
    }

    /// Leaving the app locks it, and coming back offers Face ID.
    func wentToBackground() {
        lock()
        offerFaceID = true
    }

    /// Ask for Face ID now if it's due: at most once, so cancelling it (or
    /// tapping Lock) never brings the prompt straight back.
    func offerFaceIDIfDue() async {
        guard offerFaceID, screen == .locked, faceIDEnrolled,
              UIApplication.shared.applicationState == .active else { return }
        offerFaceID = false
        await unlockWithFaceID()
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
