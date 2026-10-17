import AppKit
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    enum Screen { case starting, createVault, locked, unlocked, failed(String) }

    @Published var screen: Screen = .starting
    @Published var status: VaultStatus?
    @Published var items: [ItemSummary] = []
    @Published var selection: ItemSummary.ID?
    @Published var detail: ItemDetail?
    @Published var search = ""
    @Published var error: String?
    @Published var busy = false
    /// A value briefly shown after "Copy", for the toast.
    @Published var toast: String?

    let backend: VaultBackend?

    init(backend: VaultBackend?) {
        self.backend = backend
    }

    var filtered: [ItemSummary] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return items }
        return items.filter {
            $0.name.lowercased().contains(q)
                || ($0.username?.lowercased().contains(q) ?? false)
                || ($0.url?.lowercased().contains(q) ?? false)
        }
    }

    // MARK: - Lifecycle

    func start() async {
        guard let backend else {
            screen = .failed("Couldn't start the stash backend. Is the stash command-line tool installed?")
            return
        }
        do {
            let s = try await backend.status()
            status = s
            if !s.vaultExists {
                screen = .createVault
            } else if s.locked {
                screen = .locked
            } else {
                await didUnlock()
            }
        } catch {
            screen = .failed(error.localizedDescription)
        }
    }

    private func run(_ work: () async throws -> Void) async {
        busy = true
        defer { busy = false }
        do {
            error = nil
            try await work()
        } catch let e as BackendError where e.isLocked {
            becameLocked()
        } catch let e as BackendError where e.isCancelled {
            // The user dismissed Touch ID: not an error worth shouting about.
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func becameLocked() {
        items = []
        detail = nil
        selection = nil
        screen = .locked
    }

    private func didUnlock() async {
        status = try? await backend?.status()
        screen = .unlocked
        await reload()
    }

    func createVault(password: String) async {
        await run {
            try await backend?.createVault(password: password)
            await didUnlock()
        }
    }

    func unlock(password: String) async {
        await run {
            try await backend?.unlock(password: password)
            await didUnlock()
        }
    }

    func unlockWithTouchID() async {
        await run {
            try await backend?.unlockWithTouchID()
            await didUnlock()
        }
    }

    func lock() async {
        await run {
            try await backend?.lock()
            becameLocked()
        }
    }

    // MARK: - Items

    func reload() async {
        await run {
            items = try await backend?.list() ?? []
            if let selection, items.contains(where: { $0.id == selection }) {
                await select(selection)
            } else {
                detail = nil
            }
        }
    }

    func select(_ name: String?) async {
        selection = name
        guard let name else {
            detail = nil
            return
        }
        await run { detail = try await backend?.item(name) }
    }

    func reveal(_ field: String) async -> String? {
        guard let name = detail?.name else { return nil }
        var value: String?
        await run { value = try await backend?.reveal(name, field: field) }
        return value
    }

    func otp() async -> OTPCode? {
        guard let name = detail?.name else { return nil }
        var code: OTPCode?
        await run { code = try await backend?.otp(name) }
        return code
    }

    func copySecret(_ field: String, label: String) async {
        guard let value = await reveal(field) else { return }
        Clipboard.copySecret(value)
        flash("Copied \(label) · clears in \(Int(Clipboard.clearAfter))s")
    }

    func copyOTP() async {
        guard let code = await otp() else { return }
        Clipboard.copySecret(code.code)
        flash("Copied 2FA code")
    }

    func copyPlain(_ value: String, label: String) {
        Clipboard.copy(value)
        flash("Copied \(label)")
    }

    func flash(_ message: String) {
        toast = message
        Task {
            try? await Task.sleep(for: .seconds(2))
            if toast == message { toast = nil }
        }
    }

    func save(_ request: SaveRequest) async -> Bool {
        var ok = false
        await run {
            try await backend?.save(request)
            ok = true
            await reload()
            await select(request.name)
        }
        return ok
    }

    func delete(_ name: String) async {
        await run {
            try await backend?.delete(name)
            selection = nil
            detail = nil
            await reload()
        }
    }

    func generate(length: Int, symbols: Bool) async -> String? {
        var pw: String?
        await run { pw = try await backend?.generate(length: length, symbols: symbols) }
        return pw
    }
}

/// Sample data for snapshots and SwiftUI previews. Nothing here is real.
final class MockBackend: VaultBackend {
    var locked: Bool
    var items: [ItemSummary] = [
        .init(name: "github", kind: .login, username: "octocat", url: "https://github.com", hasOtp: true, updated: 1_792_240_000),
        .init(name: "openai/api-key", kind: .secret, username: nil, url: nil, hasOtp: false, updated: 1_792_200_000),
        .init(name: "stripe/secret", kind: .secret, username: nil, url: nil, hasOtp: false, updated: 1_792_100_000),
        .init(name: "aws/console", kind: .login, username: "me@example.com", url: "https://console.aws.amazon.com", hasOtp: true, updated: 1_792_000_000),
        .init(name: "notes/wifi", kind: .note, username: nil, url: nil, hasOtp: false, updated: 1_791_900_000),
    ]

    /// Snapshots of the lock screen stay locked (Touch ID "cancelled").
    let stayLocked: Bool

    init(locked: Bool) {
        self.locked = locked
        stayLocked = locked
    }

    func status() async throws -> VaultStatus {
        .init(version: "0.7.0", vaultPath: "~/.stash/vault.db", vaultExists: true, locked: locked,
              touchIdAvailable: true, touchIdEnabled: true, needsUpgrade: false)
    }
    func createVault(password: String) async throws {}
    func unlock(password: String) async throws { locked = false }
    func unlockWithTouchID() async throws {
        if stayLocked { throw BackendError(code: -32004, message: "cancelled") }
        locked = false
    }
    func lock() async throws { locked = true }
    func list() async throws -> [ItemSummary] { items }
    func item(_ name: String) async throws -> ItemDetail {
        let summary = items.first { $0.name == name }!
        var fields: [FieldInfo] = []
        switch summary.kind {
        case .login:
            fields = [
                .init(label: "username", kind: .text, value: summary.username),
                .init(label: "password", kind: .concealed, value: nil),
                .init(label: "website", kind: .url, value: summary.url),
            ]
            if summary.hasOtp { fields.append(.init(label: "one-time password", kind: .otp, value: nil)) }
        case .secret:
            fields = [.init(label: "value", kind: .concealed, value: nil)]
        case .note:
            fields = []
        }
        return .init(name: name, kind: summary.kind, fields: fields,
                     hasNotes: summary.kind != .secret, binary: false, created: summary.updated, updated: summary.updated)
    }
    func reveal(_ name: String, field: String) async throws -> String { "correct-horse-battery" }
    func otp(_ name: String) async throws -> OTPCode { .init(code: "482913", remaining: 18, period: 30) }
    func save(_ request: SaveRequest) async throws {}
    func delete(_ name: String) async throws {}
    func generate(length: Int, symbols: Bool) async throws -> String { "q7#Vd!xP2m@Kz9&Lw4$Rt8" }
    func enableTouchID(password: String) async throws {}
}
