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
    /// The open editor sheet, if any.
    @Published var editor: EditorTarget?

    let backend: VaultBackend?

    init(backend: VaultBackend?) {
        self.backend = backend
    }

    enum Filter: Hashable {
        case all
        case kind(ItemKind)
        case folder(String)

        var title: String {
            switch self {
            case .all: "All Items"
            case .kind(let k): k == .note ? "Secure Notes" : "\(k.title)s"
            case .folder(let f): f
            }
        }
    }

    enum Sort { case name, updated }

    @Published var filter: Filter = .all
    @Published var sort: Sort = .name

    func matches(_ item: ItemSummary, _ filter: Filter) -> Bool {
        switch filter {
        case .all: true
        case .kind(let k): item.kind == k
        case .folder(let f): item.folder?.split(separator: "/").first.map(String.init) == f
        }
    }

    func count(_ filter: Filter) -> Int { items.filter { matches($0, filter) }.count }

    /// Top-level folders, from names like `work/github`.
    var folders: [String] {
        Array(Set(items.compactMap { $0.folder?.split(separator: "/").first.map(String.init) })).sorted()
    }

    var filtered: [ItemSummary] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let shown = items.filter { matches($0, filter) }.filter {
            q.isEmpty
                || $0.name.lowercased().contains(q)
                || ($0.username?.lowercased().contains(q) ?? false)
                || ($0.url?.lowercased().contains(q) ?? false)
        }
        switch sort {
        // By the name shown in the table (the last segment), then by folder.
        case .name: return shown.sorted {
            let order = $0.title.localizedCaseInsensitiveCompare($1.title)
            return order == .orderedSame
                ? ($0.folder ?? "").localizedCaseInsensitiveCompare($1.folder ?? "") == .orderedAscending
                : order == .orderedAscending
        }
        case .updated: return shown.sorted { $0.updated > $1.updated }
        }
    }

    /// In this filter's scope, before searching: for "3 of 12 items".
    var scopeCount: Int { count(filter) }

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

    func otpLink() async -> OTPLink? {
        guard let name = detail?.name else { return nil }
        var link: OTPLink?
        await run { link = try await backend?.otpLink(name) }
        return link
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
    var items: [ItemSummary] = {
        let now = Int(Date().timeIntervalSince1970)
        return [
            .init(name: "github", kind: .login, username: "octocat", url: "https://github.com", hasOtp: true, updated: now - 7_200),
            .init(name: "openai/api-key", kind: .secret, username: nil, url: nil, hasOtp: false, updated: now - 86_400),
            .init(name: "stripe/secret-key", kind: .secret, username: nil, url: nil, hasOtp: false, updated: now - 3 * 86_400),
            .init(name: "stripe/dashboard", kind: .login, username: "billing@acme.dev", url: "https://dashboard.stripe.com", hasOtp: true, updated: now - 5 * 86_400),
            .init(name: "work/aws-console", kind: .login, username: "j.lopez@acme.dev", url: "https://console.aws.amazon.com", hasOtp: true, updated: now - 9 * 86_400),
            .init(name: "work/vercel", kind: .login, username: "joshua", url: "https://vercel.com", hasOtp: false, updated: now - 12 * 86_400),
            .init(name: "work/database-url", kind: .secret, username: nil, url: nil, hasOtp: false, updated: now - 20 * 86_400),
            .init(name: "cloudflare/api-token", kind: .secret, username: nil, url: nil, hasOtp: false, updated: now - 26 * 86_400),
            .init(name: "linear", kind: .login, username: "joshua@acme.dev", url: "https://linear.app", hasOtp: false, updated: now - 40 * 86_400),
            .init(name: "notes/home-wifi", kind: .note, username: nil, url: nil, hasOtp: false, updated: now - 60 * 86_400),
            .init(name: "cards/visa", kind: .card, username: nil, url: nil, hasOtp: false, updated: now - 4 * 86_400,
                  subtitle: "Visa •••• 4242 · 08/27"),
            .init(name: "cards/amex-business", kind: .card, username: nil, url: nil, hasOtp: false, updated: now - 30 * 86_400,
                  subtitle: "American Express •••• 0005 · 11/28"),
            .init(name: "banks/chase-checking", kind: .bank, username: nil, url: nil, hasOtp: false, updated: now - 14 * 86_400,
                  subtitle: "Chase · Checking •••• 6789"),
            .init(name: "notes/recovery-codes", kind: .note, username: nil, url: nil, hasOtp: false, updated: now - 90 * 86_400),
        ]
    }()

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
        case .card:
            fields = [
                .init(label: "cardholder", kind: .text, value: "Joshua Lopez"),
                .init(label: "number", kind: .concealed, value: nil),
                .init(label: "expiry", kind: .text, value: "08/27"),
                .init(label: "cvv", kind: .concealed, value: nil),
                .init(label: "billing zip", kind: .text, value: "78666"),
            ]
        case .bank:
            fields = [
                .init(label: "bank", kind: .text, value: "Chase"),
                .init(label: "account holder", kind: .text, value: "Joshua Lopez"),
                .init(label: "account type", kind: .text, value: "checking"),
                .init(label: "routing number", kind: .text, value: "021000021"),
                .init(label: "account number", kind: .concealed, value: nil),
            ]
        }
        let card = summary.kind == .card
            ? CardFace(brand: summary.subtitle?.components(separatedBy: " •").first ?? "Card",
                       last4: String(summary.subtitle?.split(separator: " ").dropLast(2).last ?? "4242"))
            : nil
        return .init(name: name, kind: summary.kind, subtitle: summary.subtitle, card: card, fields: fields,
                     hasNotes: summary.kind == .login || summary.kind == .note, binary: false,
                     created: summary.updated, updated: summary.updated)
    }
    func reveal(_ name: String, field: String) async throws -> String { "correct-horse-battery" }
    func otp(_ name: String) async throws -> OTPCode { .init(code: "482913", remaining: 18, period: 30) }
    func otpLink(_ name: String) async throws -> OTPLink {
        .init(uri: "otpauth://totp/\(name):octocat?secret=JBSWY3DPEHPK3PXP&issuer=\(name)", issuer: name, account: "octocat")
    }
    func save(_ request: SaveRequest) async throws {}
    func delete(_ name: String) async throws {}
    func generate(length: Int, symbols: Bool) async throws -> String { "q7#Vd!xP2m@Kz9&Lw4$Rt8" }
    func enableTouchID(password: String) async throws {}
}
