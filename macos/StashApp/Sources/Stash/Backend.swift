// The app's only link to the vault: a private `stash app-server` child
// process, spoken to with JSON-RPC over its stdin/stdout. All crypto and
// vault logic lives there, in Rust; this file just moves messages.

import Foundation

struct BackendError: LocalizedError {
    let code: Int
    let message: String

    var errorDescription: String? { message }
    var isLocked: Bool { code == -32001 }
    var isCancelled: Bool { code == -32004 }
    var isWrongPassword: Bool { code == -32003 }
}

/// What the UI needs from a vault. `RPCBackend` is the real one; `MockBackend`
/// serves sample data for snapshots and previews.
protocol VaultBackend: AnyObject {
    func status() async throws -> VaultStatus
    func createVault(password: String) async throws
    func unlock(password: String) async throws
    func unlockWithTouchID() async throws
    func lock() async throws
    func list() async throws -> [ItemSummary]
    func item(_ name: String) async throws -> ItemDetail
    func reveal(_ name: String, field: String) async throws -> String
    func otp(_ name: String) async throws -> OTPCode
    func otpLink(_ name: String) async throws -> OTPLink
    func save(_ request: SaveRequest) async throws
    func delete(_ name: String) async throws
    func generate(length: Int, symbols: Bool) async throws -> String
    func enableTouchID(password: String) async throws
}

final class RPCBackend: VaultBackend, @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let lock = NSLock()
    private var nextID = 0
    private var pending: [Int: CheckedContinuation<Data, Error>] = [:]
    private var buffer = Data()

    init() throws {
        process.executableURL = try Self.stashBinary()
        process.arguments = ["app-server"]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.standardError
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            self?.receive(handle.availableData)
        }
        process.terminationHandler = { [weak self] _ in
            self?.failAll(BackendError(code: -32099, message: "The stash backend stopped."))
        }
        try process.run()
    }

    deinit {
        process.terminate()
    }

    /// The `stash` binary: `Contents/Helpers/stash` in the app bundle (not
    /// `MacOS/`, where it would collide with the app's own `Stash` executable
    /// on case-insensitive disks), otherwise `$STASH_BIN`, `~/.cargo/bin/stash`,
    /// or `$PATH`.
    static func stashBinary() throws -> URL {
        let fm = FileManager.default
        var candidates: [URL] = [
            Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/stash")
        ]
        if let env = ProcessInfo.processInfo.environment["STASH_BIN"] {
            candidates.append(URL(fileURLWithPath: env))
        }
        candidates.append(fm.homeDirectoryForCurrentUser.appendingPathComponent(".cargo/bin/stash"))
        for dir in (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":") {
            candidates.append(URL(fileURLWithPath: String(dir)).appendingPathComponent("stash"))
        }
        // Never pick up the app's own executable, which is also named `Stash`
        // on case-insensitive disks.
        let me = Bundle.main.executableURL?.resolvingSymlinksInPath()
        guard let found = candidates.first(where: {
            fm.isExecutableFile(atPath: $0.path) && $0.resolvingSymlinksInPath() != me
        }) else {
            throw BackendError(code: -32098, message: "Couldn't find the stash command-line tool.")
        }
        return found
    }

    private func receive(_ data: Data) {
        guard !data.isEmpty else { return }
        lock.lock()
        buffer.append(data)
        var lines: [Data] = []
        while let newline = buffer.firstIndex(of: 0x0A) {
            lines.append(buffer.subdata(in: buffer.startIndex..<newline))
            buffer.removeSubrange(buffer.startIndex...newline)
        }
        lock.unlock()
        for line in lines { deliver(line) }
    }

    private func deliver(_ line: Data) {
        guard let message = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let id = message["id"] as? Int else { return }
        lock.lock()
        let continuation = pending.removeValue(forKey: id)
        lock.unlock()
        guard let continuation else { return }
        if let error = message["error"] as? [String: Any] {
            continuation.resume(throwing: BackendError(
                code: error["code"] as? Int ?? -32000,
                message: error["message"] as? String ?? "Unknown error"))
        } else {
            let result = message["result"] ?? [:]
            let data = (try? JSONSerialization.data(withJSONObject: result, options: [.fragmentsAllowed])) ?? Data()
            continuation.resume(returning: data)
        }
    }

    private func failAll(_ error: Error) {
        lock.lock()
        let waiting = pending
        pending.removeAll()
        lock.unlock()
        for (_, c) in waiting { c.resume(throwing: error) }
    }

    private func call(_ method: String, _ params: [String: Any] = [:]) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            nextID += 1
            let id = nextID
            pending[id] = continuation
            lock.unlock()
            let message: [String: Any] = ["jsonrpc": "2.0", "id": id, "method": method, "params": params]
            do {
                var data = try JSONSerialization.data(withJSONObject: message)
                data.append(0x0A)
                try input.fileHandleForWriting.write(contentsOf: data)
            } catch {
                lock.lock()
                let c = pending.removeValue(forKey: id)
                lock.unlock()
                c?.resume(throwing: error)
            }
        }
    }

    private func call<T: Decodable>(_ method: String, _ params: [String: Any] = [:], as: T.Type) async throws -> T {
        let data = try await call(method, params)
        return try JSONDecoder.stash.decode(T.self, from: data)
    }

    func status() async throws -> VaultStatus { try await call("status", as: VaultStatus.self) }
    func createVault(password: String) async throws { _ = try await call("create_vault", ["password": password]) }
    func unlock(password: String) async throws { _ = try await call("unlock", ["method": "password", "password": password]) }
    func unlockWithTouchID() async throws { _ = try await call("unlock", ["method": "touch_id"]) }
    func lock() async throws { _ = try await call("lock") }
    func list() async throws -> [ItemSummary] {
        struct Wrapper: Decodable { let items: [ItemSummary] }
        return try await call("list", as: Wrapper.self).items
    }
    func item(_ name: String) async throws -> ItemDetail { try await call("item", ["name": name], as: ItemDetail.self) }
    func reveal(_ name: String, field: String) async throws -> String {
        struct Wrapper: Decodable { let value: String }
        return try await call("reveal", ["name": name, "field": field], as: Wrapper.self).value
    }
    func otp(_ name: String) async throws -> OTPCode { try await call("otp", ["name": name], as: OTPCode.self) }
    func otpLink(_ name: String) async throws -> OTPLink { try await call("otp_uri", ["name": name], as: OTPLink.self) }
    func save(_ request: SaveRequest) async throws { _ = try await call("save", request.params) }
    func delete(_ name: String) async throws { _ = try await call("delete", ["name": name]) }
    func generate(length: Int, symbols: Bool) async throws -> String {
        struct Wrapper: Decodable { let password: String }
        return try await call("generate", ["length": length, "symbols": symbols], as: Wrapper.self).password
    }
    func enableTouchID(password: String) async throws { _ = try await call("enable_touch_id", ["password": password]) }
}

extension JSONDecoder {
    static let stash: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()
}
