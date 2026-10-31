// Swift side of the Rust vault core (crates/stash-ffi, through
// StashCore.xcframework). The phone opens the same encrypted vault format
// as the Mac, with the same code.

import Foundation
import StashCore

struct VaultError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// One item in the list: no values.
struct PhoneItem: Decodable, Identifiable, Hashable {
    let name: String
    let kind: ItemKind
    let subtitle: String?
    var id: String { name }
    /// "cards/visa" → "visa"
    var title: String { name.split(separator: "/").last.map(String.init) ?? name }
}

/// One item's details: no secret values (reveal them one at a time).
struct PhoneDetail: Decodable {
    let name: String
    let kind: ItemKind
    let subtitle: String?
    let card: CardFace?
    let fields: [FieldInfo]
    let hasNotes: Bool

    func value(_ label: String) -> String? { fields.first { $0.label == label }?.value }
}

/// An open vault. Opened off the main thread (Argon2 takes a moment), then
/// used from one thread at a time: the core isn't thread-safe.
final class VaultCore: @unchecked Sendable {
    private var handle: OpaquePointer?

    private init(_ handle: OpaquePointer) { self.handle = handle }

    deinit {
        if let handle { stash_close(handle) }
    }

    /// Throws unless the file is a current stash vault. Needs no password.
    static func check(path: URL) throws {
        var error: UnsafeMutablePointer<CChar>?
        let ok = path.path.withCString { stash_check_vault($0, &error) }
        if !ok { throw take(error) }
    }

    static func open(path: URL, password: String) throws -> VaultCore {
        var error: UnsafeMutablePointer<CChar>?
        var bytes = Array(password.utf8)
        defer { bytes.withUnsafeMutableBufferPointer { $0.update(repeating: 0) } }
        let handle = path.path.withCString { p in
            stash_open_password(p, bytes, bytes.count, &error)
        }
        guard let handle else { throw take(error) }
        return VaultCore(handle)
    }

    /// With the 64 key bytes saved for Face ID.
    static func open(path: URL, keys: Data) throws -> VaultCore {
        guard keys.count == 64 else { throw VaultError(message: "the saved keys are damaged") }
        var error: UnsafeMutablePointer<CChar>?
        let handle = path.path.withCString { p in
            keys.withUnsafeBytes { stash_open_keys(p, $0.bindMemory(to: UInt8.self).baseAddress, &error) }
        }
        guard let handle else { throw take(error) }
        return VaultCore(handle)
    }

    /// The main and sensitive keys, for Face ID to wrap.
    func copyKeys() -> Data? {
        var out = Data(count: 64)
        let ok = out.withUnsafeMutableBytes { stash_copy_keys(handle, $0.bindMemory(to: UInt8.self).baseAddress) }
        return ok ? out : nil
    }

    func list() throws -> [PhoneItem] {
        var error: UnsafeMutablePointer<CChar>?
        return try decode(stash_list(handle, &error), error)
    }

    func item(_ name: String) throws -> PhoneDetail {
        var error: UnsafeMutablePointer<CChar>?
        let json = name.withCString { stash_item(handle, $0, &error) }
        return try decode(json, error)
    }

    /// One secret value, on demand.
    func reveal(_ name: String, field: String) throws -> String {
        var error: UnsafeMutablePointer<CChar>?
        let value = name.withCString { n in field.withCString { f in stash_reveal(handle, n, f, &error) } }
        guard let value else { throw Self.take(error) }
        defer { stash_string_free(value) }
        return String(cString: value)
    }

    func close() {
        if let handle { stash_close(handle) }
        handle = nil
    }

    private func decode<T: Decodable>(_ json: UnsafeMutablePointer<CChar>?, _ error: UnsafeMutablePointer<CChar>?) throws -> T {
        guard let json else { throw Self.take(error) }
        defer { stash_string_free(json) }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(T.self, from: Data(String(cString: json).utf8))
    }

    private static func take(_ error: UnsafeMutablePointer<CChar>?) -> VaultError {
        guard let error else { return VaultError(message: "something went wrong") }
        defer { stash_string_free(error) }
        return VaultError(message: String(cString: error))
    }
}
