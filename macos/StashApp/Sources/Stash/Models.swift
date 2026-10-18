import Foundation

enum ItemKind: String, Codable, CaseIterable, Identifiable {
    case login, secret, note, card, bank, ssh
    var id: String { rawValue }

    var title: String {
        switch self {
        case .login: "Login"
        case .secret: "Secret"
        case .note: "Secure Note"
        case .card: "Payment Card"
        case .bank: "Bank Account"
        case .ssh: "SSH Key"
        }
    }

    var isPayment: Bool { self == .card || self == .bank }

    var symbol: String {
        switch self {
        case .login: "person.badge.key"
        case .secret: "key.horizontal"
        case .note: "note.text"
        case .card: "creditcard"
        case .bank: "building.columns"
        case .ssh: "terminal"
        }
    }
}

enum FieldKind: String, Codable {
    case text, concealed, url, email, otp
    var isSensitive: Bool { self == .concealed || self == .otp }
}

struct VaultStatus: Decodable {
    var version: String
    var vaultPath: String
    var vaultExists: Bool
    var locked: Bool
    var touchIdAvailable: Bool
    var touchIdEnabled: Bool
    var needsUpgrade: Bool
}

struct ItemSummary: Decodable, Identifiable, Hashable {
    var name: String
    var kind: ItemKind
    var username: String?
    var url: String?
    var hasOtp: Bool
    var updated: Int
    /// Cards and bank accounts: "Visa •••• 4242 · 08/27".
    var subtitle: String? = nil
    var id: String { name }

    /// The last path segment, for display ("work/github" → "github").
    var title: String { name.split(separator: "/").last.map(String.init) ?? name }
    var folder: String? {
        let parts = name.split(separator: "/")
        return parts.count > 1 ? parts.dropLast().joined(separator: "/") : nil
    }
}

struct FieldInfo: Decodable, Identifiable, Hashable {
    var label: String
    var kind: FieldKind
    /// Present only for non-sensitive fields.
    var value: String?
    var id: String { label }
}

/// What's needed to draw a card face: never the full number.
struct CardFace: Decodable, Hashable {
    var brand: String
    var last4: String
}

struct ItemDetail: Decodable {
    var name: String
    var kind: ItemKind
    var subtitle: String?
    var card: CardFace?
    var fields: [FieldInfo]
    var hasNotes: Bool
    var binary: Bool
    var created: Int
    var updated: Int
}

/// An otpauth:// link for an authenticator app. Shown only as a QR code.
struct OTPLink: Decodable {
    var uri: String
    var issuer: String
    var account: String
}

struct OTPCode: Decodable {
    var code: String
    var remaining: Int
    var period: Int
}

/// A field to save. `value == nil` keeps the stored value, so editing never
/// requires loading secrets into the app.
struct SaveField {
    var label: String
    var kind: FieldKind
    var value: String?
}

struct SaveRequest {
    var name: String
    var originalName: String?
    var kind: ItemKind
    var fields: [SaveField]
    /// `nil` keeps the stored notes.
    var notes: String?

    var params: [String: Any] {
        var p: [String: Any] = [
            "name": name,
            "kind": kind.rawValue,
            "fields": fields.map { f -> [String: Any] in
                var d: [String: Any] = ["label": f.label, "kind": f.kind.rawValue]
                if let v = f.value { d["value"] = v }
                return d
            },
        ]
        if let originalName { p["original_name"] = originalName }
        if let notes { p["notes"] = notes }
        return p
    }
}
