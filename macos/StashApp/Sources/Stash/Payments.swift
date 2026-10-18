// Payment cards and bank accounts in the app: live hints while typing, and
// the card face in the inspector. The backend (stash-core/src/payment.rs)
// is the authority and re-checks everything on save; these checks only let
// the editor flag a typo before you hit Save.

import SwiftUI

enum PaymentHints {
    static func digits(_ s: String) -> String { s.filter(\.isNumber) }

    static func brand(_ number: String) -> String? {
        let d = digits(number)
        func p(_ n: Int) -> Int? { d.count >= n ? Int(d.prefix(n)) : nil }
        if d.hasPrefix("4") { return "Visa" }
        if let two = p(2), two == 34 || two == 37 { return "American Express" }
        if let two = p(2), (51...55).contains(two) { return "Mastercard" }
        if let four = p(4), (2221...2720).contains(four) { return "Mastercard" }
        if let four = p(4), four == 6011 { return "Discover" }
        if let three = p(3), (644...649).contains(three) { return "Discover" }
        if let two = p(2), two == 65 { return "Discover" }
        if let four = p(4), (3528...3589).contains(four) { return "JCB" }
        if let two = p(2), [36, 38, 39].contains(two) { return "Diners Club" }
        if let three = p(3), (300...305).contains(three) { return "Diners Club" }
        if let two = p(2), two == 62 { return "UnionPay" }
        return nil
    }

    static func luhn(_ number: String) -> Bool {
        let d = digits(number).compactMap(\.wholeNumberValue)
        guard d.count >= 12 else { return false }
        let sum = d.reversed().enumerated().reduce(0) { acc, pair in
            let (i, n) = pair
            let v = i % 2 == 1 ? (n * 2 > 9 ? n * 2 - 9 : n * 2) : n
            return acc + v
        }
        return sum % 10 == 0
    }

    /// A short status for the number being typed.
    static func cardStatus(_ number: String) -> (ok: Bool, text: String)? {
        let d = digits(number)
        guard d.count >= 4 else { return nil }
        let name = brand(d) ?? "Card"
        if d.count < 12 { return (true, name) }
        return luhn(d) ? (true, "\(name) · looks right") : (false, "\(name) · check for a typo")
    }

    static func routingOK(_ routing: String) -> Bool {
        let d = digits(routing).compactMap(\.wholeNumberValue)
        guard d.count == 9 else { return false }
        let sum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
        return sum % 10 == 0
    }

    /// "MM/YY" from what's typed: "827" stays as is, "0827" → "08/27".
    static func formatExpiry(_ s: String) -> String {
        let d = digits(s).prefix(4)
        return d.count > 2 ? "\(d.prefix(2))/\(d.dropFirst(2))" : String(d)
    }
}

/// The card face at the top of a card's inspector: brand, last four digits,
/// cardholder, and expiry. Never the full number.
struct CardFaceView: View {
    let face: CardFace
    let cardholder: String?
    let expiry: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .fill(LinearGradient(colors: [Color(hex: 0xF7D58A), Color.keyholeAmber],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 34, height: 26)
                    .overlay(
                        RoundedRectangle(cornerRadius: 4, style: .continuous)
                            .strokeBorder(Color.black.opacity(0.15), lineWidth: 0.5))
                Spacer()
                Text(face.brand)
                    .font(.plex(14, weight: .bold))
                    .foregroundStyle(Color.plaintext)
            }
            Spacer()
            Text("••••  ••••  ••••  \(face.last4)")
                .font(.mono(17, weight: .semibold))
                .foregroundStyle(Color.plaintext)
                .tracking(1)
            Spacer().frame(height: 14)
            HStack(alignment: .bottom) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("CARDHOLDER").font(.plex(8.5, weight: .semibold)).tracking(1).foregroundStyle(Color.plaintext.opacity(0.55))
                    Text(cardholder ?? "—").font(.plex(12.5, weight: .medium)).foregroundStyle(Color.plaintext).lineLimit(1)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text("EXPIRES").font(.plex(8.5, weight: .semibold)).tracking(1).foregroundStyle(Color.plaintext.opacity(0.55))
                    Text(expiry ?? "—").font(.mono(12.5, weight: .medium)).foregroundStyle(Color.plaintext)
                }
            }
        }
        .padding(18)
        .frame(height: 176)
        .background(
            LinearGradient(colors: [Color(hex: 0x1D222B), Color.vaultInk],
                           startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.white.opacity(0.08)))
        .shadow(color: .black.opacity(0.18), radius: 14, y: 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(face.brand) card ending in \(face.last4)")
    }
}
