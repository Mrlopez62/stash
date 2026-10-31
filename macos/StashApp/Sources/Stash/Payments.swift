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
    /// What to say under a card number: `text` in full, or `note` beside the
    /// network's logo.
    static func cardStatus(_ number: String) -> (ok: Bool, text: String, brand: String?, note: String?)? {
        let d = digits(number)
        guard d.count >= 4 else { return nil }
        let brand = brand(d)
        let name = brand ?? "Card"
        if d.count < 12 { return (true, name, brand, nil) }
        let ok = luhn(d)
        let note = ok ? "looks right" : "check for a typo"
        return (ok, "\(name) · \(note)", brand, note)
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

/// The card at the top of a card's inspector: brand, last four digits,
/// cardholder, and expiry. Never the full number.
///
/// Clicking it turns it over to the security code, which is fetched only
/// then, and it turns back by itself after 30 seconds (dropping the code).
struct CardFaceView: View {
    let face: CardFace
    let cardholder: String?
    let expiry: String?
    let revealCVV: () async -> String?
    var finish: CardFinish?

    @ViewState private var flipped = PremiumCard.startFlipped
    @ViewState private var cvv: String?
    @ViewState private var flipBack: Task<Void, Never>?

    var body: some View {
        PremiumCard(
            content: CardContent(
                brand: face.brand,
                number: face.brand == "American Express"
                    ? "•••• •••••• •\(face.last4)"
                    : "•••• •••• •••• \(face.last4)",
                cardholder: cardholder,
                expiry: expiry,
                cvv: cvv,
                finish: finish),
            flipped: flipped)
            .frame(maxWidth: .infinity)
            .contentShape(Rectangle())
            .onTapGesture { toggle() }
            .help(flipped ? "Turn back over" : "Turn over to see the security code")
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(flipped
                ? "Security code \(cvv.map { $0.map(String.init).joined(separator: " ") } ?? "hidden")"
                : "\(face.brand) card ending in \(face.last4)")
            .accessibilityAddTraits(.isButton)
            .accessibilityHint(flipped ? "Turns the card back over" : "Shows the security code")
            .accessibilityAction { toggle() }
            .onChange(of: face) { _, _ in reset() }
            .onDisappear { reset() }
    }

    private func toggle() {
        if flipped { reset(); return }
        flipped = true
        Task { @MainActor in
            let code = await revealCVV()
            if flipped { cvv = code }
        }
        flipBack?.cancel()
        flipBack = Task { @MainActor in
            try? await Task.sleep(for: .seconds(30))
            if !Task.isCancelled { reset() }
        }
    }

    private func reset() {
        flipBack?.cancel()
        flipBack = nil
        flipped = false
        cvv = nil
    }
}
