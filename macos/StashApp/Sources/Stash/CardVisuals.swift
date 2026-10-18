// The premium payment card: a 3D card that tilts toward the pointer with a
// moving highlight, a one-time foil sheen when it appears, and a flip to its
// back (stripe, signature panel, security code).
//
// Motion follows the system's Reduce Motion setting: with it on, there's no
// tilt or sheen, and flips become cross-fades.

import SwiftUI

/// Everything the card shows. The number arrives already masked or
/// grouped; the card never decides what to reveal.
struct CardContent: Equatable {
    var brand: String?
    var number: String
    var cardholder: String?
    var expiry: String?
    /// The back's security code; nil shows dots.
    var cvv: String?
}

struct PremiumCard: View {
    let content: CardContent
    var flipped = false
    /// Tilt and highlight on hover (off for static uses).
    var interactive = true
    var sheenOnAppear = true
    var maxWidth: CGFloat = 330

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ViewState private var tilt = CGSize.zero
    @ViewState private var pointer: CGPoint?
    @ViewState private var sheen: CGFloat = -0.6
    @ViewState private var size = CGSize(width: 330, height: 208)

    var body: some View {
        ZStack {
            CardFront(content: content, sheen: sheen, pointer: flipped ? nil : pointer)
                .opacity(flipped ? 0 : 1)
                .accessibilityHidden(flipped)
            // Pre-mirrored, so it reads correctly once the card turns over.
            CardBack(content: content)
                .rotation3DEffect(.degrees(reduceMotion ? 0 : 180), axis: (0, 1, 0))
                .opacity(flipped ? 1 : 0)
                .accessibilityHidden(!flipped)
        }
        .aspectRatio(1.586, contentMode: .fit) // ISO/IEC 7810 ID-1, a real card's shape
        .frame(maxWidth: maxWidth)
        .background(GeometryReader { geo in
            Color.clear
                .onAppear { size = geo.size }
                .onChange(of: geo.size) { _, new in size = new }
        })
        .rotation3DEffect(.degrees(reduceMotion ? 0 : (flipped ? 180 : 0)), axis: (0, 1, 0), perspective: 0.45)
        .rotation3DEffect(.degrees(tilt.height), axis: (1, 0, 0), perspective: 0.6)
        .rotation3DEffect(.degrees(tilt.width), axis: (0, 1, 0), perspective: 0.6)
        .shadow(color: .black.opacity(0.10), radius: 3, y: 2)
        .shadow(color: .black.opacity(0.22), radius: 18, x: -tilt.width * 0.8, y: 14 + tilt.height * 0.6)
        .animation(reduceMotion ? .easeInOut(duration: 0.2) : .spring(response: 0.6, dampingFraction: 0.8), value: flipped)
        .onContinuousHover(coordinateSpace: .local) { phase in
            guard interactive && !reduceMotion else { return }
            switch phase {
            case .active(let location):
                let x = (location.x / max(size.width, 1) - 0.5) * 2
                let y = (location.y / max(size.height, 1) - 0.5) * 2
                withAnimation(.interactiveSpring(response: 0.35, dampingFraction: 0.7)) {
                    tilt = CGSize(width: x * 8, height: -y * 6)
                    pointer = location
                }
            case .ended:
                withAnimation(.spring(response: 0.6, dampingFraction: 0.65)) {
                    tilt = .zero
                    pointer = nil
                }
            }
        }
        .onAppear {
            guard sheenOnAppear && !reduceMotion else { return }
            sheen = -0.6
            withAnimation(.easeInOut(duration: 1.4).delay(0.2)) { sheen = 1.6 }
        }
        .accessibilityElement(children: .contain)
    }

    /// `--card-back` for snapshots: inspector cards start turned over.
    nonisolated(unsafe) static var startFlipped = false
}

// MARK: - Faces

/// A subtle hue per network over Vault Ink: enough to tell cards apart at a
/// glance, never loud.
private func brandTint(for brand: String?) -> Color {
    switch brand {
    case "Visa": Color(hex: 0x1F3A8A)
    case "Mastercard": Color(hex: 0x8A3B12)
    case "American Express": Color(hex: 0x0F6B6B)
    case "Discover": Color(hex: 0x8A5A12)
    case "JCB": Color(hex: 0x1F5A3A)
    case "UnionPay": Color(hex: 0x7A1F2A)
    default: Color(hex: 0x3A4250)
    }
}

private struct CardSurface: View {
    let brand: String?

    var body: some View {
        ZStack {
            LinearGradient(colors: [Color(hex: 0x232934), Color.vaultInk],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
            RadialGradient(colors: [brandTint(for: brand).opacity(0.55), .clear],
                           center: .topTrailing, startRadius: 4, endRadius: 260)
                .animation(.easeInOut(duration: 0.5), value: brand)
            Grain().opacity(0.07)
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(
                    LinearGradient(colors: [.white.opacity(0.22), .white.opacity(0.04)],
                                   startPoint: .topLeading, endPoint: .bottomTrailing),
                    lineWidth: 1))
    }
}

private struct CardFront: View {
    let content: CardContent
    let sheen: CGFloat
    let pointer: CGPoint?

    var body: some View {
        GeometryReader { geo in
            ZStack {
                CardSurface(brand: content.brand)
                VStack(alignment: .leading, spacing: 0) {
                    HStack(alignment: .top) {
                        Chip()
                        Image(systemName: "wave.3.right")
                            .font(.system(size: 15, weight: .medium))
                            .foregroundStyle(Color.plaintext.opacity(0.7))
                            .padding(.leading, 6)
                            .padding(.top, 5)
                        Spacer()
                        Text(content.brand ?? "")
                            .font(.plex(15, weight: .bold))
                            .italic(content.brand == "Visa")
                            .foregroundStyle(Color.plaintext)
                            .contentTransition(.opacity)
                            .animation(.easeInOut(duration: 0.3), value: content.brand)
                    }
                    Spacer()
                    Text(content.number)
                        .font(.mono(geo.size.height * 0.088, weight: .semibold))
                        .foregroundStyle(Color.plaintext)
                        .tracking(0.8)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .contentTransition(.numericText())
                        .animation(.snappy(duration: 0.25), value: content.number)
                        .shadow(color: .black.opacity(0.35), radius: 0.5, y: 1)
                    Spacer().frame(height: geo.size.height * 0.08)
                    HStack(alignment: .bottom) {
                        caption("CARDHOLDER", content.cardholder?.uppercased() ?? "YOUR NAME", mono: false)
                        Spacer()
                        caption("EXPIRES", content.expiry ?? "MM/YY", mono: true, trailing: true)
                    }
                }
                .padding(geo.size.height * 0.1)
                // A soft light where the pointer is, as if under a lamp.
                if let pointer {
                    RadialGradient(colors: [.white.opacity(0.16), .clear],
                                   center: UnitPoint(x: pointer.x / geo.size.width, y: pointer.y / geo.size.height),
                                   startRadius: 2, endRadius: geo.size.width * 0.6)
                        .blendMode(.plusLighter)
                        .allowsHitTesting(false)
                }
                // The one-time foil sheen.
                LinearGradient(colors: [.clear, .white.opacity(0.18), .clear],
                               startPoint: .leading, endPoint: .trailing)
                    .frame(width: geo.size.width * 0.35)
                    .rotationEffect(.degrees(20))
                    .offset(x: sheen * geo.size.width)
                    .blendMode(.plusLighter)
                    .allowsHitTesting(false)
            }
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        }
    }

    private func caption(_ label: String, _ value: String, mono: Bool, trailing: Bool = false) -> some View {
        VStack(alignment: trailing ? .trailing : .leading, spacing: 2) {
            Text(label).font(.plex(8.5, weight: .semibold)).tracking(1.1).foregroundStyle(Color.plaintext.opacity(0.55))
            Text(value)
                .font(mono ? .mono(12.5, weight: .medium) : .plex(12.5, weight: .medium))
                .foregroundStyle(Color.plaintext)
                .lineLimit(1)
                .contentTransition(.opacity)
                .animation(.easeInOut(duration: 0.2), value: value)
        }
    }
}

private struct CardBack: View {
    let content: CardContent

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .topLeading) {
                CardSurface(brand: content.brand)
                VStack(alignment: .leading, spacing: 0) {
                    Rectangle()
                        .fill(LinearGradient(colors: [Color(hex: 0x050608), Color(hex: 0x15181E)],
                                             startPoint: .top, endPoint: .bottom))
                        .frame(height: geo.size.height * 0.2)
                        .padding(.top, geo.size.height * 0.11)
                    HStack(spacing: 10) {
                        // The signature panel, with the code at its end.
                        ZStack(alignment: .trailing) {
                            RoundedRectangle(cornerRadius: 3, style: .continuous)
                                .fill(Color.paper)
                                .overlay(
                                    Stripes()
                                        .stroke(Color(hex: 0xD9D4C7), lineWidth: 1)
                                        .clipShape(RoundedRectangle(cornerRadius: 3, style: .continuous)))
                            Text(content.cvv ?? "•••")
                                .font(.mono(14, weight: .bold))
                                .italic()
                                .foregroundStyle(Color.vaultInk)
                                .padding(.horizontal, 10)
                                .contentTransition(.numericText())
                                .animation(.snappy, value: content.cvv)
                        }
                        .frame(height: geo.size.height * 0.17)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("SECURITY").font(.plex(7.5, weight: .semibold)).tracking(1)
                            Text("CODE").font(.plex(7.5, weight: .semibold)).tracking(1)
                        }
                        .foregroundStyle(Color.plaintext.opacity(0.55))
                    }
                    .padding(.horizontal, geo.size.height * 0.1)
                    .padding(.top, geo.size.height * 0.1)
                    Spacer()
                    HStack {
                        Text(content.brand ?? "")
                            .font(.plex(12, weight: .bold))
                            .foregroundStyle(Color.plaintext.opacity(0.8))
                        Spacer()
                        Text("stash")
                            .font(.mono(11, weight: .heavy))
                            .tracking(-0.5)
                            .foregroundStyle(Color.plaintext.opacity(0.45))
                    }
                    .padding(geo.size.height * 0.1)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        }
    }
}

// MARK: - Details

/// An EMV chip with its contact pads.
private struct Chip: View {
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .fill(LinearGradient(colors: [Color(hex: 0xF9DE9C), Color.keyholeAmber, Color(hex: 0xC98A1E)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
            ChipContacts()
                .stroke(Color(hex: 0x8A5A12).opacity(0.55), lineWidth: 0.8)
        }
        .frame(width: 38, height: 29)
        .overlay(RoundedRectangle(cornerRadius: 5, style: .continuous).strokeBorder(Color.black.opacity(0.18), lineWidth: 0.5))
    }
}

private struct ChipContacts: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        let midY = r.midY
        p.move(to: CGPoint(x: r.minX, y: midY))
        p.addLine(to: CGPoint(x: r.width * 0.32, y: midY))
        p.move(to: CGPoint(x: r.width * 0.68, y: midY))
        p.addLine(to: CGPoint(x: r.maxX, y: midY))
        for y in [r.height * 0.3, r.height * 0.7] {
            p.move(to: CGPoint(x: r.minX, y: y))
            p.addLine(to: CGPoint(x: r.width * 0.32, y: y))
            p.move(to: CGPoint(x: r.width * 0.68, y: y))
            p.addLine(to: CGPoint(x: r.maxX, y: y))
        }
        p.addRoundedRect(in: CGRect(x: r.width * 0.32, y: r.height * 0.2, width: r.width * 0.36, height: r.height * 0.6),
                         cornerSize: CGSize(width: 3, height: 3))
        return p
    }
}

private struct Stripes: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        var x: CGFloat = -r.height
        while x < r.width {
            p.move(to: CGPoint(x: x, y: r.maxY))
            p.addLine(to: CGPoint(x: x + r.height, y: r.minY))
            x += 6
        }
        return p
    }
}

/// Fine static grain, like printed card stock. Seeded, so it never shimmers.
private struct Grain: View {
    var body: some View {
        Canvas { context, size in
            var seed: UInt64 = 0x5EED
            func next() -> CGFloat {
                seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                return CGFloat(seed >> 33) / CGFloat(1 << 31)
            }
            for _ in 0..<Int(size.width * size.height / 28) {
                let rect = CGRect(x: next() * size.width, y: next() * size.height, width: 1, height: 1)
                context.fill(Path(rect), with: .color(next() > 0.5 ? .white : .black))
            }
        }
        .allowsHitTesting(false)
    }
}

// MARK: - Number formatting

enum CardNumberDisplay {
    /// "4242 4242 4242 4242", or 4-6-5 for American Express.
    static func grouped(_ digits: String) -> String {
        let groups = digits.count == 15 || digits.hasPrefix("34") || digits.hasPrefix("37") ? [4, 6, 5] : [4, 4, 4, 4, 4]
        var out: [String] = []
        var rest = Substring(digits)
        for g in groups where !rest.isEmpty {
            out.append(String(rest.prefix(g)))
            rest = rest.dropFirst(g)
        }
        if !rest.isEmpty { out.append(String(rest)) }
        return out.joined(separator: " ")
    }

    /// What the editor's live card shows: typed digits masked except the
    /// last four (unless the field is showing them), padded to a full card.
    static func preview(_ typed: String, reveal: Bool) -> String {
        let digits = PaymentHints.digits(typed)
        let amex = digits.hasPrefix("34") || digits.hasPrefix("37")
        let total = amex ? 15 : 16
        let shown = digits.enumerated().map { i, c in
            reveal || i >= digits.count - 4 ? c : Character("•")
        }
        let padded = String(shown) + String(repeating: "•", count: max(0, total - digits.count))
        return grouped(padded)
    }
}
