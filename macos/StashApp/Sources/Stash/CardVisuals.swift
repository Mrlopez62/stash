// The premium payment card: a 3D card that tilts toward the pointer with a
// moving highlight, a one-time foil sheen when it appears, and a flip to its
// back (stripe, signature panel, security code).
//
// Motion follows the system's Reduce Motion setting: with it on, there's no
// tilt or sheen, and flips become cross-fades.

import SwiftUI
#if os(iOS)
import CoreMotion
#endif

/// Everything the card shows. The number arrives already masked or
/// grouped; the card never decides what to reveal.
struct CardContent: Equatable {
    var brand: String?
    var number: String
    var cardholder: String?
    var expiry: String?
    /// The back's security code; nil shows dots.
    var cvv: String?
    /// The chosen color; nil lets the card's network pick.
    var finish: CardFinish?
}

/// The colors a card can be. Dark enough that white print always reads. The
/// raw values are what the vault stores (crates/stash-ffi, CARD_COLORS).
enum CardFinish: String, CaseIterable, Identifiable {
    case graphite, midnight, forest, plum, oxblood, copper, titanium
    var id: Self { self }

    var title: String { rawValue.capitalized }

    var top: Color {
        switch self {
        case .graphite: Color(hex: 0x3A3D42)
        case .midnight: Color(hex: 0x1B2A4E)
        case .forest: Color(hex: 0x1F3D33)
        case .plum: Color(hex: 0x3F2248)
        case .oxblood: Color(hex: 0x4A1A1E)
        case .copper: Color(hex: 0x5A3620)
        case .titanium: Color(hex: 0x6A6C70)
        }
    }

    var bottom: Color {
        switch self {
        case .graphite: Color(hex: 0x17181B)
        case .midnight: Color(hex: 0x0A1022)
        case .forest: Color(hex: 0x0A1714)
        case .plum: Color(hex: 0x160B1B)
        case .oxblood: Color(hex: 0x1A080A)
        case .copper: Color(hex: 0x1E120B)
        case .titanium: Color(hex: 0x2C2E31)
        }
    }

    var glow: Color {
        switch self {
        case .graphite: Color(hex: 0x6B7078)
        case .midnight: Color(hex: 0x3A5BA8)
        case .forest: Color(hex: 0x3E7D66)
        case .plum: Color(hex: 0x8A4A9A)
        case .oxblood: Color(hex: 0xA33A40)
        case .copper: Color(hex: 0xC07A45)
        case .titanium: Color(hex: 0xB8BCC2)
        }
    }
}

/// Where the light falls on a card (0...1 across it) and how strongly.
/// Strength 0 is a card at rest, with no shine at all.
struct CardLight: Equatable {
    var x: CGFloat = 0.5
    var y: CGFloat = 0.5
    var strength: CGFloat = 0
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
    @ViewState private var light = CardLight()
    @ViewState private var sheen: CGFloat = -0.6
    @ViewState private var size = CGSize(width: 330, height: 208)

    var body: some View {
        ZStack {
            CardFront(content: content, sheen: sheen, light: flipped ? CardLight() : light)
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
                    light = CardLight(x: location.x / max(size.width, 1), y: location.y / max(size.height, 1), strength: 0.8)
                }
            case .ended:
                withAnimation(.spring(response: 0.6, dampingFraction: 0.65)) {
                    tilt = .zero
                    light.strength = 0
                }
            }
        }
        #if os(iOS)
        .task(id: reduceMotion) {
            guard interactive && !reduceMotion else { return }
            for await lean in CardMotion.leans() { reflect(lean) }
        }
        #endif
        #if os(macOS)
        .onAppear {
            guard sheenOnAppear && !reduceMotion else { return }
            sheen = -0.6
            withAnimation(.easeInOut(duration: 1.4).delay(0.2)) { sheen = 1.6 }
        }
        #endif
        .accessibilityElement(children: .contain)
    }

    #if os(iOS)
    /// Light stays put in the room as the phone moves, so the reflection
    /// slides against the lean, and the card leans back a little to meet it.
    /// Held still, the lean settles to nothing and the shine goes out.
    private func reflect(_ lean: CGPoint) {
        let t = max(0, min(1, (hypot(lean.x, lean.y) - 0.02) / 0.38))
        light = CardLight(x: 0.5 - lean.x * 0.65, y: 0.5 + lean.y * 0.65, strength: t * t * (3 - 2 * t))
        tilt = CGSize(width: -lean.x * 5, height: -lean.y * 4)
    }
    #endif

    /// `--card-back` for snapshots: inspector cards start turned over.
    nonisolated(unsafe) static var startFlipped = false
}

#if os(iOS)
/// How far the phone has leaned from the way you're holding it.
enum CardMotion {
    /// Each lean is -1...1 on both axes: +x is the right edge going down, +y
    /// the top edge going away. Whatever angle you settle at soon becomes the
    /// new rest, so a phone held still reads as no lean. Ends (and the sensor
    /// stops) when the task reading it does.
    static func leans() -> AsyncStream<CGPoint> {
        AsyncStream { continuation in
            #if DEBUG
            // Simulator checks only (never in release builds).
            if let fixed = ProcessInfo.processInfo.environment["STASH_SIM_TILT"]?.split(separator: ",").compactMap({ Double($0) }),
               fixed.count == 2 {
                continuation.yield(CGPoint(x: fixed[0], y: fixed[1]))
                return
            }
            #endif
            let manager = CMMotionManager()
            guard manager.isDeviceMotionAvailable else {
                continuation.finish()
                return
            }
            let range = 0.45 // of gravity, for a full lean: about 27°
            let settle = 0.006 // per reading: about 3 seconds at 60 a second
            let smooth = 0.3 // per reading, to take out hand tremor
            var rest: (x: Double, y: Double)?
            var eased = CGPoint.zero
            manager.deviceMotionUpdateInterval = 1.0 / 60
            manager.startDeviceMotionUpdates(to: .main) { motion, _ in
                guard let gravity = motion?.gravity else { return }
                var held = rest ?? (gravity.x, gravity.y)
                let leanX = max(-1, min(1, (gravity.x - held.x) / range))
                let leanY = max(-1, min(1, (gravity.y - held.y) / range))
                eased.x += (leanX - eased.x) * smooth
                eased.y += (leanY - eased.y) * smooth
                held.x += (gravity.x - held.x) * settle
                held.y += (gravity.y - held.y) * settle
                rest = held
                continuation.yield(eased)
            }
            continuation.onTermination = { _ in manager.stopDeviceMotionUpdates() }
        }
    }
}
#endif

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
    var finish: CardFinish?

    var body: some View {
        ZStack {
            LinearGradient(colors: [finish?.top ?? Color(hex: 0x232934), finish?.bottom ?? Color.vaultInk],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
                .animation(.easeInOut(duration: 0.4), value: finish)
            RadialGradient(colors: [(finish?.glow ?? brandTint(for: brand)).opacity(0.55), .clear],
                           center: .topTrailing, startRadius: 4, endRadius: 260)
                .animation(.easeInOut(duration: 0.5), value: brand)
                .animation(.easeInOut(duration: 0.4), value: finish)
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
    let light: CardLight

    var body: some View {
        GeometryReader { geo in
            ZStack {
                CardSurface(brand: content.brand, finish: content.finish)
                VStack(alignment: .leading, spacing: 0) {
                    HStack(alignment: .top) {
                        Chip()
                        Image(systemName: "wave.3.right")
                            .font(.system(size: 15, weight: .medium))
                            .foregroundStyle(Color.plaintext.opacity(0.7))
                            .padding(.leading, 6)
                            .padding(.top, 5)
                        Spacer()
                        Group {
                            if let brand = content.brand, CardNetworkLogo.has(brand) {
                                CardNetworkLogo(brand: brand, height: brand == "Visa" ? 17 : 30, onCard: true)
                                    .transition(.opacity)
                            } else {
                                Text(content.brand ?? "")
                                    .font(.plex(15, weight: .bold))
                                    .foregroundStyle(Color.plaintext)
                                    .contentTransition(.opacity)
                            }
                        }
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
                if light.strength > 0.001 {
                    CardShine(light: light, size: geo.size)
                        .allowsHitTesting(false)
                }
                #if os(macOS)
                // The one-time foil sheen.
                LinearGradient(colors: [.clear, .white.opacity(0.18), .clear],
                               startPoint: .leading, endPoint: .trailing)
                    .frame(width: geo.size.width * 0.35)
                    // Longer than the card, so its ends never show once it's angled.
                    .scaleEffect(y: 2.5)
                    .rotationEffect(.degrees(20))
                    .offset(x: sheen * geo.size.width)
                    .blendMode(.plusLighter)
                    .allowsHitTesting(false)
                #endif
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
                CardSurface(brand: content.brand, finish: content.finish)
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
                        if let brand = content.brand, CardNetworkLogo.has(brand) {
                            CardNetworkLogo(brand: brand, height: brand == "Visa" ? 11 : 20, onCard: true)
                        } else {
                            Text(content.brand ?? "")
                                .font(.plex(12, weight: .bold))
                                .foregroundStyle(Color.plaintext.opacity(0.8))
                        }
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

// MARK: - Shine

/// Light on a real card, in layers that all add to what's beneath them: a soft
/// bloom, the bead-blasted surface sparkling inside it, a long feathered streak
/// of reflection, a faint prism that moves faster than the streak (the way
/// colors separate on metal), and the card's edge catching the light on the
/// side it comes from. Every layer has soft ends, so none shows a shape.
private struct CardShine: View {
    let light: CardLight
    let size: CGSize

    var body: some View {
        let center = UnitPoint(x: light.x, y: light.y)
        ZStack {
            // The bloom: bright only at its heart, with a long, gentle falloff.
            RadialGradient(stops: [
                .init(color: .white.opacity(0.2), location: 0),
                .init(color: .white.opacity(0.09), location: 0.22),
                .init(color: .white.opacity(0.03), location: 0.55),
                .init(color: .clear, location: 1),
            ], center: center, startRadius: 0, endRadius: size.width * 0.85)
                .blendMode(.plusLighter)

            // The surface's grain, catching the light only near the bloom.
            Grain()
                .opacity(0.1)
                .mask(RadialGradient(colors: [.white, .clear], center: center, startRadius: 0, endRadius: size.width * 0.42))
                .blendMode(.plusLighter)

            streak(colors: [
                .init(color: .clear, location: 0),
                .init(color: .white.opacity(0.025), location: 0.3),
                .init(color: .white.opacity(0.09), location: 0.42),
                .init(color: .white.opacity(0.22), location: 0.5),
                .init(color: .white.opacity(0.09), location: 0.58),
                .init(color: .white.opacity(0.025), location: 0.7),
                .init(color: .clear, location: 1),
            ], width: size.width * 1.1, travel: 1.5)

            // The prism, pale and low, just past the streak.
            streak(colors: [
                .init(color: .clear, location: 0),
                .init(color: Color(hex: 0xF9C6D8).opacity(0.10), location: 0.25),
                .init(color: Color(hex: 0xC9C2FF).opacity(0.13), location: 0.4),
                .init(color: Color(hex: 0xB8E6FF).opacity(0.13), location: 0.52),
                .init(color: Color(hex: 0xC4F5DE).opacity(0.10), location: 0.64),
                .init(color: Color(hex: 0xFFE9B8).opacity(0.08), location: 0.76),
                .init(color: .clear, location: 1),
            ], width: size.width * 1.5, travel: 2.1)

            // The edge, brightest on the side the light is on.
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(
                    AngularGradient(stops: [
                        .init(color: .white.opacity(0.75), location: 0),
                        .init(color: .clear, location: 0.2),
                        .init(color: .clear, location: 0.8),
                        .init(color: .white.opacity(0.75), location: 1),
                    ], center: .center, angle: .radians(atan2(light.y - 0.5, light.x - 0.5))),
                    lineWidth: 1.2)
                .blendMode(.plusLighter)
        }
        .opacity(light.strength)
    }

    /// A band across the card at a slant, longer than the card so its ends
    /// never show, sliding with the light. `.overlay` keeps it out of layout.
    private func streak(colors: [Gradient.Stop], width: CGFloat, travel: CGFloat) -> some View {
        Color.clear.overlay {
            LinearGradient(stops: colors, startPoint: .leading, endPoint: .trailing)
                .frame(width: width, height: size.width * 2.4)
                .rotationEffect(.degrees(22))
                .offset(x: (light.x - 0.5) * size.width * travel,
                        y: (light.y - 0.5) * size.height * 0.5)
                .blendMode(.plusLighter)
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
        return split(digits, groups)
    }

    /// A number as it's typed: in fours (4-6-5 for American Express). Goes by
    /// the first digits alone, so groups don't jump around at the 15th digit.
    static func typed(_ text: String) -> String {
        let digits = String(PaymentHints.digits(text).prefix(19))
        return split(digits, digits.hasPrefix("34") || digits.hasPrefix("37") ? [4, 6, 5] : [4, 4, 4, 4, 4])
    }

    private static func split(_ digits: String, _ groups: [Int]) -> String {
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
