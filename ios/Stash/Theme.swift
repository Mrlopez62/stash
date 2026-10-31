// The stash design system on iOS: the same colors and type as the Mac app
// (macos/StashApp/Sources/Stash/Theme.swift), built on UIKit instead of
// AppKit, so the shared card views look the same on the phone.

import SwiftUI
import UIKit

extension UIColor {
    convenience init(hex: UInt32) {
        self.init(
            red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(uiColor: UIColor(hex: hex))
    }

    /// A color that follows the system appearance.
    init(light: UInt32, dark: UInt32) {
        self.init(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark ? UIColor(hex: dark) : UIColor(hex: light)
        })
    }

    static let keyholeAmber = Color(hex: 0xF5B544)
    static let vaultInk = Color(hex: 0x0E1116)
    static let enclave = Color(hex: 0x171B22)
    static let plaintext = Color(hex: 0xE8EAED)
    static let paper = Color(hex: 0xF4F2EC)

    static let canvas = Color(light: 0xF4F2EC, dark: 0x0B0D11)
    static let surface = Color(light: 0xFFFFFF, dark: 0x171B22)
    static let surfaceRaised = Color(light: 0xFAF9F6, dark: 0x1D222B)
    static let line = Color(light: 0xE4E0D6, dark: 0x2A303B)
    static let ink = Color(light: 0x0E1116, dark: 0xE8EAED)
    static let inkSecondary = Color(light: 0x4A5160, dark: 0xB9C0CC)
    static let inkTertiary = Color(light: 0x5F6877, dark: 0x8A93A3)
    static let amberTint = Color(light: 0xFCEFD4, dark: 0x3A2F17)
    static let amberText = Color(light: 0x8A5A00, dark: 0xF5B544)
    static let danger = Color(light: 0xC2410C, dark: 0xFF8A65)
    static let success = Color(light: 0x1F8A5B, dark: 0x7DD3A8)
}

extension Font {
    /// Body text: IBM Plex Sans (bundled, listed in Info.plist).
    static func plex(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        UIFont(name: "IBM Plex Sans", size: size) != nil
            ? .custom("IBM Plex Sans", size: size).weight(weight)
            : .system(size: size, weight: weight)
    }

    /// Names, values, and code: JetBrains Mono.
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        UIFont(name: "JetBrains Mono", size: size) != nil
            ? .custom("JetBrains Mono", size: size).weight(weight)
            : .system(size: size, weight: weight, design: .monospaced)
    }
}

/// The wordmark (docs/brand): lowercase JetBrains Mono ExtraBold with tight
/// tracking, and the amber dot.
struct Wordmark: View {
    var size: CGFloat = 30

    var body: some View {
        // A monospaced "." sits mid-cell: pull it in to the "h", as in the logo.
        // One Text, so its width is measured correctly.
        (Text("stas").foregroundStyle(Color.ink).tracking(-size * 0.05)
            + Text("h").foregroundStyle(Color.ink).tracking(-size * 0.25)
            + Text(".").foregroundStyle(Color.keyholeAmber))
            .font(.mono(size, weight: .heavy))
            .lineLimit(1)
            .fixedSize()
            .accessibilityLabel("stash")
    }
}

/// The stash mark (docs/brand/mark.svg): an ink tile with the terminal
/// prompt and the keyhole, drawn from the same 64×64 geometry.
struct StashMark: View {
    var size: CGFloat = 64

    var body: some View {
        Canvas { ctx, canvas in
            let s = canvas.width / 64
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * s, y: y * s) }
            ctx.fill(Path(roundedRect: CGRect(origin: .zero, size: canvas), cornerRadius: 14.5 * s, style: .continuous),
                     with: .color(.vaultInk))
            // The hairline that keeps the tile visible on dark backgrounds.
            ctx.stroke(Path(roundedRect: CGRect(x: 0.75 * s, y: 0.75 * s, width: 62.5 * s, height: 62.5 * s),
                            cornerRadius: 13.75 * s, style: .continuous),
                       with: .color(Color(hex: 0x2A303B)), lineWidth: 1.5 * s)
            ctx.stroke(StashMarkPrompt().path(in: CGRect(origin: .zero, size: canvas)), with: .color(.plaintext),
                       style: StrokeStyle(lineWidth: 6.5 * s, lineCap: .round, lineJoin: .round))
            ctx.fill(StashMarkKeyhole().path(in: CGRect(origin: .zero, size: canvas)), with: .color(.keyholeAmber))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The mark's prompt (a stroke), on its 64×64 grid.
struct StashMarkPrompt: Shape {
    func path(in r: CGRect) -> Path {
        let s = r.width / 64
        var p = Path()
        p.move(to: CGPoint(x: 14 * s, y: 20 * s))
        p.addLine(to: CGPoint(x: 26 * s, y: 32 * s))
        p.addLine(to: CGPoint(x: 14 * s, y: 44 * s))
        return p
    }
}

/// The mark's keyhole, on its 64×64 grid. It turns about the center of its
/// round head, at `anchor`.
struct StashMarkKeyhole: Shape {
    static let anchor = UnitPoint(x: 43.0 / 64, y: 27.0 / 64)

    func path(in r: CGRect) -> Path {
        let s = r.width / 64
        func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * s, y: y * s) }
        var p = Path(ellipseIn: CGRect(x: 36 * s, y: 20 * s, width: 14 * s, height: 14 * s))
        p.move(to: pt(39.6, 30))
        p.addLine(to: pt(37.5, 45))
        p.addQuadCurve(to: pt(38.8, 46.5), control: pt(37.3, 46.5))
        p.addLine(to: pt(47.2, 46.5))
        p.addQuadCurve(to: pt(48.5, 45), control: pt(48.7, 46.5))
        p.addLine(to: pt(46.4, 30))
        p.closeSubpath()
        return p
    }
}

/// What plays when stash opens: the prompt slides into the keyhole like a key,
/// the keyhole turns like a lock with a soft click, and the mark lifts away to
/// reveal your vault. About a second, and it never blocks touches. With Reduce
/// Motion, a quick fade instead.
struct UnlockCurtain: View {
    let finished: () -> Void
    private let size: CGFloat = 92

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var scale: CGFloat = 0.94
    @State private var keyIn = false
    @State private var turn: Double = 0
    @State private var glow: Double = 0
    @State private var lift = false
    @State private var clicked = false

    var body: some View {
        ZStack {
            Color.canvas.ignoresSafeArea()
                .opacity(lift ? 0 : 1)
            ZStack {
                Circle()
                    .fill(RadialGradient(colors: [Color.keyholeAmber.opacity(0.42), .clear],
                                         center: .center, startRadius: 0, endRadius: size * 1.25))
                    .frame(width: size * 2.5, height: size * 2.5)
                    .opacity(glow)
                RoundedRectangle(cornerRadius: size * 14.5 / 64, style: .continuous)
                    .fill(Color.vaultInk)
                    .overlay(RoundedRectangle(cornerRadius: size * 14.5 / 64, style: .continuous)
                        .strokeBorder(Color(hex: 0x2A303B), lineWidth: size * 1.5 / 64))
                    .frame(width: size, height: size)
                StashMarkPrompt()
                    .stroke(Color.plaintext, style: StrokeStyle(lineWidth: size * 6.5 / 64, lineCap: .round, lineJoin: .round))
                    .frame(width: size, height: size)
                    .offset(x: keyIn ? size * 12 / 64 : 0)
                    .opacity(keyIn ? 0 : 1)
                StashMarkKeyhole()
                    .fill(Color.keyholeAmber)
                    .frame(width: size, height: size)
                    .rotationEffect(.degrees(turn), anchor: StashMarkKeyhole.anchor)
            }
            .scaleEffect(lift ? 1.28 : scale)
            .opacity(lift ? 0 : 1)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .sensoryFeedback(.impact(weight: .light, intensity: 0.7), trigger: clicked)
        .task { await play() }
    }

    private func wait(_ seconds: Double) async {
        try? await Task.sleep(for: .seconds(seconds))
    }

    private func play() async {
        if reduceMotion {
            scale = 1
            await wait(0.2)
            withAnimation(.easeOut(duration: 0.25)) { lift = true }
            await wait(0.25)
            finished()
            return
        }
        withAnimation(.spring(response: 0.3, dampingFraction: 0.85)) { scale = 1 }
        await wait(0.08)
        withAnimation(.easeIn(duration: 0.2)) { keyIn = true }
        await wait(0.2)
        clicked = true
        withAnimation(.spring(response: 0.36, dampingFraction: 0.66)) { turn = 90 }
        withAnimation(.easeOut(duration: 0.28)) { glow = 1 }
        await wait(0.44)
        withAnimation(.easeInOut(duration: 0.36)) { lift = true }
        await wait(0.36)
        finished()
    }
}
