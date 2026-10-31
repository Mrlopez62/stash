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
            var prompt = Path()
            prompt.move(to: p(14, 20))
            prompt.addLine(to: p(26, 32))
            prompt.addLine(to: p(14, 44))
            ctx.stroke(prompt, with: .color(.plaintext),
                       style: StrokeStyle(lineWidth: 6.5 * s, lineCap: .round, lineJoin: .round))
            ctx.fill(Path(ellipseIn: CGRect(x: 36 * s, y: 20 * s, width: 14 * s, height: 14 * s)), with: .color(.keyholeAmber))
            var keyhole = Path()
            keyhole.move(to: p(39.6, 30))
            keyhole.addLine(to: p(37.5, 45))
            keyhole.addQuadCurve(to: p(38.8, 46.5), control: p(37.3, 46.5))
            keyhole.addLine(to: p(47.2, 46.5))
            keyhole.addQuadCurve(to: p(48.5, 45), control: p(48.7, 46.5))
            keyhole.addLine(to: p(46.4, 30))
            keyhole.closeSubpath()
            ctx.fill(keyhole, with: .color(.keyholeAmber))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
