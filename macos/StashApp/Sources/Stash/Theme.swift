// The stash brand (docs/brand): mostly ink, a little amber. Amber marks the
// one thing that matters — the secret, the unlock, the primary action.

import SwiftUI

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255)
    }

    static let keyholeAmber = Color(hex: 0xF5B544)
    static let vaultInk = Color(hex: 0x0E1116)
    static let enclave = Color(hex: 0x171B22)
    static let border = Color(hex: 0x2A303B)
    static let redacted = Color(hex: 0x8A93A3)
    static let plaintext = Color(hex: 0xE8EAED)
    static let secondaryText = Color(hex: 0xB9C0CC)
    static let success = Color(hex: 0x7DD3A8)
    static let paper = Color(hex: 0xF4F2EC)
}

extension Font {
    /// JetBrains Mono is the brand face; SF Mono stands in until it's bundled.
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}

/// The mark's shapes in its 64×64 design space, scaled to any size.
private func scaled(_ rect: CGRect) -> (CGFloat, CGFloat, CGFloat) {
    let s = min(rect.width, rect.height) / 64
    return (s, rect.minX + (rect.width - 64 * s) / 2, rect.minY + (rect.height - 64 * s) / 2)
}

/// The prompt chevron: the terminal.
struct Chevron: Shape {
    var bold = false
    func path(in rect: CGRect) -> Path {
        let (s, x, y) = scaled(rect)
        var p = Path()
        p.move(to: CGPoint(x: x + 14 * s, y: y + 20 * s))
        p.addLine(to: CGPoint(x: x + 26 * s, y: y + 32 * s))
        p.addLine(to: CGPoint(x: x + 14 * s, y: y + 44 * s))
        return p.strokedPath(StrokeStyle(lineWidth: (bold ? 8 : 6.5) * s, lineCap: .round, lineJoin: .round))
    }
}

/// The keyhole: the cursor waiting for your fingerprint.
struct Keyhole: Shape {
    func path(in rect: CGRect) -> Path {
        let (s, x, y) = scaled(rect)
        func pt(_ px: CGFloat, _ py: CGFloat) -> CGPoint { CGPoint(x: x + px * s, y: y + py * s) }
        let head = Path(ellipseIn: CGRect(x: x + 36 * s, y: y + 20 * s, width: 14 * s, height: 14 * s))
        var p = Path()
        p.move(to: pt(39.6, 30))
        p.addLine(to: pt(37.5, 45))
        p.addQuadCurve(to: pt(38.8, 46.5), control: pt(37.3, 46.5))
        p.addLine(to: pt(47.2, 46.5))
        p.addQuadCurve(to: pt(48.5, 45), control: pt(48.7, 46.5))
        p.addLine(to: pt(46.4, 30))
        p.closeSubpath()
        // One merged shape: overlapping subpaths drawn in opposite directions
        // would otherwise cancel out and leave a notch.
        return head.union(p)
    }
}

/// The full mark: tile, chevron, keyhole.
struct StashMark: View {
    var size: CGFloat = 64
    var tile: Color = .enclave
    var chevron: Color = .plaintext
    var keyhole: Color = .keyholeAmber

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 15 / 64, style: .continuous)
                .fill(tile)
                .overlay(
                    RoundedRectangle(cornerRadius: size * 15 / 64, style: .continuous)
                        .strokeBorder(Color.border, lineWidth: max(1, size * 1.5 / 64)))
            Chevron().fill(chevron)
            Keyhole().fill(keyhole)
        }
        .frame(width: size, height: size)
        .accessibilityLabel("stash")
    }
}

/// The wordmark: lowercase "stash" plus the amber block cursor.
struct Wordmark: View {
    var size: CGFloat = 40
    var color: Color = .plaintext

    var body: some View {
        HStack(alignment: .lastTextBaseline, spacing: size * 0.06) {
            Text("stash")
                .font(.mono(size, weight: .heavy))
                .tracking(-size * 0.06)
                .foregroundStyle(color)
            RoundedRectangle(cornerRadius: size * 0.02)
                .fill(Color.keyholeAmber)
                .frame(width: size * 0.13, height: size * 0.155)
        }
    }
}

/// The menu bar template image (black only; macOS tints it).
@MainActor
func menuBarImage() -> NSImage {
    let view = ZStack {
        Chevron(bold: true).fill(.black)
        Keyhole().fill(.black)
    }
    .frame(width: 18, height: 18)
    let renderer = ImageRenderer(content: view)
    renderer.scale = 2
    let image = renderer.nsImage ?? NSImage(systemSymbolName: "key.fill", accessibilityDescription: "stash")!
    image.size = NSSize(width: 18, height: 18)
    image.isTemplate = true
    return image
}
