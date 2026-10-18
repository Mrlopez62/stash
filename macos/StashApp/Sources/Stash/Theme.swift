// The stash design system, from docs/brand: Paper and white in light mode,
// Vault Ink in dark mode, JetBrains Mono for names and values, IBM Plex
// Sans for text, and Keyhole Amber only for the one thing that matters on
// screen (the primary action, the selection, the secret).

import AppKit
import CoreText
import SwiftUI

// MARK: - Color

extension Color {
    init(hex: UInt32) {
        self.init(nsColor: NSColor(hex: hex))
    }

    /// A color that follows the system appearance.
    init(light: UInt32, dark: UInt32) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(hex: dark) : NSColor(hex: light)
        })
    }

    // Brand constants.
    static let keyholeAmber = Color(hex: 0xF5B544)
    static let vaultInk = Color(hex: 0x0E1116)
    static let enclave = Color(hex: 0x171B22)
    static let plaintext = Color(hex: 0xE8EAED)
    static let paper = Color(hex: 0xF4F2EC)

    // Semantic, appearance-aware.
    static let canvas = Color(light: 0xF4F2EC, dark: 0x0B0D11)
    static let sidebar = Color(light: 0xEDEAE2, dark: 0x0E1116)
    static let surface = Color(light: 0xFFFFFF, dark: 0x171B22)
    static let surfaceRaised = Color(light: 0xFAF9F6, dark: 0x1D222B)
    static let line = Color(light: 0xE4E0D6, dark: 0x2A303B)
    static let ink = Color(light: 0x0E1116, dark: 0xE8EAED)
    static let inkSecondary = Color(light: 0x4A5160, dark: 0xB9C0CC)
    static let inkTertiary = Color(light: 0x7D8594, dark: 0x8A93A3)
    static let amberTint = Color(light: 0xFCEFD4, dark: 0x3A2F17)
    static let amberText = Color(light: 0x8A5A00, dark: 0xF5B544)
    static let success = Color(light: 0x1F8A5B, dark: 0x7DD3A8)
    static let successTint = Color(light: 0xE3F4EB, dark: 0x173327)
    static let danger = Color(light: 0xC2410C, dark: 0xFF8A65)
    static let hover = Color(light: 0xF6F4EF, dark: 0x1B2028)
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1)
    }
}

// MARK: - Type

enum BrandFonts {
    /// Register the bundled fonts (OFL, see Fonts/). Falls back to system
    /// fonts if they're missing, so the app never fails to draw text.
    static func register() {
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("Fonts"),
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fonts"),
        ]
        guard let dir = candidates.compactMap({ $0 }).first(where: {
            FileManager.default.fileExists(atPath: $0.appendingPathComponent("IBMPlexSans.ttf").path)
        }) else { return }
        for file in ["IBMPlexSans.ttf", "JetBrainsMono.ttf"] {
            CTFontManagerRegisterFontsForURL(dir.appendingPathComponent(file) as CFURL, .process, nil)
        }
    }

    static var available: Bool { NSFont(name: "IBM Plex Sans", size: 12) != nil }
}

extension Font {
    /// Body text: IBM Plex Sans.
    static func plex(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        BrandFonts.available ? .custom("IBM Plex Sans", size: size).weight(weight) : .system(size: size, weight: weight)
    }

    /// Names, values, and code: JetBrains Mono.
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        NSFont(name: "JetBrains Mono", size: size) != nil
            ? .custom("JetBrains Mono", size: size).weight(weight)
            : .system(size: size, weight: weight, design: .monospaced)
    }
}

// MARK: - Components

/// A white (or Enclave) card with a hairline border and a soft shadow.
struct Card<Content: View>: View {
    var padding: CGFloat = 0
    /// Stretch to the available width (forms, panels) instead of hugging.
    var fill = false
    @ViewBuilder var content: Content

    var body: some View {
        content
            .frame(maxWidth: fill ? .infinity : nil, alignment: .leading)
            .padding(padding)
            .background(Color.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.line))
            .shadow(color: .black.opacity(0.05), radius: 1, y: 1)
            .shadow(color: .black.opacity(0.05), radius: 12, y: 6)
    }
}

/// Small-caps section and column headers.
struct Eyebrow: View {
    let text: String
    var body: some View {
        Text(text.uppercased())
            .font(.plex(10.5, weight: .semibold))
            .tracking(1.1)
            .foregroundStyle(Color.inkTertiary)
    }
}

/// The primary action: amber, used once per screen.
struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    var wide = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.plex(13, weight: .semibold))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .frame(maxWidth: wide ? .infinity : nil)
            .foregroundStyle(Color.vaultInk)
            .background(
                Color.keyholeAmber.opacity(enabled ? (configuration.isPressed ? 0.82 : 1) : 0.45),
                in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(Rectangle())
    }
}

/// A quiet secondary button with a hairline border.
struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.plex(13, weight: .medium))
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .foregroundStyle(Color.ink)
            .background(
                configuration.isPressed ? Color.hover : Color.surface,
                in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.line))
            .contentShape(Rectangle())
    }
}

/// A small square icon button (copy, reveal, close).
struct IconButton: View {
    let symbol: String
    let help: String
    let action: () -> Void
    @ViewState private var hovering = false

    init(_ symbol: String, help: String, action: @escaping () -> Void) {
        self.symbol = symbol
        self.help = help
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 12, weight: .medium))
                .frame(width: 28, height: 28)
                .background(hovering ? Color.hover : .clear, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        }
        .buttonStyle(.plain)
        .foregroundStyle(hovering ? Color.ink : Color.inkTertiary)
        .onHover { hovering = $0 }
        .help(help)
    }
}

/// A text input with the app's look and an amber focus ring (the cursor is
/// a legitimate use of amber).
struct FieldBox<Content: View, Trailing: View>: View {
    var icon: String?
    var mono = true
    @ViewBuilder var content: Content
    /// Buttons inside the box (reveal, generate, remove), so every input in
    /// a form shares the same right edge.
    @ViewBuilder var trailing: Trailing
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 8) {
            if let icon {
                Image(systemName: icon)
                    .font(.system(size: 12.5))
                    .foregroundStyle(Color.inkTertiary)
                    .frame(width: 16)
            }
            content
                .textFieldStyle(.plain)
                .font(mono ? .mono(13.5) : .plex(13.5))
                .foregroundStyle(Color.ink)
                .focused($focused)
            trailing
        }
        .padding(.leading, 12)
        .padding(.trailing, Trailing.self == EmptyView.self ? 12 : 4)
        .frame(minHeight: 36)
        .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(focused ? Color.keyholeAmber.opacity(0.7) : Color.line, lineWidth: focused ? 1.5 : 1))
    }
}

extension FieldBox where Trailing == EmptyView {
    init(icon: String? = nil, mono: Bool = true, @ViewBuilder content: () -> Content) {
        self.init(icon: icon, mono: mono, content: content, trailing: { EmptyView() })
    }
}

/// A keyboard shortcut chip: ⇧⌘L, ↩, esc.
struct Keycap: View {
    let keys: String
    var body: some View {
        Text(keys)
            .font(.mono(10.5, weight: .medium))
            .foregroundStyle(Color.inkSecondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 1.5)
            .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 4, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(Color.line))
    }
}

/// A hint like "[↩] copy password".
struct KeyHint: View {
    let keys: String
    let label: String
    var body: some View {
        HStack(spacing: 5) {
            Keycap(keys: keys)
            Text(label).font(.plex(11.5)).foregroundStyle(Color.inkTertiary)
        }
    }
}

/// Field labels are stored lowercase ("one-time password"); show them
/// sentence-case ("One-time password").
func displayLabel(_ label: String) -> String {
    label.prefix(1).uppercased() + label.dropFirst()
}

/// The one way hidden values are shown.
let concealedMask = "••••••••••••"

/// A rounded search field.
struct SearchField: View {
    let prompt: String
    @Binding var text: String
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12))
                .foregroundStyle(Color.inkTertiary)
            TextField("", text: $text, prompt: Text(prompt).foregroundStyle(Color.inkTertiary))
                .textFieldStyle(.plain)
                .font(.plex(13))
                .focused($focused)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(Color.inkTertiary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(focused ? Color.keyholeAmber.opacity(0.7) : Color.line, lineWidth: focused ? 1.5 : 1))
    }
}

/// A rounded tag ("Login", "2FA").
struct Badge: View {
    let text: String
    var tint: Color = .surfaceRaised
    var foreground: Color = .inkSecondary

    var body: some View {
        Text(text)
            .font(.plex(11, weight: .medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(foreground)
            .background(tint, in: Capsule())
            .overlay(Capsule().strokeBorder(Color.line.opacity(0.7)))
    }
}

// MARK: - The mark

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

/// The full mark: ink tile, light chevron, amber keyhole (the app icon).
struct StashMark: View {
    var size: CGFloat = 64

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 15 / 64, style: .continuous)
                .fill(Color.vaultInk)
                .overlay(
                    RoundedRectangle(cornerRadius: size * 15 / 64, style: .continuous)
                        .strokeBorder(Color(hex: 0x2A303B), lineWidth: max(0.5, size * 1.5 / 64)))
            Chevron().fill(Color.plaintext)
            Keyhole().fill(Color.keyholeAmber)
        }
        .frame(width: size, height: size)
        .accessibilityLabel("stash")
    }
}

/// The wordmark: lowercase "stash" plus the amber block cursor.
struct Wordmark: View {
    var size: CGFloat = 40

    var body: some View {
        HStack(alignment: .lastTextBaseline, spacing: size * 0.06) {
            Text("stash")
                .font(.mono(size, weight: .heavy))
                .tracking(-size * 0.06)
                .foregroundStyle(Color.ink)
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

/// "2h ago", "3d ago", or a date.
func relative(_ unix: Int) -> String {
    guard unix > 0 else { return "—" }
    let date = Date(timeIntervalSince1970: TimeInterval(unix))
    let seconds = Date().timeIntervalSince(date)
    switch seconds {
    case ..<60: return "just now"
    case ..<3600: return "\(Int(seconds / 60))m ago"
    case ..<86_400: return "\(Int(seconds / 3600))h ago"
    case ..<(86_400 * 30): return "\(Int(seconds / 86_400))d ago"
    case ..<(86_400 * 300): return date.formatted(.dateTime.month(.abbreviated).day())
    default: return date.formatted(.dateTime.month(.abbreviated).year())
    }
}
