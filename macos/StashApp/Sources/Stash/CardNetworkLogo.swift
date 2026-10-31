// The card networks' own marks, drawn as vectors so they're sharp at any size.
// Visa and Mastercard are trademarks of their owners, shown only to identify a
// card's network. Other networks are shown by name.

import SwiftUI

struct CardNetworkLogo: View {
    let brand: String
    var height: CGFloat
    /// On a card's dark face, whatever the app's appearance.
    var onCard = false

    @Environment(\.colorScheme) private var scheme

    static func has(_ brand: String?) -> Bool { brand == "Visa" || brand == "Mastercard" }

    var body: some View {
        Group {
            switch brand {
            case "Visa":
                VisaMark()
                    .fill(onCard || scheme == .dark ? Color.white : Color(hex: 0x1434CB), style: FillStyle(eoFill: true))
                    .aspectRatio(VisaMark.aspect, contentMode: .fit)
            case "Mastercard":
                MastercardMark()
                    .aspectRatio(MastercardMark.aspect, contentMode: .fit)
            default:
                Text(brand)
            }
        }
        .frame(height: height)
        .accessibilityElement()
        .accessibilityLabel(brand)
    }
}

/// A verdict on something typed: a green check, or a red warning.
struct CheckLine: View {
    let ok: Bool
    let text: String

    var body: some View {
        Label(text, systemImage: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
            .labelStyle(CheckLabelStyle())
            .foregroundStyle(ok ? Color.success : Color.danger)
    }
}

private struct CheckLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon
            configuration.title
        }
    }
}

/// The network's logo, then the verdict on the number, once there is one.
struct CardStatusLine: View {
    let ok: Bool
    let brand: String?
    let text: String
    let note: String?

    var body: some View {
        if let brand, CardNetworkLogo.has(brand) {
            HStack(spacing: 6) {
                CardNetworkLogo(brand: brand, height: brand == "Visa" ? 10 : 15)
                if let note { CheckLine(ok: ok, text: note) }
            }
        } else if note != nil {
            CheckLine(ok: ok, text: text)
        } else {
            Text(text)
        }
    }
}

/// Two circles and the colour where they overlap. The circles' spacing is
/// Mastercard's: 0.617 of their diameter.
private struct MastercardMark: View {
    private static let spacing: CGFloat = 0.617
    static let aspect: CGFloat = 1 + spacing

    var body: some View {
        GeometryReader { geo in
            let d = geo.size.height
            let offset = d * Self.spacing
            ZStack(alignment: .leading) {
                Circle().fill(Color(hex: 0xEB001B)).frame(width: d, height: d)
                Circle().fill(Color(hex: 0xF79E1B)).frame(width: d, height: d).offset(x: offset)
                Circle().fill(Color(hex: 0xFF5F00)).frame(width: d, height: d)
                    .mask(Circle().frame(width: d, height: d).offset(x: offset))
            }
        }
    }
}

/// The Visa wordmark.
private struct VisaMark: Shape {
    private static let size = CGSize(width: 24, height: 7.751)
    static let aspect = size.width / size.height

    func path(in r: CGRect) -> Path {
        func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: r.minX + x / Self.size.width * r.width, y: r.minY + y / Self.size.height * r.height)
        }
        var p = Path()
        p.move(to: pt(9.112, 0.138))
        p.addLine(to: pt(5.970, 7.634))
        p.addLine(to: pt(3.920, 7.634))
        p.addLine(to: pt(2.374, 1.651))
        p.addCurve(to: pt(1.913, 0.993), control1: pt(2.280, 1.283), control2: pt(2.199, 1.148))
        p.addCurve(to: pt(0.000, 0.355), control1: pt(1.447, 0.740), control2: pt(0.677, 0.503))
        p.addLine(to: pt(0.046, 0.138))
        p.addLine(to: pt(3.346, 0.138))
        p.addCurve(to: pt(4.240, 0.902), control1: pt(3.792, 0.138), control2: pt(4.171, 0.462))
        p.addLine(to: pt(5.057, 5.240))
        p.addLine(to: pt(7.075, 0.138))
        p.closeSubpath()
        p.move(to: pt(17.145, 5.187))
        p.addCurve(to: pt(14.428, 2.215), control1: pt(17.153, 3.208), control2: pt(14.409, 3.099))
        p.addCurve(to: pt(15.250, 1.587), control1: pt(14.434, 1.946), control2: pt(14.690, 1.660))
        p.addCurve(to: pt(17.163, 1.923), control1: pt(15.906, 1.525), control2: pt(16.567, 1.641))
        p.addLine(to: pt(17.503, 0.333))
        p.addCurve(to: pt(15.689, 0.000), control1: pt(16.923, 0.115), control2: pt(16.309, 0.002))
        p.addCurve(to: pt(12.411, 2.479), control1: pt(13.772, 0.000), control2: pt(12.423, 1.020))
        p.addCurve(to: pt(14.109, 4.519), control1: pt(12.399, 3.558), control2: pt(13.374, 4.159))
        p.addCurve(to: pt(15.115, 5.450), control1: pt(14.865, 4.886), control2: pt(15.119, 5.122))
        p.addCurve(to: pt(13.955, 6.184), control1: pt(15.110, 5.954), control2: pt(14.513, 6.175))
        p.addCurve(to: pt(11.963, 5.711), control1: pt(12.980, 6.199), control2: pt(12.415, 5.921))
        p.addLine(to: pt(11.612, 7.353))
        p.addCurve(to: pt(13.768, 7.751), control1: pt(12.065, 7.561), control2: pt(12.901, 7.743))
        p.addCurve(to: pt(17.145, 5.187), control1: pt(15.805, 7.751), control2: pt(17.138, 6.745))
        p.move(to: pt(22.206, 7.634))
        p.addLine(to: pt(24.000, 7.634))
        p.addLine(to: pt(22.435, 0.138))
        p.addLine(to: pt(20.779, 0.138))
        p.addCurve(to: pt(19.953, 0.688), control1: pt(20.417, 0.135), control2: pt(20.090, 0.353))
        p.addLine(to: pt(17.044, 7.634))
        p.addLine(to: pt(19.080, 7.634))
        p.addLine(to: pt(19.485, 6.514))
        p.addLine(to: pt(21.973, 6.514))
        p.closeSubpath()
        p.move(to: pt(20.043, 4.978))
        p.addLine(to: pt(21.063, 2.163))
        p.addLine(to: pt(21.651, 4.978))
        p.closeSubpath()
        p.move(to: pt(11.883, 0.138))
        p.addLine(to: pt(10.280, 7.634))
        p.addLine(to: pt(8.340, 7.634))
        p.addLine(to: pt(9.945, 0.138))
        p.closeSubpath()
        return p
    }
}
