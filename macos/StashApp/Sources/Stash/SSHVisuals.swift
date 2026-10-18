// An SSH key at the top of its inspector: the key type, its fingerprint,
// and its "randomart", the picture `ssh-keygen -lv` draws from the
// fingerprint, so two keys can be told apart at a glance and checked
// against the terminal.

import SwiftUI

struct SSHKeyPanel: View {
    let fingerprint: String
    let publicKey: String?
    let copyPublicKey: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 6) {
                        Image(systemName: "terminal")
                            .font(.system(size: 11, weight: .semibold))
                        Text("ED25519")
                            .font(.plex(10, weight: .semibold))
                            .tracking(1.2)
                    }
                    .foregroundStyle(Color.plaintext.opacity(0.6))
                    VStack(alignment: .leading, spacing: 3) {
                        Text("FINGERPRINT")
                            .font(.plex(8.5, weight: .semibold))
                            .tracking(1.1)
                            .foregroundStyle(Color.plaintext.opacity(0.5))
                        Text(fingerprint.replacingOccurrences(of: "SHA256:", with: ""))
                            .font(.mono(11.5, weight: .medium))
                            .foregroundStyle(Color.plaintext)
                            .lineLimit(4)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                    Spacer(minLength: 0)
                }
                Spacer(minLength: 0)
                RandomArt(fingerprint: fingerprint)
            }
            Button(action: copyPublicKey) {
                Label("Copy Public Key", systemImage: "doc.on.doc")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(PrimaryButtonStyle(wide: true))
            .disabled(publicKey == nil)
            .help("For GitHub (Settings → SSH and GPG keys) or a server's authorized_keys")
        }
        .padding(18)
        .background {
            ZStack {
                LinearGradient(colors: [Color(hex: 0x232934), Color.vaultInk],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
                RadialGradient(colors: [Color.keyholeAmber.opacity(0.10), .clear],
                               center: .topTrailing, startRadius: 4, endRadius: 220)
            }
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        }
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(Color.white.opacity(0.10)))
        .shadow(color: .black.opacity(0.18), radius: 14, y: 8)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Ed25519 SSH key, fingerprint \(fingerprint)")
    }
}

/// OpenSSH's "drunken bishop" picture of a fingerprint.
struct RandomArt: View {
    let fingerprint: String

    var body: some View {
        let rows = RandomArt.rows(fingerprint: fingerprint)
        VStack(spacing: 0) {
            Text("+--[ED25519 256]--+")
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                Text("|\(row)|")
            }
            Text("+----[SHA256]-----+")
        }
        .font(.mono(8.5, weight: .medium))
        .foregroundStyle(Color.keyholeAmber.opacity(0.85))
        .fixedSize()
        .accessibilityHidden(true)
        .help("The same picture as `ssh-keygen -lvf` shows for this key")
    }

    /// The 17×9 field, row by row (sshkey.c, fingerprint_randomart).
    static func rows(fingerprint: String) -> [String] {
        let width = 17, height = 9
        let symbols = Array(" .o+=*BOX@%&#/^SE")
        let start = symbols.count - 2, end = symbols.count - 1
        var field = Array(repeating: Array(repeating: 0, count: height), count: width)
        var x = width / 2, y = height / 2
        for byte in digest(fingerprint) {
            var input = byte
            for _ in 0..<4 {
                x = min(max(x + (input & 1 == 1 ? 1 : -1), 0), width - 1)
                y = min(max(y + (input & 2 == 2 ? 1 : -1), 0), height - 1)
                if field[x][y] < start { field[x][y] += 1 }
                input >>= 2
            }
        }
        field[width / 2][height / 2] = start
        field[x][y] = end
        return (0..<height).map { row in
            String((0..<width).map { symbols[min(field[$0][row], end)] })
        }
    }

    /// The SHA-256 digest in a `SHA256:…` fingerprint (unpadded base64).
    static func digest(_ fingerprint: String) -> [UInt8] {
        var b64 = fingerprint.replacingOccurrences(of: "SHA256:", with: "")
        while b64.count % 4 != 0 { b64 += "=" }
        return Data(base64Encoded: b64).map { Array($0) } ?? []
    }
}
