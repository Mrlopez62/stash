// Text rules for naming items, shared by the Mac and iPhone apps so both
// agree, and so the Mac's `--modeltest` checks them.

import Foundation

enum ItemText {
    /// "Chase Checking!" → "chase-checking": what item names allow.
    static func slug(_ text: String) -> String {
        let mapped = text.lowercased().map { $0.isASCII && ($0.isLetter || $0.isNumber) ? $0 : "-" }
        return String(mapped).split(separator: "-").joined(separator: "-").prefix(60).description
    }

    /// "https://www.github.com/login" → "github": a login's name from its website.
    static func site(fromWebsite website: String) -> String? {
        var host = website.lowercased()
        if let range = host.range(of: "://") { host = String(host[range.upperBound...]) }
        host = String(host.prefix { $0 != "/" && $0 != ":" })
        if host.hasPrefix("www.") { host = String(host.dropFirst(4)) }
        let site = slug(String(host.prefix { $0 != "." }))
        return site.isEmpty ? nil : site
    }

    /// The site and account a 2FA QR code names:
    /// `otpauth://totp/GitHub:me@x.com?issuer=GitHub`. Only for filling in
    /// empty fields: the code itself is checked by the vault's core.
    static func otpLabel(_ code: String) -> (issuer: String?, account: String?) {
        guard code.hasPrefix("otpauth://"), let url = URLComponents(string: code) else { return (nil, nil) }
        let path = url.path.drop { $0 == "/" }
        let parts = path.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        let named = url.queryItems?.first { $0.name == "issuer" }?.value
        let issuer = named ?? (parts.count == 2 ? parts[0] : nil)
        return (issuer.flatMap { $0.isEmpty ? nil : $0 }, parts.last.flatMap { $0.isEmpty ? nil : $0 })
    }
}
