import AppKit

/// Copies secrets the way password managers should:
/// - marked **concealed** and **transient** (nspasteboard.org conventions),
///   so clipboard-history apps skip them;
/// - **this Mac only**, so Universal Clipboard doesn't send them to your
///   other devices;
/// - **cleared** after a while, unless you've copied something else since.
enum Clipboard {
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    static var clearAfter: TimeInterval = 30

    @MainActor
    static func copySecret(_ value: String) {
        let pb = NSPasteboard.general
        pb.prepareForNewContents(with: .currentHostOnly)
        pb.declareTypes([.string, concealed, transient], owner: nil)
        pb.setString(value, forType: .string)
        pb.setString("", forType: concealed)
        pb.setString("", forType: transient)
        let change = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            if pb.changeCount == change {
                pb.clearContents()
            }
        }
    }

    /// Plain copies for things that aren't secret (usernames, URLs).
    @MainActor
    static func copy(_ value: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(value, forType: .string)
    }
}
