import CoreImage
import SwiftUI

/// The selected item, in a panel beside the table.
struct InspectorView: View {
    @EnvironmentObject var model: AppModel
    let detail: ItemDetail
    let onEdit: () -> Void
    @ViewState private var confirmDelete = false

    private var title: String { detail.name.split(separator: "/").last.map(String.init) ?? detail.name }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .top, spacing: 12) {
                    ItemIcon(kind: detail.kind, size: 42)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .font(.mono(17, weight: .bold))
                            .foregroundStyle(Color.ink)
                            .lineLimit(2)
                        if let folder {
                            Label(folder, systemImage: "folder")
                                .font(.plex(12))
                                .foregroundStyle(Color.inkTertiary)
                        }
                    }
                    Spacer(minLength: 4)
                    HStack(spacing: 0) {
                        IconButton("pencil", help: "Edit (⌘E)", action: onEdit)
                            .keyboardShortcut("e", modifiers: .command)
                            .disabled(detail.binary)
                        Menu {
                            Button("Copy reference") { model.copyPlain("stash://\(detail.name)", label: "reference") }
                            Divider()
                            Button("Delete Item…", role: .destructive) { confirmDelete = true }
                        } label: {
                            Image(systemName: "ellipsis")
                                .font(.system(size: 12, weight: .medium))
                                .frame(width: 28, height: 28)
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.hidden)
                        .fixedSize()
                        // Borderless menus take the accent color unless tinted.
                        .tint(Color.inkTertiary)
                        .foregroundStyle(Color.inkTertiary)
                        .help("More")
                        IconButton("xmark", help: "Close") { Task { await model.select(nil) } }
                    }
                }
                .padding(.top, 36)

                if let face = detail.card {
                    CardFaceView(
                        face: face,
                        cardholder: detail.fields.first { $0.label == "cardholder" }?.value,
                        expiry: detail.fields.first { $0.label == "expiry" }?.value)
                } else if detail.kind == .bank, let subtitle = detail.subtitle {
                    Label(subtitle, systemImage: "building.columns")
                        .font(.plex(13, weight: .medium))
                        .foregroundStyle(Color.inkSecondary)
                }

                if detail.binary {
                    Text("This secret holds binary data. Use `stash get \(detail.name)` in the terminal.")
                        .font(.plex(13))
                        .foregroundStyle(Color.inkSecondary)
                }

                if !detail.fields.isEmpty || detail.hasNotes {
                    Card(fill: true) {
                        VStack(spacing: 0) {
                            ForEach(Array(detail.fields.enumerated()), id: \.element.id) { index, field in
                                if index > 0 { Rectangle().fill(Color.line).frame(height: 1) }
                                FieldRow(field: field, maskedPreview: maskedPreview(for: field))
                            }
                            if detail.hasNotes {
                                if !detail.fields.isEmpty { Rectangle().fill(Color.line).frame(height: 1) }
                                NotesRow()
                            }
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Eyebrow(text: "Use in code")
                    HStack {
                        Text("stash://\(detail.name)")
                            .font(.mono(12))
                            .foregroundStyle(Color.inkSecondary)
                            .textSelection(.enabled)
                        Spacer()
                        IconButton("doc.on.doc", help: "Copy reference") {
                            model.copyPlain("stash://\(detail.name)", label: "reference")
                        }
                    }
                    .padding(.leading, 12)
                    .padding(.trailing, 2)
                    .padding(.vertical, 2)
                    .background(Color.surfaceRaised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.line))
                    (Text("Use it in .env files with ").font(.plex(11.5))
                        + Text("stash run").font(.mono(11.5)))
                        .foregroundStyle(Color.inkTertiary)
                }

                HStack(spacing: 14) {
                    if detail.updated > 0 {
                        Text("Updated \(relative(detail.updated))")
                    }
                    if detail.created > 0 && abs(detail.created - detail.updated) > 60 {
                        Text("Created \(relative(detail.created))")
                    }
                }
                .font(.plex(12))
                .foregroundStyle(Color.inkTertiary)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 24)
        }
        .background(Color.canvas)
        .confirmationDialog("Delete \(detail.name)?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { Task { await model.delete(detail.name) } }
        } message: {
            Text("This can't be undone.")
        }
    }

    /// Card and account numbers show their last four while hidden, the way
    /// a statement does.
    private func maskedPreview(for field: FieldInfo) -> String? {
        guard detail.kind.isPayment, ["number", "account number", "iban"].contains(field.label) else { return nil }
        if field.label == "number", let last4 = detail.card?.last4 { return "•••• •••• •••• \(last4)" }
        // "Chase · Checking •••• 6789" → "6789"
        return detail.subtitle?.split(separator: " ").last.map { "•••• \($0)" }
    }

    /// The icon already shows the kind, so only the folder needs saying.
    private var folder: String? {
        let folder = detail.name.split(separator: "/").dropLast().joined(separator: "/")
        return folder.isEmpty ? nil : folder
    }
}

/// Notes, hidden until revealed, in the same style as a concealed field.
struct NotesRow: View {
    @EnvironmentObject var model: AppModel
    @ViewState private var notes: String?
    @ViewState private var hovering = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 5) {
                Text("Notes").font(.plex(11.5, weight: .medium)).foregroundStyle(Color.inkTertiary)
                Text(notes ?? concealedMask)
                    .font(notes == nil ? .mono(13.5) : .plex(13.5))
                    .foregroundStyle(Color.ink)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 0) {
                IconButton(notes == nil ? "eye" : "eye.slash", help: notes == nil ? "Show notes" : "Hide notes") {
                    if notes == nil {
                        Task { notes = await model.reveal("notes") }
                    } else {
                        notes = nil
                    }
                }
                IconButton("doc.on.doc", help: "Copy notes") {
                    Task { await model.copySecret("notes", label: "notes") }
                }
            }
            .opacity(hovering ? 1 : 0.55)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(hovering ? Color.hover : Color.clear)
        .onHover { hovering = $0 }
    }
}

struct FieldRow: View {
    @EnvironmentObject var model: AppModel
    let field: FieldInfo
    /// For card and account numbers: e.g. "•••• 4242" while hidden.
    var maskedPreview: String?
    @ViewState private var revealed: String?
    @ViewState private var code: OTPCode?
    @ViewState private var fetchedAt = Date()
    @ViewState private var hovering = false
    @ViewState private var showQR = false

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 5) {
                Text(displayLabel(field.label))
                    .font(.plex(11.5, weight: .medium))
                    .foregroundStyle(Color.inkTertiary)
                value
            }
            Spacer(minLength: 4)
            actions.opacity(hovering || field.kind == .otp ? 1 : 0.55)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(hovering ? Color.hover : Color.clear)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .task(id: field.id) {
            guard field.kind == .otp else { return }
            await refreshCode()
        }
    }

    @ViewBuilder private var value: some View {
        switch field.kind {
        case .otp:
            if let code {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let left = max(0, code.remaining - Int(context.date.timeIntervalSince(fetchedAt)))
                    HStack(spacing: 10) {
                        Text(grouped(code.code))
                            .font(.mono(19, weight: .semibold))
                            .foregroundStyle(Color.ink)
                        CountdownRing(fraction: Double(left) / Double(code.period))
                        Text("\(left)s").font(.mono(11)).foregroundStyle(Color.inkTertiary)
                    }
                    .task(id: left == 0) {
                        if left == 0 { await refreshCode() }
                    }
                }
            } else {
                Text("••• •••").font(.mono(19)).foregroundStyle(Color.inkTertiary)
            }
        case .concealed:
            Text(revealed ?? maskedPreview ?? concealedMask)
                .font(.mono(13.5, weight: revealed == nil ? .regular : .medium))
                .foregroundStyle(Color.ink)
                .textSelection(.enabled)
                .lineLimit(revealed == nil ? 1 : nil)
        case .url:
            if let v = field.value, let url = URL(string: v), url.scheme != nil {
                Link(destination: url) {
                    Text(v).font(.plex(13.5)).foregroundStyle(Color.ink).underline(hovering)
                }
                .help("Open in your browser")
            } else {
                Text(field.value ?? "").font(.plex(13.5)).foregroundStyle(Color.ink)
            }
        case .text, .email:
            Text(displayValue(field.value ?? "", label: field.label))
                .font(.plex(13.5))
                .foregroundStyle(Color.ink)
                .textSelection(.enabled)
        }
    }

    @ViewBuilder private var actions: some View {
        HStack(spacing: 0) {
            if field.kind == .otp {
                IconButton("qrcode", help: "Show a QR code for your authenticator app") { showQR = true }
                    .popover(isPresented: $showQR, arrowEdge: .bottom) { AuthenticatorQR() }
            }
            if field.kind == .concealed {
                IconButton(revealed == nil ? "eye" : "eye.slash", help: revealed == nil ? "Reveal" : "Hide") {
                    if revealed == nil {
                        Task {
                            revealed = await model.reveal(field.label)
                            // Hide again after a while.
                            try? await Task.sleep(for: .seconds(30))
                            revealed = nil
                        }
                    } else {
                        revealed = nil
                    }
                }
            }
            IconButton("doc.on.doc", help: "Copy \(displayLabel(field.label).lowercased())") {
                Task {
                    switch field.kind {
                    case .otp: await model.copyOTP()
                    case .concealed: await model.copySecret(field.label, label: field.label)
                    default: model.copyPlain(field.value ?? "", label: field.label)
                    }
                }
            }
        }
    }

    private func refreshCode() async {
        code = await model.otp()
        fetchedAt = Date()
    }

    private func grouped(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }
}

struct CountdownRing: View {
    let fraction: Double

    var body: some View {
        ZStack {
            Circle().stroke(Color.line, lineWidth: 2.5)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(fraction < 0.2 ? Color.danger : Color.keyholeAmber,
                        style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
        }
        .frame(width: 15, height: 15)
    }
}

/// A QR code for adding this item's 2FA to an authenticator app.
///
/// The code itself carries the 2FA secret (that's how authenticator apps
/// import it), so it's fetched only when this opens, never shown as text,
/// and closes by itself after a minute.
struct AuthenticatorQR: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @ViewState private var link: OTPLink?
    @ViewState private var image: NSImage?

    var body: some View {
        VStack(spacing: 14) {
            Text("Add to an authenticator app")
                .font(.plex(14, weight: .semibold))
                .foregroundStyle(Color.ink)
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.white)
                if let image {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .aspectRatio(1, contentMode: .fit)
                        .padding(14)
                } else {
                    ProgressView()
                }
            }
            .frame(width: 220, height: 220)
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.line))
            if let link {
                Text("\(link.issuer) · \(link.account)")
                    .font(.mono(12))
                    .foregroundStyle(Color.inkSecondary)
            }
            Text("Scan with Google Authenticator, Authy, or your phone's Passwords app. Anyone who sees this code can make your 2FA codes, so close it when you're done.")
                .font(.plex(11.5))
                .foregroundStyle(Color.inkTertiary)
                .multilineTextAlignment(.center)
                .frame(width: 250)
        }
        .padding(20)
        .background(Color.surface)
        .task {
            link = await model.otpLink()
            image = link.flatMap { qrImage($0.uri) }
            try? await Task.sleep(for: .seconds(60))
            dismiss()
        }
        .onDisappear {
            link = nil
            image = nil
        }
    }

    /// A crisp QR image from CoreImage (scaled with nearest-neighbor).
    private func qrImage(_ text: String) -> NSImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: output.extent.width, height: output.extent.height))
    }
}
