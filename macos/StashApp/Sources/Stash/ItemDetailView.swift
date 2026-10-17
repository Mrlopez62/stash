import SwiftUI

struct ItemDetailView: View {
    @EnvironmentObject var model: AppModel
    let detail: ItemDetail
    let onEdit: () -> Void
    @ViewState private var confirmDelete = false
    @ViewState private var notes: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 14) {
                    ItemIcon(kind: detail.kind, size: 48)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(detail.name.split(separator: "/").last.map(String.init) ?? detail.name)
                            .font(.system(size: 22, weight: .semibold))
                            .foregroundStyle(Color.plaintext)
                        Text(detail.name.contains("/") ? "\(detail.kind.title) · \(detail.name)" : detail.kind.title)
                            .font(.mono(12))
                            .foregroundStyle(Color.redacted)
                    }
                    Spacer()
                    Button("Edit", action: onEdit)
                        .keyboardShortcut("e", modifiers: .command)
                        .disabled(detail.binary)
                }

                if detail.binary {
                    Text("This secret holds binary data. Use `stash get \(detail.name)` in the terminal.")
                        .font(.callout)
                        .foregroundStyle(Color.secondaryText)
                }

                VStack(spacing: 0) {
                    ForEach(Array(detail.fields.enumerated()), id: \.element.id) { index, field in
                        if index > 0 { Divider().overlay(Color.border) }
                        FieldRow(field: field)
                    }
                }
                .background(Color.enclave, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.border))

                if detail.hasNotes {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("notes").font(.mono(11)).foregroundStyle(Color.redacted)
                            Spacer()
                            Button(notes == nil ? "Show" : "Hide") {
                                if notes == nil {
                                    Task { notes = await model.reveal("notes") }
                                } else {
                                    notes = nil
                                }
                            }
                            .buttonStyle(.link)
                        }
                        Text(notes ?? "••••••••")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.plaintext)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(14)
                    .background(Color.enclave, in: RoundedRectangle(cornerRadius: 12))
                    .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.border))
                }

                HStack {
                    if detail.updated > 0 {
                        Text("Updated \(Date(timeIntervalSince1970: TimeInterval(detail.updated)).formatted(date: .abbreviated, time: .shortened))")
                    }
                    Spacer()
                    Text("stash://\(detail.name)")
                        .textSelection(.enabled)
                        .help("Use this reference in .env files, stash run, and stash inject")
                }
                .font(.mono(11))
                .foregroundStyle(Color.redacted)

                Button("Delete…", role: .destructive) { confirmDelete = true }
                    .buttonStyle(.link)
                    .foregroundStyle(.red)
            }
            .padding(28)
            .frame(maxWidth: 640, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color.vaultInk)
        .confirmationDialog("Delete \(detail.name)?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { Task { await model.delete(detail.name) } }
        } message: {
            Text("This can't be undone.")
        }
    }
}

struct FieldRow: View {
    @EnvironmentObject var model: AppModel
    let field: FieldInfo
    @ViewState private var revealed: String?
    @ViewState private var code: OTPCode?
    @ViewState private var fetchedAt = Date()

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label)
                    .font(.mono(11))
                    .foregroundStyle(Color.redacted)
                value
            }
            Spacer()
            actions
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .contentShape(Rectangle())
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
                            .font(.mono(20, weight: .semibold))
                            .foregroundStyle(Color.plaintext)
                        CountdownRing(fraction: Double(left) / Double(code.period))
                        Text("\(left)s").font(.mono(11)).foregroundStyle(Color.redacted)
                    }
                    .task(id: left == 0) {
                        if left == 0 { await refreshCode() }
                    }
                }
            } else {
                Text("••• •••").font(.mono(20)).foregroundStyle(Color.redacted)
            }
        case .concealed:
            Text(revealed ?? "••••••••••••")
                .font(.mono(14))
                .foregroundStyle(Color.plaintext)
                .textSelection(.enabled)
        case .url:
            if let v = field.value, let url = URL(string: v), url.scheme != nil {
                Link(v, destination: url).font(.system(size: 14))
            } else {
                Text(field.value ?? "").font(.system(size: 14)).foregroundStyle(Color.plaintext)
            }
        case .text, .email:
            Text(field.value ?? "")
                .font(.system(size: 14))
                .foregroundStyle(Color.plaintext)
                .textSelection(.enabled)
        }
    }

    @ViewBuilder private var actions: some View {
        HStack(spacing: 6) {
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
            IconButton("doc.on.doc", help: "Copy") {
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
            Circle().stroke(Color.border, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(fraction < 0.2 ? Color.red : Color.keyholeAmber, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
        }
        .frame(width: 16, height: 16)
    }
}

struct IconButton: View {
    let symbol: String
    let help: String
    let action: () -> Void

    init(_ symbol: String, help: String, action: @escaping () -> Void) {
        self.symbol = symbol
        self.help = help
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 13))
                .frame(width: 28, height: 28)
                .background(Color.vaultInk, in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.border))
        }
        .buttonStyle(.plain)
        .foregroundStyle(Color.secondaryText)
        .help(help)
    }
}
