import SwiftUI

// MARK: - Detail

struct DetailView: View {
    @EnvironmentObject var model: PhoneModel
    let item: PhoneItem
    @State private var detail: PhoneDetail?
    /// Revealed values, by label; hidden again after 30 seconds.
    @State private var shown: [String: String] = [:]
    @State private var confirmDelete = false
    @State private var editing = false
    @State private var finish: CardFinish?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            if let detail {
                if let face = detail.card {
                    CardFaceView(face: face,
                                 cardholder: detail.value("cardholder"),
                                 expiry: detail.value("expiry"),
                                 revealCVV: { model.reveal(item.name, "cvv") },
                                 finish: finish)
                        .padding(.vertical, 8)
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets())
                    Section("Card Color") {
                        CardColorPicker(selection: Binding(get: { finish }, set: { new in
                            finish = new
                            model.setCardColor(item.name, new)
                        }))
                        .listRowBackground(Color.surface)
                    }
                }
                Section {
                    ForEach(detail.fields) { field in
                        if field.kind == .otp {
                            OTPRow(name: item.name)
                        } else {
                            fieldRow(field)
                        }
                    }
                }
                if detail.hasNotes {
                    Section { fieldRow(FieldInfo(label: "notes", kind: .concealed, value: nil)) }
                }
                if model.madeHere {
                    Section {
                        Button("Delete", role: .destructive) { confirmDelete = true }
                            .listRowBackground(Color.surface)
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.canvas)
        .navigationTitle(item.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text(item.title).font(.mono(15, weight: .semibold)).foregroundStyle(Color.ink)
            }
            if model.madeHere {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Edit") { editing = true }
                }
            }
        }
        .sheet(isPresented: $editing) {
            Group {
                if item.kind == .login {
                    LoginFormView(editing: item, onSaved: saved)
                } else {
                    AddPaymentView(kind: item.kind == .bank ? .bank : .card, editing: item, onSaved: saved)
                }
            }
            .sheetGuarded()
        }
        #if DEBUG
        .onAppear {
            // Simulator checks only (never in release builds).
            if SimHooks.shows("edit") { editing = true }
        }
        #endif
        .confirmationDialog("Delete \(item.title)?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if model.removeItem(item.name) { dismiss() }
            }
        } message: {
            Text("This is the only copy, and it can't be undone.")
        }
        .onAppear {
            detail = model.detail(item.name)
            finish = detail?.cardColor.flatMap(CardFinish.init(rawValue:))
            #if DEBUG
            if let color = SimHooks.color { finish = CardFinish(rawValue: color) }
            #endif
        }
        .onDisappear { shown = [:] }
    }

    private func saved(_ name: String) {
        shown = [:]
        // A new nickname is a new item: back to the list to find it.
        if name == item.name { detail = model.detail(name) } else { dismiss() }
    }

    /// Where a saved website opens: web addresses only.
    private func link(_ value: String?) -> URL? {
        guard let value, !value.isEmpty else { return nil }
        let url = URL(string: value.contains("://") ? value : "https://\(value)")
        return ["http", "https"].contains(url?.scheme?.lowercased()) ? url : nil
    }

    private func fieldRow(_ field: FieldInfo) -> some View {
        let value = field.value ?? shown[field.label]
        return HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(displayLabel(field.label))
                    .font(.plex(12.5, weight: .medium))
                    .foregroundStyle(Color.inkSecondary)
                // Hidden fields can't be selected: the system's Copy would skip
                // the copy button's stay-on-this-phone and 60-second rules.
                let shownValue = Text(value ?? "••••••••••••")
                    .font(.mono(16))
                    .foregroundStyle(Color.ink)
                if field.value != nil {
                    shownValue.textSelection(.enabled)
                } else {
                    shownValue
                }
            }
            Spacer()
            if field.kind == .url, let url = link(field.value) {
                Link(destination: url) {
                    Image(systemName: "arrow.up.right.square")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Open website")
            }
            if field.value == nil {
                Button {
                    toggle(field.label)
                } label: {
                    Image(systemName: shown[field.label] == nil ? "eye" : "eye.slash")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(shown[field.label] == nil ? "Show \(field.label)" : "Hide \(field.label)")
            }
            Button {
                if let v = field.value ?? model.reveal(item.name, field.label) {
                    model.copy(v, label: field.label)
                }
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Copy \(field.label)")
        }
        .listRowBackground(Color.surface)
    }

    private func displayLabel(_ label: String) -> String {
        switch label {
        case "number": "Card Number"
        case "cvv": "Security Code"
        case "pin": "PIN"
        case "iban": "IBAN"
        case "swift": "SWIFT"
        case "billing zip": "Billing ZIP"
        case "routing number": "Routing Number"
        default: label.capitalized
        }
    }

    private func toggle(_ label: String) {
        if shown[label] != nil {
            shown[label] = nil
            return
        }
        guard let value = model.reveal(item.name, label) else { return }
        shown[label] = value
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(30))
            shown[label] = nil
        }
    }
}

/// A login's 2FA code, kept current, with the time it has left. The code is
/// fetched once per period, not every second.
struct OTPRow: View {
    @EnvironmentObject var model: PhoneModel
    let name: String
    @State private var current: (otp: PhoneOTP, until: Date)?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let otp = code(at: context.date)
            let remaining = otp.map { max(0, Int(ceil($0.until.timeIntervalSince(context.date)))) }
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("2FA Code")
                        .font(.plex(12.5, weight: .medium))
                        .foregroundStyle(Color.inkSecondary)
                    Text(otp.map { grouped($0.otp.code) } ?? "——— ———")
                        .font(.mono(20, weight: .semibold))
                        .foregroundStyle(Color.ink)
                        .contentTransition(.numericText())
                }
                Spacer()
                if let otp, let remaining {
                    ZStack {
                        Circle().stroke(Color.line, lineWidth: 2.5)
                        Circle()
                            .trim(from: 0, to: CGFloat(remaining) / CGFloat(max(otp.otp.period, 1)))
                            .stroke(remaining <= 5 ? Color.danger : Color.inkSecondary,
                                    style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(remaining)")
                            .font(.mono(10.5, weight: .medium))
                            .foregroundStyle(Color.inkSecondary)
                    }
                    .frame(width: 28, height: 28)
                    .accessibilityLabel("\(remaining) seconds left")
                }
                Button {
                    if let code = code(at: .now)?.otp.code { model.copy(code, label: "2FA code") }
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Copy 2FA code")
            }
        }
        .listRowBackground(Color.surface)
    }

    /// The current code, asking the vault only when the last one has run out.
    private func code(at date: Date) -> (otp: PhoneOTP, until: Date)? {
        if let current, date < current.until { return current }
        guard let otp = model.otp(name) else { return nil }
        let fresh = (otp: otp, until: date.addingTimeInterval(TimeInterval(otp.remaining)))
        // Not during the view update itself.
        DispatchQueue.main.async { current = fresh }
        return fresh
    }

    private func grouped(_ code: String) -> String {
        let middle = code.count / 2
        return "\(code.prefix(middle)) \(code.suffix(code.count - middle))"
    }
}
