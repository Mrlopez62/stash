// Quick Access: a floating search panel on ⇧⌘Space, from anywhere. Find an
// item, press Return to copy its password (or value), and get back to work.

import AppKit
import Carbon.HIToolbox
import SwiftUI

extension AppModel {
    /// Copy an item's main value without opening it.
    func copyPrimary(_ item: ItemSummary) async -> Bool {
        guard let backend else { return false }
        do {
            let detail = try await backend.item(item.name)
            guard let field = detail.fields.first(where: { $0.kind == .concealed }) else {
                if detail.hasNotes {
                    Clipboard.copySecret(try await backend.reveal(item.name, field: "notes"))
                    return true
                }
                return false
            }
            Clipboard.copySecret(try await backend.reveal(item.name, field: field.label))
            return true
        } catch let e as BackendError where e.isLocked {
            screen = .locked
        } catch {
            self.error = error.localizedDescription
        }
        return false
    }

    func copyOTP(for item: ItemSummary) async -> Bool {
        guard let backend else { return false }
        do {
            Clipboard.copySecret(try await backend.otp(item.name).code)
            return true
        } catch {
            self.error = error.localizedDescription
            return false
        }
    }
}

struct QuickAccessView: View {
    @EnvironmentObject var model: AppModel
    let close: () -> Void
    @ViewState private var query = ""
    @ViewState private var highlighted = 0
    @ViewState private var copied: String?
    @FocusState private var focused: Bool

    private var results: [ItemSummary] {
        let q = query.lowercased()
        let all = q.isEmpty ? model.items : model.items.filter {
            $0.name.lowercased().contains(q) || ($0.username?.lowercased().contains(q) ?? false)
        }
        return Array(all.prefix(8))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                StashMark(size: 22)
                TextField("Search stash", text: $query)
                    .textFieldStyle(.plain)
                    .font(.plex(19))
                    .foregroundStyle(Color.ink)
                    .focused($focused)
                    .onSubmit { Task { await copyHighlighted() } }
                    .onKeyPress(.return, phases: .down) { press in
                        guard press.modifiers.contains(.option),
                              let item = results[safe: highlighted], item.hasOtp else { return .ignored }
                        Task { if await model.copyOTP(for: item) { finish("2FA code") } }
                        return .handled
                    }
                    .onKeyPress(.downArrow) { highlighted = min(highlighted + 1, max(results.count - 1, 0)); return .handled }
                    .onKeyPress(.upArrow) { highlighted = max(highlighted - 1, 0); return .handled }
                    .onKeyPress(.escape) { close(); return .handled }
                    .onChange(of: query) { highlighted = 0 }
            }
            .padding(14)

            if case .unlocked = model.screen {
                if results.isEmpty {
                    Rectangle().fill(Color.line).frame(height: 1)
                    Text(query.isEmpty ? "Your vault is empty." : "No matches for “\(query)”")
                        .font(.plex(13))
                        .foregroundStyle(Color.inkTertiary)
                        .frame(maxWidth: .infinity, minHeight: 44)
                } else {
                    Rectangle().fill(Color.line).frame(height: 1)
                    VStack(spacing: 2) {
                        ForEach(Array(results.enumerated()), id: \.element.id) { index, item in
                            QuickRow(item: item, highlighted: index == highlighted)
                                .onTapGesture { highlighted = index; Task { await copyHighlighted() } }
                        }
                    }
                    .padding(6)
                }
                Rectangle().fill(Color.line).frame(height: 1)
                HStack(spacing: 14) {
                    if let copied {
                        Label("Copied \(copied) · clears in \(Int(Clipboard.clearAfter))s", systemImage: "checkmark.circle.fill")
                            .font(.plex(11.5, weight: .medium))
                            .foregroundStyle(Color.success)
                    } else {
                        KeyHint(keys: "↩", label: "copy password")
                        if results[safe: highlighted]?.hasOtp == true {
                            KeyHint(keys: "⌥↩", label: "copy 2FA code")
                        }
                        KeyHint(keys: "↑↓", label: "move")
                    }
                    Spacer()
                    KeyHint(keys: "esc", label: "close")
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(Color.surfaceRaised)
            } else {
                Rectangle().fill(Color.line).frame(height: 1)
                Button {
                    Task { await model.unlockWithTouchID() }
                } label: {
                    Label("Unlock stash", systemImage: "touchid").frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryButtonStyle(wide: true))
                .padding(14)
            }
        }
        .frame(width: 560)
        .background(Color.surface)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.line))
        .onAppear {
            query = ""
            copied = nil
            focused = true
        }
    }

    private func copyHighlighted() async {
        guard let item = results[safe: highlighted] else { return }
        if await model.copyPrimary(item) { finish(item.title) }
    }

    private func finish(_ what: String) {
        copied = what
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { close() }
    }
}

struct QuickRow: View {
    let item: ItemSummary
    let highlighted: Bool

    var body: some View {
        HStack(spacing: 10) {
            ItemIcon(kind: item.kind, size: 26)
            (Text(item.folder.map { "\($0)/" } ?? "").foregroundStyle(Color.inkTertiary)
                + Text(item.title).foregroundStyle(Color.ink))
                .font(.mono(13.5, weight: .semibold))
                .lineLimit(1)
            if let user = item.username {
                Text(user).font(.plex(12.5)).foregroundStyle(Color.inkTertiary)
            }
            Spacer()
            if highlighted {
                Keycap(keys: "↩")
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(highlighted ? Color.amberTint : .clear, in: RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
    }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}

/// A key panel that floats above other apps without a title bar.
final class QuickAccessPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

@MainActor
final class QuickAccessController {
    private var panel: QuickAccessPanel?
    private let model: AppModel

    init(model: AppModel) { self.model = model }

    func toggle() {
        if let panel, panel.isVisible {
            hide()
        } else {
            show()
        }
    }

    func show() {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        if case .unlocked = model.screen {
            Task { await model.reload() }
        }
        if let screen = NSScreen.main {
            let frame = screen.visibleFrame
            panel.setFrameTopLeftPoint(NSPoint(x: frame.midX - 280, y: frame.maxY - frame.height * 0.22))
        }
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    func hide() {
        panel?.orderOut(nil)
    }

    private func makePanel() -> QuickAccessPanel {
        let panel = QuickAccessPanel(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 120),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered, defer: false)
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.hidesOnDeactivate = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        // A hosting controller resizes the panel to fit its content.
        let controller = NSHostingController(rootView: QuickAccessView(close: { [weak self] in self?.hide() })
            .environmentObject(model))
        controller.sizingOptions = [.preferredContentSize]
        panel.contentViewController = controller
        return panel
    }
}

/// A system-wide shortcut through Carbon's hot key API, which needs no
/// Accessibility permission.
final class HotKey {
    private var ref: EventHotKeyRef?
    private static var actions: [UInt32: () -> Void] = [:]
    private static var installed = false

    init?(keyCode: UInt32, modifiers: UInt32, id: UInt32, action: @escaping () -> Void) {
        Self.installHandler()
        Self.actions[id] = action
        let hotKeyID = EventHotKeyID(signature: OSType(0x5354_5348), id: id) // "STSH"
        let status = RegisterEventHotKey(keyCode, modifiers, hotKeyID, GetApplicationEventTarget(), 0, &ref)
        if status != noErr { return nil }
    }

    deinit {
        if let ref { UnregisterEventHotKey(ref) }
    }

    private static func installHandler() {
        guard !installed else { return }
        installed = true
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, event, _ in
            var id = EventHotKeyID()
            GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID),
                              nil, MemoryLayout<EventHotKeyID>.size, nil, &id)
            DispatchQueue.main.async { HotKey.actions[id.id]?() }
            return noErr
        }, 1, &spec, nil, nil)
    }
}
