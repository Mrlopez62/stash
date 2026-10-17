import AppKit
import Carbon.HIToolbox
import SwiftUI

@main
struct StashApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("stash", id: "main") {
            RootView()
                .environmentObject(delegate.model)
                .frame(minWidth: 1000, minHeight: 600)
                .tint(.keyholeAmber)
                .font(.plex(13))
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1240, height: 760)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Quick Access") { delegate.quickAccess?.toggle() }
                    .keyboardShortcut(.space, modifiers: [.command, .shift])
            }
        }

        MenuBarExtra {
            MenuBarContent(quickAccess: { delegate.quickAccess?.show() })
                .environmentObject(delegate.model)
        } label: {
            Image(nsImage: menuBarImage())
        }

        Settings {
            SettingsView()
                .environmentObject(delegate.model)
                .tint(.keyholeAmber)
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            switch model.screen {
            case .starting:
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity).background(Color.canvas)
            case .createVault:
                CreateVaultView()
            case .locked:
                LockView()
            case .unlocked:
                VaultView()
            case .failed(let message):
                VStack(spacing: 16) {
                    StashMark(size: 56)
                    Text(message).font(.plex(14)).foregroundStyle(Color.inkSecondary).multilineTextAlignment(.center)
                }
                .padding(40)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.canvas)
            }
        }
        .task { await model.start() }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    let quickAccess: () -> Void

    var body: some View {
        Button("Quick Access") { quickAccess() }
            .keyboardShortcut(.space, modifiers: [.command, .shift])
        Button("Open stash") {
            NSApp.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }
        Divider()
        if case .unlocked = model.screen {
            Button("Lock") { Task { await model.lock() } }
        } else {
            Button("Unlock with Touch ID") { Task { await model.unlockWithTouchID() } }
        }
        Divider()
        Button("Quit stash") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage("clipboardSeconds") private var clipboardSeconds = 30.0
    @ViewState private var password = ""
    @ViewState private var message: String?

    var body: some View {
        Form {
            Section("Clipboard") {
                HStack {
                    Slider(value: $clipboardSeconds, in: 10...120, step: 5)
                    Text("\(Int(clipboardSeconds))s").font(.mono(12)).frame(width: 40)
                }
                Text("Copied secrets are cleared after this long, marked concealed so clipboard managers skip them, and kept off your other devices.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Touch ID") {
                if model.status?.touchIdEnabled == true {
                    Label("Touch ID unlock is on", systemImage: "touchid")
                } else if model.status?.touchIdAvailable == true {
                    SecureField("Master password", text: $password)
                    Button("Turn On Touch ID") {
                        Task {
                            do {
                                try await model.backend?.enableTouchID(password: password)
                                password = ""
                                model.status = try? await model.backend?.status()
                                message = nil
                            } catch {
                                message = error.localizedDescription
                            }
                        }
                    }
                    .disabled(password.isEmpty)
                    if let message { Text(message).foregroundStyle(.red).font(.caption) }
                } else {
                    Text("Touch ID isn't available on this Mac.").foregroundStyle(.secondary)
                }
            }
            Section("AI agents (MCP)") {
                Text("claude mcp add stash -- stash mcp --allow 'github/*'")
                    .font(.mono(12))
                    .textSelection(.enabled)
                Text("Agents can use your secrets without seeing them. Every use asks for your fingerprint.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Vault") {
                LabeledContent("Location", value: model.status?.vaultPath ?? "—")
                LabeledContent("Version", value: model.status?.version ?? "—")
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 520)
        .onChange(of: clipboardSeconds, initial: true) { Clipboard.clearAfter = clipboardSeconds }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model: AppModel
    var quickAccess: QuickAccessController?
    private var hotKey: HotKey?
    private let options = LaunchOptions.parse()

    override init() {
        BrandFonts.register()
        if options.mock {
            model = AppModel(backend: MockBackend(locked: options.locked))
        } else {
            model = AppModel(backend: try? RPCBackend())
        }
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        switch options.appearance {
        case "light": NSApp.appearance = NSAppearance(named: .aqua)
        case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
        default: break
        }
        quickAccess = QuickAccessController(model: model)
        hotKey = HotKey(keyCode: UInt32(kVK_Space), modifiers: UInt32(cmdKey | shiftKey), id: 1) { [weak self] in
            self?.quickAccess?.toggle()
        }
        if let path = options.snapshot {
            Task { await snapshot(to: path) }
        }
        if options.selftest {
            Task { await selftest() }
        }
    }

    /// `--selftest`: exercise every backend call against a throwaway vault
    /// (STASH_VAULT must point at one) and print the results. Checks that the
    /// Swift client and the Rust backend agree on the protocol.
    private func selftest() async {
        func say(_ s: String) { print(s); fflush(stdout) }
        guard let vault = ProcessInfo.processInfo.environment["STASH_VAULT"], !vault.isEmpty,
              !vault.hasSuffix("/.stash/vault.db") else {
            say("selftest: refusing to run without STASH_VAULT pointing at a throwaway vault")
            exit(2)
        }
        do {
            let b = try RPCBackend()
            var s = try await b.status()
            say("status: exists=\(s.vaultExists) locked=\(s.locked) version=\(s.version)")
            if !s.vaultExists { try await b.createVault(password: "selftest-password") }
            try await b.lock()
            do {
                _ = try await b.list()
                say("FAIL: list worked while locked")
            } catch let e as BackendError where e.isLocked {
                say("locked list refused: ok")
            }
            try await b.unlock(password: "selftest-password")
            try await b.save(SaveRequest(name: "selftest/github", originalName: nil, kind: .login, fields: [
                .init(label: "username", kind: .text, value: "octocat"),
                .init(label: "password", kind: .concealed, value: "hunter2!"),
                .init(label: "website", kind: .url, value: "https://github.com"),
                .init(label: "one-time password", kind: .otp, value: "JBSWY3DPEHPK3PXP"),
            ], notes: "recovery codes"))
            let items = try await b.list()
            say("list: \(items.map { "\($0.name)[\($0.kind.rawValue) otp=\($0.hasOtp)]" })")
            let d = try await b.item("selftest/github")
            say("item fields: \(d.fields.map { "\($0.label)=\($0.value ?? "<hidden>")" }) notes=\(d.hasNotes)")
            say("reveal password: \(try await b.reveal("selftest/github", field: "password"))")
            let code = try await b.otp("selftest/github")
            say("otp: \(code.code.count) digits, \(code.remaining)s left")
            try await b.save(SaveRequest(name: "selftest/github", originalName: "selftest/github", kind: .login, fields: [
                .init(label: "username", kind: .text, value: "hubot"),
                .init(label: "password", kind: .concealed, value: nil),
            ], notes: nil))
            say("after edit, password kept: \(try await b.reveal("selftest/github", field: "password"))")
            say("generate: \(try await b.generate(length: 20, symbols: false).count) chars")
            try await b.delete("selftest/github")
            s = try await b.status()
            say("selftest: ok (locked=\(s.locked))")
            exit(0)
        } catch {
            say("selftest: FAILED: \(error.localizedDescription)")
            exit(1)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// `--mock --snapshot out.png [--select NAME] [--locked] [--quick-access]`:
    /// render the window (with sample data, never your vault) and quit.
    private func snapshot(to path: String) async {
        try? await Task.sleep(for: .seconds(1.5))
        if let name = options.select { await model.select(name) }
        if options.quickAccessSnapshot { quickAccess?.show() }
        if let name = options.editor {
            if name == "new" {
                model.editor = .new(.login)
            } else if let detail = model.detail {
                model.editor = .edit(detail)
            }
        }
        try? await Task.sleep(for: .seconds(1.0))
        if !options.quickAccessSnapshot, let w = NSApp.windows.first(where: { $0.title == "stash" }) {
            w.setContentSize(NSSize(width: 1240, height: 760))
            try? await Task.sleep(for: .seconds(0.6))
        }
        let main = NSApp.windows.first { $0.title == "stash" && $0.isVisible }
        let window = options.quickAccessSnapshot
            ? NSApp.windows.first { $0 is QuickAccessPanel }
            : (options.editor != nil ? main?.attachedSheet : main)
        if let view = window?.contentView?.superview ?? window?.contentView,
           let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
            view.cacheDisplay(in: view.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        }
        NSApp.terminate(nil)
    }
}

struct LaunchOptions {
    var mock = false
    var locked = false
    var snapshot: String?
    var select: String?
    var quickAccessSnapshot = false
    var selftest = false
    var appearance: String?
    /// `new`, or `edit` (with --select).
    var editor: String?

    static func parse() -> LaunchOptions {
        var o = LaunchOptions()
        var args = CommandLine.arguments.dropFirst().makeIterator()
        while let arg = args.next() {
            switch arg {
            case "--mock": o.mock = true
            case "--locked": o.locked = true
            case "--snapshot": o.snapshot = args.next()
            case "--select": o.select = args.next()
            case "--quick-access": o.quickAccessSnapshot = true
            case "--selftest": o.selftest = true
            case "--appearance": o.appearance = args.next()
            case "--editor": o.editor = args.next()
            default: break
            }
        }
        return o
    }
}
