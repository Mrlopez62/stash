// Scanning a two-factor QR code with the camera. The camera runs only while
// this screen is open, nothing is recorded, and only a code the vault's core
// accepts gets past it.

import AVFoundation
import SwiftUI

struct QRScannerView: View {
    /// A code the core accepted.
    let found: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var access = QRScannerView.currentAccess
    @State private var problem: String?
    /// The last code refused, so holding it in view doesn't repeat the work.
    @State private var refused: String?

    private enum Access { case unknown, allowed, denied, noCamera }

    private static var currentAccess: Access {
        #if DEBUG
        // Simulator checks only (never in release builds): it has no camera.
        if ProcessInfo.processInfo.environment["STASH_SIM_SCAN"] == "viewfinder" { return .allowed }
        #endif
        guard AVCaptureDevice.default(for: .video) != nil else { return .noCamera }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return .allowed
        case .notDetermined: return .unknown
        default: return .denied
        }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                switch access {
                case .allowed:
                    QRCamera(onCode: handle).ignoresSafeArea()
                    viewfinder
                case .unknown:
                    ProgressView().tint(.white)
                case .denied:
                    message("Camera access is off", "Turn it on in Settings to scan QR codes, or go back and paste the setup key.") {
                        Button("Open Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.keyholeAmber)
                        .foregroundStyle(Color.vaultInk)
                    }
                case .noCamera:
                    message("No camera available", "Go back and paste the setup key instead.") { EmptyView() }
                }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.tint(.white)
                }
            }
        }
        .task {
            guard access == .unknown else { return }
            access = await AVCaptureDevice.requestAccess(for: .video) ? .allowed : .denied
        }
    }

    private var viewfinder: some View {
        VStack(spacing: 22) {
            Spacer()
            ViewfinderCorners()
                .stroke(Color.keyholeAmber, style: StrokeStyle(lineWidth: 4, lineCap: .round, lineJoin: .round))
                .frame(width: 250, height: 250)
            Group {
                if let problem {
                    Label(problem, systemImage: "exclamationmark.circle.fill")
                } else {
                    Text("Point the camera at the QR code from the site's 2FA setup.")
                }
            }
            .font(.plex(15, weight: .medium))
            .foregroundStyle(.white)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 16).padding(.vertical, 10)
            .background(.black.opacity(0.6), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .padding(.horizontal, 28)
            Spacer()
        }
    }

    private func message(_ title: String, _ detail: String, @ViewBuilder action: () -> some View) -> some View {
        VStack(spacing: 12) {
            Text(title).font(.plex(18, weight: .semibold)).foregroundStyle(.white)
            Text(detail).font(.plex(15)).foregroundStyle(.white.opacity(0.75)).multilineTextAlignment(.center)
            action().padding(.top, 8)
        }
        .padding(32)
    }

    private func handle(_ code: String) {
        guard code != refused else { return }
        if code.hasPrefix("otpauth-migration:") {
            refused = code
            problem = "That's an export from another app. Scan the QR code from the site itself."
            return
        }
        do {
            try VaultCore.checkOTP(code)
            found(code)
        } catch {
            refused = code
            problem = "That QR code isn't a 2FA setup code."
        }
    }

    /// The site and account a code names: `otpauth://totp/GitHub:me@x.com?issuer=GitHub`.
    static func label(in code: String) -> (issuer: String?, account: String?) {
        guard code.hasPrefix("otpauth://"), let url = URLComponents(string: code) else { return (nil, nil) }
        let path = url.path.drop { $0 == "/" }
        let parts = path.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        let named = url.queryItems?.first { $0.name == "issuer" }?.value
        let issuer = named ?? (parts.count == 2 ? parts[0] : nil)
        return (issuer.flatMap { $0.isEmpty ? nil : $0 }, parts.last.flatMap { $0.isEmpty ? nil : $0 })
    }
}

private struct ViewfinderCorners: Shape {
    func path(in r: CGRect) -> Path {
        let arm: CGFloat = 34
        var p = Path()
        for (corner, dx, dy) in [(CGPoint(x: r.minX, y: r.minY), 1.0, 1.0), (CGPoint(x: r.maxX, y: r.minY), -1.0, 1.0),
                                 (CGPoint(x: r.minX, y: r.maxY), 1.0, -1.0), (CGPoint(x: r.maxX, y: r.maxY), -1.0, -1.0)] {
            p.move(to: CGPoint(x: corner.x + arm * dx, y: corner.y))
            p.addLine(to: corner)
            p.addLine(to: CGPoint(x: corner.x, y: corner.y + arm * dy))
        }
        return p
    }
}

/// The live camera, reporting QR codes as they're seen.
private struct QRCamera: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> QRCameraController {
        QRCameraController(onCode: onCode)
    }

    func updateUIViewController(_ controller: QRCameraController, context: Context) {
        controller.onCode = onCode
    }
}

private final class QRCameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: (String) -> Void
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "stash.qr-camera")
    private var preview: AVCaptureVideoPreviewLayer?

    init(onCode: @escaping (String) -> Void) {
        self.onCode = onCode
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("not used") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let camera = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: camera),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let session = session
        queue.async { session.startRunning() }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = session
        queue.async { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        for case let code as AVMetadataMachineReadableCodeObject in objects {
            if let value = code.stringValue { onCode(value) }
        }
    }
}
