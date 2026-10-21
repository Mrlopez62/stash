// stash-touchid: a tiny helper that protects the stash vault key with a
// Secure Enclave key that can only be used after a Touch ID match.
//
// The Secure Enclave key never leaves the chip. CryptoKit hands us an
// encrypted handle to it (`dataRepresentation`) that only this Mac's Secure
// Enclave can use, so nothing needs to be stored in the Keychain and no code
// signing entitlements are required.
//
// Usage (all I/O is on stdin/stdout so secrets never appear in argv):
//   stash-touchid available          exit 0 if Touch ID + Secure Enclave are usable
//   stash-touchid wrap               stdin: vault key (hex)  -> stdout: blob
//   stash-touchid unwrap <reason>    stdin: blob             -> stdout: vault key (hex)
//   stash-touchid confirm <reason>   fingerprint check only; exit 0 if approved
//   stash-touchid copy               stdin: a secret -> the clipboard, marked
//                                    concealed and transient, this Mac only
//   stash-touchid clear              empty the clipboard
//
// Exit codes: 0 ok, 1 error, 2 cancelled by the user, 3 Touch ID unavailable.
//
// Only the `stash` binary installed next to this helper may use it (checked
// from the kernel's view of who started us). The helper is usually inside
// stash-touchid.app (so macOS shows the stash icon and name on Touch ID
// prompts); then "next to" means next to the bundle. Otherwise any program could
// show a stash-branded Touch ID prompt with a reason of its choosing and,
// if you approved, receive the vault key.

import AppKit
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication

let blobPrefix = "stash-touchid-v1:"
let hkdfInfo = Data("stash/touchid-wrap/v1".utf8)

struct Failure: Error {
    let message: String
    let code: Int32
    init(_ message: String, code: Int32 = 1) {
        self.message = message
        self.code = code
    }
}

func readStdin() -> String {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

func hexDecode(_ hex: String) throws -> Data {
    guard hex.count % 2 == 0 else { throw Failure("invalid hex input") }
    var out = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else { throw Failure("invalid hex input") }
        out.append(byte)
        index = next
    }
    return out
}

func hexEncode(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func checkAvailable() throws {
    guard SecureEnclave.isAvailable else { throw Failure("this Mac has no Secure Enclave", code: 3) }
    var error: NSError?
    guard LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        throw Failure("Touch ID is not available: \(error?.localizedDescription ?? "unknown reason")", code: 3)
    }
}

func wrappingKey(_ shared: SharedSecret, ephemeral: Data, recipient: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: ephemeral + recipient, sharedInfo: hkdfInfo, outputByteCount: 32)
}

/// Blob layout (base64 after the prefix):
/// u16 BE length of SE key handle | SE key handle | ephemeral public key (x963, 65 bytes) | ChaChaPoly box
func wrap() throws {
    try checkAvailable()
    let vaultKey = try hexDecode(readStdin())
    // The main key, or the main and sensitive keys together (version 3).
    guard vaultKey.count == 32 || vaultKey.count == 64 else { throw Failure("vault keys must be 32 or 64 bytes") }

    var cfError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfError)
    else { throw Failure("could not create access control: \(String(describing: cfError?.takeRetainedValue()))") }

    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
    let ephemeralPub = ephemeral.publicKey.x963Representation
    let key = wrappingKey(shared, ephemeral: ephemeralPub, recipient: seKey.publicKey.x963Representation)
    let sealed = try ChaChaPoly.seal(vaultKey, using: key).combined

    let handle = seKey.dataRepresentation
    var blob = Data([UInt8(handle.count >> 8), UInt8(handle.count & 0xff)])
    blob += handle + ephemeralPub + sealed
    print(blobPrefix + blob.base64EncodedString())
}

func authenticate(reason: String) throws -> LAContext {
    let context = LAContext()
    let done = DispatchSemaphore(value: 0)
    var result: Result<Void, Error> = .failure(Failure("Touch ID did not respond"))
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
        result = ok ? .success(()) : .failure(error ?? Failure("Touch ID failed"))
        done.signal()
    }
    done.wait()
    do {
        try result.get()
    } catch let error as LAError {
        switch error.code {
        case .userCancel, .appCancel, .systemCancel, .userFallback:
            throw Failure("Touch ID was cancelled", code: 2)
        case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout:
            throw Failure("Touch ID is not available: \(error.localizedDescription)", code: 3)
        default:
            throw Failure("Touch ID failed: \(error.localizedDescription)")
        }
    }
    return context
}

func unwrap(reason: String) throws {
    let text = readStdin()
    guard text.hasPrefix(blobPrefix), let blob = Data(base64Encoded: String(text.dropFirst(blobPrefix.count))),
        blob.count > 2
    else { throw Failure("unrecognized Touch ID blob") }
    let handleLen = Int(blob[0]) << 8 | Int(blob[1])
    let pubStart = 2 + handleLen
    let boxStart = pubStart + 65
    guard blob.count > boxStart else { throw Failure("truncated Touch ID blob") }
    let handle = blob.subdata(in: 2..<pubStart)
    let ephemeralPub = blob.subdata(in: pubStart..<boxStart)
    let sealed = blob.subdata(in: boxStart..<blob.count)

    try checkAvailable()
    let context = try authenticate(reason: reason)
    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: handle, authenticationContext: context)
    } catch {
        // Happens when fingerprints were added or removed since enrollment.
        throw Failure("Touch ID key is no longer valid; run `stash touchid enable` again", code: 3)
    }
    let shared = try seKey.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: ephemeralPub))
    let key = wrappingKey(shared, ephemeral: ephemeralPub, recipient: seKey.publicKey.x963Representation)
    let vaultKey = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: sealed), using: key)
    print(hexEncode(vaultKey))
}

/// Copy a secret the way the stash app does: marked concealed and transient
/// (nspasteboard.org conventions) so clipboard-history apps skip it, and
/// kept on this Mac (no Universal Clipboard). `pbcopy` can do neither.
func copySecret() throws {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard let value = String(data: data, encoding: .utf8) else {
        throw Failure("only text can be copied")
    }
    let pb = NSPasteboard.general
    pb.prepareForNewContents(with: .currentHostOnly)
    let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    pb.declareTypes([.string, concealed, transient], owner: nil)
    guard pb.setString(value, forType: .string),
          pb.setString("", forType: concealed),
          pb.setString("", forType: transient)
    else {
        throw Failure("couldn't write to the clipboard")
    }
}

/// The executable of process `pid`, with symlinks resolved.
func executable(of pid: pid_t) -> URL? {
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
    return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath()
}

/// Is the process that started us the `stash` next to this helper (or next
/// to the app bundle it's in)?
func calledByStash() -> Bool {
    guard let me = executable(of: getpid()), let parent = executable(of: getppid()) else { return false }
    var dir = me.deletingLastPathComponent()
    // …/stash-touchid.app/Contents/MacOS/stash-touchid
    if dir.lastPathComponent == "MacOS",
       dir.deletingLastPathComponent().lastPathComponent == "Contents",
       dir.deletingLastPathComponent().deletingLastPathComponent().pathExtension == "app" {
        dir = dir.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }
    let sibling = dir.appendingPathComponent("stash").resolvingSymlinksInPath()
    return parent == sibling
}

// Keys pass through this process: no debugger may attach to it
// (ptrace(PT_DENY_ATTACH), which Swift doesn't import directly).
typealias PtraceFunction = @convention(c) (CInt, pid_t, UnsafeMutablePointer<CChar>?, CInt) -> CInt
if let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace") {
    let ptraceDenyAttach: CInt = 31
    _ = unsafeBitCast(symbol, to: PtraceFunction.self)(ptraceDenyAttach, 0, nil, 0)
}

let args = CommandLine.arguments.dropFirst()
do {
    if args.first != "available" && !calledByStash() {
        throw Failure("only the stash command next to this helper can use it")
    }
    switch args.first {
    case "available":
        try checkAvailable()
    case "wrap":
        try wrap()
    case "unwrap":
        try unwrap(reason: args.dropFirst().first ?? "unlock your stash vault")
    case "confirm":
        try checkAvailable()
        _ = try authenticate(reason: args.dropFirst().first ?? "approve a stash request")
    case "copy":
        try copySecret()
    case "clear":
        NSPasteboard.general.clearContents()
    default:
        throw Failure("usage: stash-touchid available | wrap | unwrap <reason> | confirm <reason> | copy | clear")
    }
} catch let failure as Failure {
    FileHandle.standardError.write(Data("stash-touchid: \(failure.message)\n".utf8))
    exit(failure.code)
} catch {
    FileHandle.standardError.write(Data("stash-touchid: \(error)\n".utf8))
    exit(1)
}
