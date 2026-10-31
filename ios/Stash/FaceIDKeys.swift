// Face ID unlock, the same way the Mac's Touch ID helper does it
// (swift/stash-touchid): the vault's keys are encrypted to a Secure
// Enclave key that only works after a Face ID match on this device
// (`biometryCurrentSet`), so enrolling a new face makes the saved keys
// unusable until you unlock with the password again. The Secure Enclave key
// never leaves the chip; the encrypted blob sits in the app's private
// storage with complete file protection.

import CryptoKit
import Foundation
import LocalAuthentication

enum FaceIDKeys {
    private static let info = Data("stash/ios-faceid-wrap/v1".utf8)

    static var file: URL {
        URL.applicationSupportDirectory.appending(path: "faceid.keys")
    }

    /// Face ID (or Touch ID) and a Secure Enclave are there to use.
    static var available: Bool {
        var error: NSError?
        return SecureEnclave.isAvailable
            && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    static var enrolled: Bool { FileManager.default.fileExists(atPath: file.path) }

    private static func wrappingKey(_ shared: SharedSecret, ephemeral: Data, recipient: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral + recipient, sharedInfo: info, outputByteCount: 32)
    }

    /// Save `keys` (64 bytes) so Face ID can unlock them.
    static func enroll(_ keys: Data) throws {
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfError)
        else { throw VaultError(message: "Face ID couldn't be set up") }
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let ephemeralPub = ephemeral.publicKey.x963Representation
        let key = wrappingKey(shared, ephemeral: ephemeralPub, recipient: seKey.publicKey.x963Representation)
        let sealed = try ChaChaPoly.seal(keys, using: key).combined
        let handle = seKey.dataRepresentation
        var blob = Data([UInt8(handle.count >> 8), UInt8(handle.count & 0xff)])
        blob += handle + ephemeralPub + sealed
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try blob.write(to: file, options: [.atomic, .completeFileProtection])
        try PhoneModel.protect(file)
    }

    /// Ask for Face ID, then decrypt the saved keys. Throws `cancelled`
    /// when the person dismissed the prompt.
    static func unlock(reason: String) async throws -> Data {
        let blob = try Data(contentsOf: file)
        guard blob.count > 2 else { throw VaultError(message: "the Face ID data is damaged") }
        let handleLen = Int(blob[0]) << 8 | Int(blob[1])
        let pubStart = 2 + handleLen
        let boxStart = pubStart + 65
        guard blob.count > boxStart else { throw VaultError(message: "the Face ID data is damaged") }
        let handle = blob.subdata(in: 2..<pubStart)
        let ephemeralPub = blob.subdata(in: pubStart..<boxStart)
        let sealed = blob.subdata(in: boxStart..<blob.count)

        let context = LAContext()
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError where [.userCancel, .appCancel, .systemCancel, .userFallback].contains(error.code) {
            throw CancellationError()
        }
        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: handle, authenticationContext: context)
        } catch {
            // A face was added or removed since: the password is needed again.
            forget()
            throw VaultError(message: "Face ID changed on this iPhone. Unlock with the password to turn it back on.")
        }
        let shared = try seKey.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: ephemeralPub))
        let key = wrappingKey(shared, ephemeral: ephemeralPub, recipient: seKey.publicKey.x963Representation)
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: sealed), using: key)
    }

    static func forget() {
        try? FileManager.default.removeItem(at: file)
    }
}
