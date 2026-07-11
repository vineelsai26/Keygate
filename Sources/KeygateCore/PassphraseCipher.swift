import CommonCrypto
import CryptoKit
import Foundation

/// Passphrase-based encryption for on-disk private key material.
///
/// A 256-bit key is derived from the user's passphrase with PBKDF2-HMAC-SHA256,
/// then material is sealed with AES-256-GCM. The passphrase (and derived key)
/// never touch the Keychain or disk — the derived key lives only in memory for
/// the agent's session. This gives real at-rest encryption on a self-signed
/// build, where the Secure Enclave / data-protection Keychain is unavailable.
public enum PassphraseCipher {
    /// OWASP-recommended floor for PBKDF2-HMAC-SHA256 (2023).
    public static let defaultIterations = 600_000
    public static let saltLength = 16
    private static let keyLength = 32

    public static func randomSalt() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: saltLength)
        guard SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes) == errSecSuccess else {
            throw KeygateError.keychainFailure("secure random salt generation failed")
        }
        return Data(bytes)
    }

    public static func deriveKey(passphrase: String, salt: Data, iterations: Int) throws -> SymmetricKey {
        let passwordBytes = Array(passphrase.utf8)
        var derived = [UInt8](repeating: 0, count: keyLength)
        let status = passwordBytes.withUnsafeBufferPointer { passwordPtr in
            salt.withUnsafeBytes { saltPtr in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordPtr.baseAddress?.withMemoryRebound(to: Int8.self, capacity: passwordBytes.count) { $0 },
                    passwordBytes.count,
                    saltPtr.bindMemory(to: UInt8.self).baseAddress,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &derived,
                    keyLength
                )
            }
        }
        guard status == kCCSuccess else {
            throw KeygateError.keychainFailure("PBKDF2 key derivation failed (\(status))")
        }
        return SymmetricKey(data: Data(derived))
    }

    /// AES-256-GCM sealed box (nonce || ciphertext || tag).
    public static func encrypt(_ data: Data, key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else {
            throw KeygateError.keychainFailure("AES-GCM produced no combined box")
        }
        return combined
    }

    public static func decrypt(_ data: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: key)
    }
}

/// Persisted parameters describing how the vault passphrase derives its key,
/// plus a verifier used to detect a wrong passphrase without touching key files.
public struct VaultEncryptionConfig: Codable, Sendable {
    public var version: Int
    public var kdf: String
    public var iterations: Int
    public var salt: Data
    /// AES-GCM box of `verifierPlaintext`, sealed with the derived key.
    public var verifier: Data

    static let verifierPlaintext = Data("keygate-encryption-verifier-v1".utf8)

    public static func create(passphrase: String, iterations: Int = PassphraseCipher.defaultIterations) throws -> (config: VaultEncryptionConfig, key: SymmetricKey) {
        let salt = try PassphraseCipher.randomSalt()
        let key = try PassphraseCipher.deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)
        let verifier = try PassphraseCipher.encrypt(verifierPlaintext, key: key)
        let config = VaultEncryptionConfig(version: 1, kdf: "pbkdf2-sha256", iterations: iterations, salt: salt, verifier: verifier)
        return (config, key)
    }

    /// Derives the key for `passphrase` and confirms it matches this config.
    public func unlock(passphrase: String) throws -> SymmetricKey {
        let key = try PassphraseCipher.deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)
        guard let plaintext = try? PassphraseCipher.decrypt(verifier, key: key),
              plaintext == Self.verifierPlaintext else {
            throw KeygateError.wrongPassphrase
        }
        return key
    }
}
