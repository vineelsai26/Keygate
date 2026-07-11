import Foundation
#if canImport(CBcryptPBKDF)
import CBcryptPBKDF
#endif

/// `bcrypt_pbkdf` key-derivation used by encrypted `openssh-key-v1` files.
///
/// There is no system API for this KDF, so it is backed by the vendored
/// `CBcryptPBKDF` C target. When that target is not present in the build, encrypted
/// OpenSSH import reports a clear, actionable error (unencrypted OpenSSH keys and
/// all PEM keys — including encrypted PEM via `SecItemImport` — still import).
public enum Bcrypt {
    public static var isAvailable: Bool {
        #if canImport(CBcryptPBKDF)
        return true
        #else
        return false
        #endif
    }

    public static func pbkdf(passphrase: Data, salt: Data, rounds: UInt32, length: Int) throws -> Data {
        #if canImport(CBcryptPBKDF)
        guard !passphrase.isEmpty, !salt.isEmpty, length > 0 else {
            throw KeygateError.wrongPassphrase
        }
        var output = [UInt8](repeating: 0, count: length)
        let result = passphrase.withUnsafeBytes { passBuffer in
            salt.withUnsafeBytes { saltBuffer in
                keygate_bcrypt_pbkdf(
                    passBuffer.bindMemory(to: UInt8.self).baseAddress,
                    passphrase.count,
                    saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                    salt.count,
                    &output,
                    length,
                    rounds
                )
            }
        }
        guard result == 0 else { throw KeygateError.importFailed("bcrypt_pbkdf failed (\(result))") }
        return Data(output)
        #else
        throw KeygateError.importFailed(
            "Encrypted OpenSSH keys require the bcrypt component, which is not built. "
            + "Import an unencrypted key, a PEM key, or rebuild Keygate with the CBcryptPBKDF target."
        )
        #endif
    }
}
