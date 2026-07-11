import Foundation
import Security

/// Stores the vault passphrase in the login Keychain so Keygate can unlock with
/// Touch ID (via `LocalAuthorizer`) without re-typing the passphrase each session.
///
/// Private key material stays file-backed; only the vault passphrase is stored
/// here. Access control is enforced in-app with LocalAuthentication before
/// `load()` is called — Keychain ACL biometry is unreliable for ad-hoc /
/// self-signed builds, which is why Keygate already gates signing that way.
public enum VaultPassphraseStore {
    public static let service = "dev.vstack.keygate.vault-passphrase"
    public static let account = "vault"

    public enum StoreError: Error, CustomStringConvertible {
        case keychain(OSStatus)
        case encoding

        public var description: String {
            switch self {
            case .keychain(let status):
                return "Keychain error (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? "unknown")"
            case .encoding:
                return "Could not encode or decode the vault passphrase"
            }
        }
    }

    /// True when a passphrase item exists (does not prompt or return the secret).
    public static func isStored(serviceName: String = service, accountName: String = account) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Saves or replaces the stored passphrase. Call only after a successful vault unlock.
    public static func save(_ passphrase: String, serviceName: String = service, accountName: String = account) throws {
        guard let data = passphrase.data(using: .utf8) else { throw StoreError.encoding }
        // Replace any previous item so toggles / passphrase changes stay clean.
        delete(serviceName: serviceName, accountName: accountName)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecAttrLabel as String: "Keygate Vault Passphrase",
            kSecAttrDescription as String: "Unlocks the encrypted Keygate vault",
            kSecValueData as String: data,
            // Device-local only; not in iCloud Keychain.
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw StoreError.keychain(status) }
    }

    /// Returns the stored passphrase, or `nil` when none is stored.
    /// Does **not** prompt for biometrics — the caller must gate with Touch ID first.
    public static func load(serviceName: String = service, accountName: String = account) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw StoreError.keychain(status) }
        guard let data = result as? Data, let passphrase = String(data: data, encoding: .utf8) else {
            throw StoreError.encoding
        }
        return passphrase
    }

    /// Removes the stored passphrase. Safe to call when nothing is stored.
    @discardableResult
    public static func delete(serviceName: String = service, accountName: String = account) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
