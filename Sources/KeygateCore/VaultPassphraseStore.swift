import Foundation
import Security
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// Stores the vault passphrase in the login Keychain so Keygate can unlock with
/// Touch ID without re-typing the passphrase each session.
///
/// The item is bound to a biometric / user-presence access control in the
/// data-protection Keychain: the Keychain itself refuses to release the secret
/// without a fresh Touch ID (or login-password) result. Retrieval is *not*
/// gated by app-side control flow alone, so a same-user attacker who reads the
/// item with `SecItemCopyMatching` is met by the system authentication prompt
/// rather than plaintext.
///
/// Storage is fail-closed: if a biometric access control cannot be created or
/// the data-protection Keychain is unavailable (some ad-hoc / self-signed
/// builds), `save` throws instead of writing an unprotected plaintext item, and
/// the user simply retypes the passphrase each session.
public enum VaultPassphraseStore {
    public static let service = "dev.vstack.keygate.vault-passphrase"
    public static let account = "vault"

    public enum StoreError: Error, CustomStringConvertible {
        case keychain(OSStatus)
        case encoding
        case accessControl(OSStatus)
        case biometricsUnavailable
        case authenticationFailed

        public var description: String {
            switch self {
            case .keychain(let status):
                return "Keychain error (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? "unknown")"
            case .encoding:
                return "Could not encode or decode the vault passphrase"
            case .accessControl(let status):
                return "Could not create a biometric access control for the vault passphrase (\(status))"
            case .biometricsUnavailable:
                return "Touch ID or a device password is not available to unlock the vault passphrase"
            case .authenticationFailed:
                return "Touch ID was cancelled or failed"
            }
        }
    }

    /// Base query identifying the single generic-password item. Callers add the
    /// data-protection selector and any return/limit/auth attributes they need.
    private static func baseQuery(serviceName: String, accountName: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
        ]
    }

    /// A separate, non-secret item records that the protected passphrase exists.
    /// Looking up the protected item's attributes can itself trigger its
    /// user-presence ACL on macOS, so normal UI refreshes must query only this
    /// marker. The passphrase remains exclusively in the protected item.
    private static func markerQuery(serviceName: String, accountName: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(serviceName).presence",
            kSecAttrAccount as String: accountName,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private static func saveMarker(serviceName: String, accountName: String) throws {
        var query = markerQuery(serviceName: serviceName, accountName: accountName)
        query[kSecAttrLabel as String] = "Keygate Vault Passphrase Presence"
        query[kSecAttrDescription as String] = "Non-secret marker for Touch ID unlock availability"
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = Data([1])
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw StoreError.keychain(status)
        }
    }

    /// True when the non-secret presence marker exists. This query never touches
    /// the protected passphrase item and therefore cannot present Touch ID.
    public static func isStored(serviceName: String = service, accountName: String = account) -> Bool {
        var query = markerQuery(serviceName: serviceName, accountName: accountName)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Saves or replaces the stored passphrase, binding it to a biometric /
    /// user-presence access control. Call only after a successful vault unlock.
    ///
    /// Throws (rather than storing plaintext) when a protected item cannot be
    /// written, so there is never a code path that leaves the passphrase readable
    /// without an authentication challenge.
    public static func save(_ passphrase: String, serviceName: String = service, accountName: String = account) throws {
        guard let data = passphrase.data(using: .utf8) else { throw StoreError.encoding }
        // Replace any previous item — including a legacy unprotected item written
        // by older builds — so toggles / passphrase changes stay clean.
        delete(serviceName: serviceName, accountName: accountName)

        var accessError: Unmanaged<CFError>?
        // .userPresence = biometry with automatic device-password fallback, so it
        // also works on Macs without a Touch ID sensor. Device-local only.
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &accessError
        ) else {
            let status = (accessError?.takeRetainedValue()).map { OSStatus(CFErrorGetCode($0)) } ?? errSecParam
            throw StoreError.accessControl(status)
        }

        var query = baseQuery(serviceName: serviceName, accountName: accountName)
        query[kSecAttrLabel as String] = "Keygate Vault Passphrase"
        query[kSecAttrDescription as String] = "Unlocks the encrypted Keygate vault"
        query[kSecValueData as String] = data
        query[kSecAttrAccessControl as String] = access
        query[kSecUseDataProtectionKeychain as String] = true

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw StoreError.keychain(status) }
        try saveMarker(serviceName: serviceName, accountName: accountName)
    }

    /// Authenticates the user (Touch ID / login password) and returns the stored
    /// passphrase, or `nil` when none is stored.
    ///
    /// The biometric challenge is enforced by the Keychain item's own access
    /// control; a single freshly-authenticated `LAContext` is reused for the
    /// retrieval so the user is prompted exactly once.
    public static func loadWithAuthentication(reason: String, serviceName: String = service, accountName: String = account) throws -> String? {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password…"
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            throw StoreError.biometricsUnavailable
        }
        // Give the unauthenticated context to the Keychain. Because the item
        // owns a user-presence access control, SecItemCopyMatching performs the
        // one required authentication on this context. Calling evaluatePolicy
        // first would create a redundant system challenge before the Keychain
        // evaluates its own ACL.
        context.localizedReason = reason
        let passphrase = try load(context: context, serviceName: serviceName, accountName: accountName)
        // Older builds stored only the protected item. A successful interactive
        // read migrates them to the prompt-free presence marker.
        if passphrase != nil {
            try? saveMarker(serviceName: serviceName, accountName: accountName)
        }
        return passphrase
        #else
        return try load(serviceName: serviceName, accountName: accountName)
        #endif
    }

    /// Returns the stored passphrase, or `nil` when none is stored.
    ///
    /// Reading the protected data triggers the item's access control. Pass a
    /// pre-authenticated `LAContext` (see `loadWithAuthentication`) to satisfy it
    /// without a second prompt; with no context the Keychain presents the
    /// authentication UI itself.
    public static func load(context: Any? = nil, serviceName: String = service, accountName: String = account) throws -> String? {
        var query = baseQuery(serviceName: serviceName, accountName: accountName)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseDataProtectionKeychain as String] = true
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        if status == errSecUserCanceled || status == errSecAuthFailed { throw StoreError.authenticationFailed }
        guard status == errSecSuccess else { throw StoreError.keychain(status) }
        guard let data = result as? Data, let passphrase = String(data: data, encoding: .utf8) else {
            throw StoreError.encoding
        }
        return passphrase
    }

    /// True when an item exists but cannot be read without an authentication
    /// challenge — i.e. the biometric / user-presence access control is actually
    /// enforced by the Keychain. Used by self-tests to prove retrieval is gated
    /// rather than readable via a plain `SecItemCopyMatching`.
    public static func requiresAuthenticationToRead(serviceName: String = service, accountName: String = account) -> Bool {
        // First prove the non-secret presence marker exists. The following data
        // query suppresses UI and verifies the passphrase itself stays gated.
        guard isStored(serviceName: serviceName, accountName: accountName) else { return false }
        var query = baseQuery(serviceName: serviceName, accountName: accountName)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseDataProtectionKeychain as String] = true
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // Depending on the macOS release, a gated item with UI suppressed is
        // either interaction-not-allowed, authentication-failed, or filtered
        // out as item-not-found. An unprotected item returns errSecSuccess.
        return status == errSecInteractionNotAllowed
            || status == errSecAuthFailed
            || status == errSecItemNotFound
    }

    /// Removes the stored passphrase from both the data-protection Keychain and
    /// the legacy file-based Keychain (to purge unprotected items from older
    /// builds). Safe to call when nothing is stored.
    @discardableResult
    public static func delete(serviceName: String = service, accountName: String = account) -> Bool {
        let ok: (OSStatus) -> Bool = { $0 == errSecSuccess || $0 == errSecItemNotFound }

        var protected = baseQuery(serviceName: serviceName, accountName: accountName)
        protected[kSecUseDataProtectionKeychain as String] = true
        let protectedStatus = SecItemDelete(protected as CFDictionary)

        var legacy = baseQuery(serviceName: serviceName, accountName: accountName)
        legacy[kSecUseDataProtectionKeychain as String] = false
        let legacyStatus = SecItemDelete(legacy as CFDictionary)

        let markerStatus = SecItemDelete(
            markerQuery(serviceName: serviceName, accountName: accountName) as CFDictionary)

        return ok(protectedStatus) && ok(legacyStatus) && ok(markerStatus)
    }
}
