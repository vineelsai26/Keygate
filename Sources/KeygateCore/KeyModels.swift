import Foundation

public enum KeygateError: Error, CustomStringConvertible {
    case unsupportedKeyType(String)
    case keyNotFound
    case signingDenied(String)
    case invalidPrivateKey
    case keychainFailure(String)
    case notImplemented(String)
    case wrongPassphrase
    case unsupportedImportFormat
    case importFailed(String)
    case exportFailed(String)
    case vaultLocked

    public var description: String {
        switch self {
        case .unsupportedKeyType(let type):
            return "Unsupported key type: \(type)"
        case .keyNotFound:
            return "No matching key is available"
        case .signingDenied(let reason):
            return "Signing denied: \(reason)"
        case .invalidPrivateKey:
            return "Private key material is invalid"
        case .keychainFailure(let message):
            return "Keychain failure: \(message)"
        case .notImplemented(let message):
            return message
        case .wrongPassphrase:
            return "Incorrect passphrase, or the key is corrupt"
        case .unsupportedImportFormat:
            return "Unrecognized private key format"
        case .importFailed(let message):
            return "Key import failed: \(message)"
        case .exportFailed(let message):
            return "Key export failed: \(message)"
        case .vaultLocked:
            return "Keys are locked; unlock Keygate with your passphrase first"
        }
    }
}

public enum SSHKeyType: String, Codable, CaseIterable, Sendable {
    case ed25519 = "ssh-ed25519"
    case rsa = "ssh-rsa"
    case ecdsaP256 = "ecdsa-sha2-nistp256"
    case ecdsaP384 = "ecdsa-sha2-nistp384"
    case ecdsaP521 = "ecdsa-sha2-nistp521"

    /// SSH curve identifier embedded in ECDSA blobs (e.g. `nistp256`), nil for non-ECDSA.
    public var curveName: String? {
        switch self {
        case .ecdsaP256: return "nistp256"
        case .ecdsaP384: return "nistp384"
        case .ecdsaP521: return "nistp521"
        default: return nil
        }
    }

    public var isECDSA: Bool { curveName != nil }
    public var isRSA: Bool { self == .rsa }

    /// Prefix used for the per-key Keychain account name.
    public var accountPrefix: String {
        switch self {
        case .ed25519: return "ed25519"
        case .rsa: return "rsa"
        case .ecdsaP256: return "ecdsa-nistp256"
        case .ecdsaP384: return "ecdsa-nistp384"
        case .ecdsaP521: return "ecdsa-nistp521"
        }
    }
}

/// How a key's private material is protected on disk. Absent (nil) means the
/// raw material is stored unencrypted (owner-only file permissions); `passphrase`
/// means AES-256-GCM with a key derived from the vault passphrase.
public enum KeyEncryption: String, Codable, Sendable {
    case passphrase
}

public struct StoredKeyRecord: Codable, Equatable, Identifiable, Sendable {
    public var id: String { fingerprint }
    public let fingerprint: String
    public let keyType: SSHKeyType
    public var comment: String
    public let publicKey: Data
    public let keychainAccount: String
    public var isSynced: Bool
    public var createdAt: Date
    public var updatedAt: Date
    /// Encryption applied to the on-disk private material; nil = plaintext.
    public var encryption: KeyEncryption?

    public init(
        fingerprint: String,
        keyType: SSHKeyType,
        comment: String,
        publicKey: Data,
        keychainAccount: String,
        isSynced: Bool,
        createdAt: Date,
        updatedAt: Date,
        encryption: KeyEncryption? = nil
    ) {
        self.fingerprint = fingerprint
        self.keyType = keyType
        self.comment = comment
        self.publicKey = publicKey
        self.keychainAccount = keychainAccount
        self.isSynced = isSynced
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.encryption = encryption
    }

    /// The full SSH public-key wire blob. New records store it directly in
    /// `publicKey`; legacy Ed25519 records stored only the raw 32-byte public key,
    /// so those are wrapped on the fly to preserve their fingerprint.
    public var wireBlob: Data {
        if keyType == .ed25519 && publicKey.count == 32 {
            return SSHPublicKeyBlob.ed25519(publicKey)
        }
        return publicKey
    }

    public var agentIdentity: AgentIdentity {
        AgentIdentity(
            keyBlob: wireBlob,
            comment: comment,
            fingerprint: fingerprint,
            keyType: keyType.rawValue
        )
    }
}

public struct SignatureResult: Equatable {
    public let algorithm: String
    public let signature: Data

    public init(algorithm: String, signature: Data) {
        self.algorithm = algorithm
        self.signature = signature
    }
}

public protocol KeyVault {
    func listKeys() throws -> [StoredKeyRecord]
    func generate(_ type: SSHKeyType, comment: String, syncToCloud: Bool, rsaBits: Int) throws -> StoredKeyRecord
    func importPrivateKey(text: String, passphrase: String?, comment: String?, syncToCloud: Bool) throws -> StoredKeyRecord
    func rename(fingerprint: String, comment: String) throws -> StoredKeyRecord
    func delete(fingerprint: String) throws
    func setSync(fingerprint: String, syncToCloud: Bool) throws -> StoredKeyRecord
    func authorizedKeysLine(fingerprint: String) throws -> String
    func exportPrivateKey(fingerprint: String, format: KeyExportFormat, passphrase: String?) throws -> String
    func sign(keyBlob: Data, payload: Data, flags: UInt32) throws -> SignatureResult
    /// True when passphrase encryption is enabled and the session key is not cached.
    /// Default is unlocked; file-backed vaults override this.
    func isLocked() -> Bool
}

public extension KeyVault {
    func generate(_ type: SSHKeyType, comment: String, syncToCloud: Bool) throws -> StoredKeyRecord {
        try generate(type, comment: comment, syncToCloud: syncToCloud, rsaBits: SSHSigner.defaultRSABits)
    }

    /// Back-compat shim: Ed25519 is the historical default.
    func generateEd25519(comment: String, syncToCloud: Bool) throws -> StoredKeyRecord {
        try generate(.ed25519, comment: comment, syncToCloud: syncToCloud)
    }

    func isLocked() -> Bool { false }
}

public extension Notification.Name {
    /// Posted when a sign request is refused because the vault is locked.
    /// The app should present the unlock sheet so the user can enter the passphrase.
    static let keygateVaultNeedsUnlock = Notification.Name("dev.vstack.keygate.vaultNeedsUnlock")
}
