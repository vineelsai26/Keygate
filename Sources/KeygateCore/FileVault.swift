import CryptoKit
import Foundation
import Security

/// File-backed key vault. Passphrase-encrypted private material lives in
/// individual `0600` files under `KeygatePaths.keysDirectory`.
///
/// Storing in the Keychain ties each item to the creating binary's code
/// signature, so a locally/self-signed app that is rebuilt often keeps being
/// treated as "a different app" and re-prompts for the login password on every
/// use. Files avoid that entirely while keeping the same on-disk protection
/// model OpenSSH uses for its own `~/.ssh` private keys (owner-only file
/// permissions). New private material is never written until vault encryption
/// is configured; legacy plaintext files can only be read during migration.
/// Signing and export remain gated by Touch ID through the app-level authorizer.
public final class FileVault: KeyVault, @unchecked Sendable {
    /// Prefixes newly-encrypted files so their protection can be identified from
    /// the file itself. This keeps interrupted metadata updates recoverable.
    private static let encryptedFileMagic = Data([0x4B, 0x47, 0x45, 0x31]) // KGE1
    private let metadataURL: URL
    private let keysDirectory: URL
    private let encryptionConfigURL: URL
    private let authorizer: SigningAuthorizer
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private let stateLock = NSLock()
    /// Serializes read-modify-write metadata changes and key-file migrations.
    /// Agent requests arrive on concurrent socket queues, while the UI and CLI
    /// can mutate the same vault independently.
    private let operationLock = NSRecursiveLock()
    /// Derived key cached for the session while the vault is unlocked; nil = locked.
    private var unlockedKey: SymmetricKey?

    public init(
        metadataURL: URL = KeygatePaths.metadataURL,
        keysDirectory: URL = KeygatePaths.keysDirectory,
        encryptionConfigURL: URL = KeygatePaths.encryptionConfigURL,
        authorizer: SigningAuthorizer = LocalAuthorizer()
    ) {
        self.metadataURL = metadataURL
        self.keysDirectory = keysDirectory
        self.encryptionConfigURL = encryptionConfigURL
        self.authorizer = authorizer
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    // MARK: Passphrase encryption

    /// True once a vault passphrase has been set.
    public func encryptionEnabled() -> Bool {
        FileManager.default.fileExists(atPath: encryptionConfigURL.path)
    }

    /// True when encryption is enabled but the derived key is not in memory.
    public func isLocked() -> Bool {
        guard encryptionEnabled() else { return false }
        // Keep the agent path consistent with non-interactive CLI use. A valid
        // KEYGATE_PASSPHRASE unlocks lazily and should not be rejected first.
        return currentKey() == nil
    }

    /// Turns on passphrase encryption and re-encrypts every existing key with it.
    public func enableEncryption(passphrase: String) throws {
        operationLock.lock(); defer { operationLock.unlock() }
        guard !passphrase.isEmpty else { throw KeygateError.wrongPassphrase }

        if encryptionEnabled() {
            // A previous migration may have been interrupted. Retain its config
            // and resume instead of deleting the only material needed to unlock
            // already-converted files.
            try unlock(passphrase: passphrase)
            try reencryptAllKeys()
            return
        }

        let (config, key) = try VaultEncryptionConfig.create(passphrase: passphrase)
        try saveEncryptionConfig(config)
        stateLock.lock(); unlockedKey = key; stateLock.unlock()
        // Do not roll back the config on a partial conversion. Files carry a
        // self-identifying envelope and metadata is updated per file, so the
        // vault remains readable and this method can resume on the next call.
        try reencryptAllKeys()
    }

    /// Caches the derived key for the session; throws `wrongPassphrase` on mismatch.
    public func unlock(passphrase: String) throws {
        operationLock.lock(); defer { operationLock.unlock() }
        let config = try loadEncryptionConfig()
        let key = try config.unlock(passphrase: passphrase)
        stateLock.lock(); unlockedKey = key; stateLock.unlock()
    }

    /// Forgets the cached key; the vault becomes locked again.
    public func lock() {
        stateLock.lock(); unlockedKey = nil; stateLock.unlock()
    }

    private func currentKey() -> SymmetricKey? {
        stateLock.lock(); defer { stateLock.unlock() }
        if let unlockedKey { return unlockedKey }
        // Non-interactive fallback (CLI/scripts): unlock from an env var if set.
        guard encryptionEnabled(), let passphrase = ProcessInfo.processInfo.environment["KEYGATE_PASSPHRASE"] else {
            return nil
        }
        guard let config = try? loadEncryptionConfig(), let key = try? config.unlock(passphrase: passphrase) else {
            return nil
        }
        unlockedKey = key
        return key
    }

    private func reencryptAllKeys() throws {
        for record in try loadMetadata() where record.encryption != .passphrase {
			let material = try readPrivateKey(record: record, allowPlaintextMigration: true)
            let encryption = try writePrivateKey(material, account: record.keychainAccount)
            try updateEncryption(fingerprint: record.fingerprint, to: encryption)
        }
    }

    private func loadEncryptionConfig() throws -> VaultEncryptionConfig {
        let data = try Data(contentsOf: encryptionConfigURL)
        return try decoder.decode(VaultEncryptionConfig.self, from: data)
    }

    private func saveEncryptionConfig(_ config: VaultEncryptionConfig) throws {
        try ensurePrivateDirectory(encryptionConfigURL.deletingLastPathComponent())
        try encoder.encode(config).write(to: encryptionConfigURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: encryptionConfigURL.path)
    }

    public func listKeys() throws -> [StoredKeyRecord] {
        operationLock.lock(); defer { operationLock.unlock() }
        return try loadMetadata()
    }

    public func generate(_ type: SSHKeyType, comment: String, syncToCloud: Bool, rsaBits: Int) throws -> StoredKeyRecord {
        operationLock.lock(); defer { operationLock.unlock() }
		try requireUnlockedEncryption()
        let generated = try SSHSigner.generate(type, rsaBits: rsaBits)
        return try store(
            keyType: type,
            privateMaterial: generated.privateMaterial,
            publicBlob: generated.publicBlob,
            comment: comment,
            syncToCloud: syncToCloud
        )
    }

    public func importPrivateKey(text: String, passphrase: String?, comment: String?, syncToCloud: Bool) throws -> StoredKeyRecord {
        operationLock.lock(); defer { operationLock.unlock() }
		try requireUnlockedEncryption()
        let imported = try KeyImporter.parse(text: text, passphrase: passphrase)
        let publicBlob = try SSHSigner.publicBlob(type: imported.keyType, privateMaterial: imported.privateMaterial)
        let resolvedComment = (comment?.isEmpty == false ? comment : nil) ?? imported.comment ?? ""
        return try store(
            keyType: imported.keyType,
            privateMaterial: imported.privateMaterial,
            publicBlob: publicBlob,
            comment: resolvedComment,
            syncToCloud: syncToCloud
        )
    }

    public func rename(fingerprint: String, comment: String) throws -> StoredKeyRecord {
        operationLock.lock(); defer { operationLock.unlock() }
        var records = try loadMetadata()
        guard let index = records.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        records[index].comment = comment.isEmpty ? fingerprint : comment
        records[index].updatedAt = Date()
        let updated = records[index]
        try saveMetadata(records.sorted { $0.comment < $1.comment })
        return updated
    }

    public func delete(fingerprint: String) throws {
        operationLock.lock(); defer { operationLock.unlock() }
        let records = try loadMetadata()
        guard let record = records.first(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        // Commit metadata first. A crash after this point may leave an orphaned
        // private file, but cannot leave a listed key with its material deleted.
        try saveMetadata(records.filter { $0.fingerprint != fingerprint })
        do {
            try deletePrivateKey(account: record.keychainAccount)
        } catch {
            // Restore the visible record when file removal fails.
            try? saveMetadata(records)
            throw error
        }
    }

    public func setSync(fingerprint: String, syncToCloud: Bool) throws -> StoredKeyRecord {
        operationLock.lock(); defer { operationLock.unlock() }
        var records = try loadMetadata()
        guard let index = records.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        // File storage is local-only; the flag is retained for the record/UI but
        // no longer moves material into the synchronizable Keychain.
        records[index].isSynced = syncToCloud
        records[index].updatedAt = Date()
        try saveMetadata(records)
        return records[index]
    }

    public func authorizedKeysLine(fingerprint: String) throws -> String {
        operationLock.lock(); defer { operationLock.unlock() }
        guard let record = try loadMetadata().first(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        let base64 = record.wireBlob.base64EncodedString()
        let suffix = record.comment.isEmpty ? "" : " \(record.comment)"
        return "\(record.keyType.rawValue) \(base64)\(suffix)"
    }

    public func exportPrivateKey(fingerprint: String, format: KeyExportFormat, passphrase: String?) throws -> String {
        operationLock.lock(); defer { operationLock.unlock() }
        guard let record = try loadMetadata().first(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        // Exporting reveals private key material, so require explicit approval up front.
        let label = record.comment.isEmpty ? record.fingerprint : record.comment
        guard authorizer.authorize(reason: "authorize exporting the private key “\(label)”") else {
            throw KeygateError.signingDenied("Export was not authorized")
        }
        let material = try readPrivateKey(record: record)
        return try KeyExporter.export(
            type: record.keyType,
            privateMaterial: material,
            comment: record.comment,
            format: format,
            passphrase: passphrase
        )
    }

    public func sign(keyBlob: Data, payload: Data, flags: UInt32) throws -> SignatureResult {
        operationLock.lock(); defer { operationLock.unlock() }
        guard let record = try loadMetadata().first(where: { $0.agentIdentity.keyBlob == keyBlob }) else {
            throw KeygateError.keyNotFound
        }
        let material = try readPrivateKey(record: record)
        return try SSHSigner.sign(type: record.keyType, privateMaterial: material, payload: payload, flags: flags)
    }

    // MARK: Storage

    private func store(keyType: SSHKeyType, privateMaterial: Data, publicBlob: Data, comment: String, syncToCloud: Bool) throws -> StoredKeyRecord {
        let fingerprint = Fingerprint.sha256(publicBlob)
        let account = "\(keyType.accountPrefix)-\(fingerprint.replacingOccurrences(of: ":", with: "-"))"

        let encryption = try writePrivateKey(privateMaterial, account: account)

        var records = try loadMetadata().filter { $0.fingerprint != fingerprint }
        let now = Date()
        let record = StoredKeyRecord(
            fingerprint: fingerprint,
            keyType: keyType,
            comment: comment.isEmpty ? fingerprint : comment,
            publicKey: publicBlob,
            keychainAccount: account,
            isSynced: syncToCloud,
            createdAt: now,
            updatedAt: now,
            encryption: encryption
        )
        records.append(record)
        try saveMetadata(records.sorted { $0.comment < $1.comment })
        return record
    }

    private func materialURL(account: String) -> URL {
        // Account names embed a base64 SHA256 fingerprint, which can contain '/'.
        // Replace it so the account maps to a single filename rather than a path.
        // ('/' is the only character illegal in an APFS filename; base64 never
        // emits '_', so this stays collision-free.)
        let safeName = account.replacingOccurrences(of: "/", with: "_")
        return keysDirectory.appendingPathComponent(safeName).appendingPathExtension("key")
    }

    /// Writes private material to its `0600` file, encrypting it with the vault
    /// passphrase when encryption is enabled. Returns the encryption actually
    /// applied so the caller can record it (reads need to know whether to unwrap).
    @discardableResult
    private func writePrivateKey(_ data: Data, account: String) throws -> KeyEncryption? {
		try requireUnlockedEncryption()
		guard let key = currentKey() else { throw KeygateError.vaultLocked }
		let bytes = Self.encryptedFileMagic + (try PassphraseCipher.encrypt(data, key: key))
        try FileManager.default.createDirectory(
            at: keysDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let url = materialURL(account: account)
        try bytes.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
		return .passphrase
    }

	private func readPrivateKey(record: StoredKeyRecord, allowPlaintextMigration: Bool = false) throws -> Data {
        let url = materialURL(account: record.keychainAccount)
        if let stored = try? Data(contentsOf: url) {
            if stored.starts(with: Self.encryptedFileMagic) {
                guard let key = currentKey() else { throw KeygateError.vaultLocked }
                return try PassphraseCipher.decrypt(Data(stored.dropFirst(Self.encryptedFileMagic.count)), key: key)
            }
            switch record.encryption {
            case .passphrase:
                guard let key = currentKey() else { throw KeygateError.vaultLocked }
                return try PassphraseCipher.decrypt(stored, key: key)
            case nil:
				guard allowPlaintextMigration, encryptionEnabled(), currentKey() != nil else {
					throw KeygateError.encryptionRequired
				}
				return stored
            }
        }
        // One-time migration: pull material from a legacy Keychain item (created
        // by an older build), persist it to a file (encrypted when possible),
        // then remove the Keychain copy. This is the last time the Keychain can
        // prompt for a given key.
		try requireUnlockedEncryption()
		guard let legacy = LegacyKeychainStore.read(account: record.keychainAccount) else {
            throw KeygateError.keyNotFound
        }
        let encryption = try writePrivateKey(legacy, account: record.keychainAccount)
        LegacyKeychainStore.delete(account: record.keychainAccount)
        try updateEncryption(fingerprint: record.fingerprint, to: encryption)
        return legacy
    }

    private func updateEncryption(fingerprint: String, to encryption: KeyEncryption?) throws {
        var records = try loadMetadata()
        guard let index = records.firstIndex(where: { $0.fingerprint == fingerprint }) else { return }
        records[index].encryption = encryption
        try saveMetadata(records)
    }

    private func deletePrivateKey(account: String) throws {
        let url = materialURL(account: account)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        LegacyKeychainStore.delete(account: account)
    }

    private func loadMetadata() throws -> [StoredKeyRecord] {
        guard FileManager.default.fileExists(atPath: metadataURL.path) else { return [] }
        let data = try Data(contentsOf: metadataURL)
        return try decoder.decode([StoredKeyRecord].self, from: data)
    }

    private func saveMetadata(_ records: [StoredKeyRecord]) throws {
        try ensurePrivateDirectory(metadataURL.deletingLastPathComponent())
        let data = try encoder.encode(records)
        try data.write(to: metadataURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metadataURL.path)
    }

    private func ensurePrivateDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

	private func requireUnlockedEncryption() throws {
		guard encryptionEnabled() else { throw KeygateError.encryptionRequired }
		guard currentKey() != nil else { throw KeygateError.vaultLocked }
	}
}

public final class InMemoryVault: KeyVault {
    private var records: [StoredKeyRecord] = []
    private var privateMaterial: [String: Data] = [:]

    public init() {}

    public func listKeys() throws -> [StoredKeyRecord] {
        records
    }

    public func generate(_ type: SSHKeyType, comment: String, syncToCloud: Bool, rsaBits: Int) throws -> StoredKeyRecord {
        let generated = try SSHSigner.generate(type, rsaBits: rsaBits)
        return store(keyType: type, privateMaterial: generated.privateMaterial, publicBlob: generated.publicBlob, comment: comment, syncToCloud: syncToCloud)
    }

    public func importPrivateKey(text: String, passphrase: String?, comment: String?, syncToCloud: Bool) throws -> StoredKeyRecord {
        let imported = try KeyImporter.parse(text: text, passphrase: passphrase)
        let publicBlob = try SSHSigner.publicBlob(type: imported.keyType, privateMaterial: imported.privateMaterial)
        let resolvedComment = (comment?.isEmpty == false ? comment : nil) ?? imported.comment ?? ""
        return store(keyType: imported.keyType, privateMaterial: imported.privateMaterial, publicBlob: publicBlob, comment: resolvedComment, syncToCloud: syncToCloud)
    }

    public func rename(fingerprint: String, comment: String) throws -> StoredKeyRecord {
        guard let index = records.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        records[index].comment = comment.isEmpty ? fingerprint : comment
        records[index].updatedAt = Date()
        return records[index]
    }

    public func delete(fingerprint: String) throws {
        guard records.contains(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        records.removeAll { $0.fingerprint == fingerprint }
        privateMaterial[fingerprint] = nil
    }

    public func setSync(fingerprint: String, syncToCloud: Bool) throws -> StoredKeyRecord {
        guard let index = records.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        records[index].isSynced = syncToCloud
        records[index].updatedAt = Date()
        return records[index]
    }

    public func authorizedKeysLine(fingerprint: String) throws -> String {
        guard let record = records.first(where: { $0.fingerprint == fingerprint }) else {
            throw KeygateError.keyNotFound
        }
        let base64 = record.wireBlob.base64EncodedString()
        let suffix = record.comment.isEmpty ? "" : " \(record.comment)"
        return "\(record.keyType.rawValue) \(base64)\(suffix)"
    }

    public func exportPrivateKey(fingerprint: String, format: KeyExportFormat, passphrase: String?) throws -> String {
        guard let record = records.first(where: { $0.fingerprint == fingerprint }),
              let material = privateMaterial[fingerprint] else {
            throw KeygateError.keyNotFound
        }
        return try KeyExporter.export(
            type: record.keyType,
            privateMaterial: material,
            comment: record.comment,
            format: format,
            passphrase: passphrase
        )
    }

    public func sign(keyBlob: Data, payload: Data, flags: UInt32) throws -> SignatureResult {
        guard let record = records.first(where: { $0.agentIdentity.keyBlob == keyBlob }),
              let material = privateMaterial[record.fingerprint] else {
            throw KeygateError.keyNotFound
        }
        return try SSHSigner.sign(type: record.keyType, privateMaterial: material, payload: payload, flags: flags)
    }

    private func store(keyType: SSHKeyType, privateMaterial material: Data, publicBlob: Data, comment: String, syncToCloud: Bool) -> StoredKeyRecord {
        let fingerprint = Fingerprint.sha256(publicBlob)
        let now = Date()
        let record = StoredKeyRecord(
            fingerprint: fingerprint,
            keyType: keyType,
            comment: comment.isEmpty ? fingerprint : comment,
            publicKey: publicBlob,
            keychainAccount: fingerprint,
            isSynced: syncToCloud,
            createdAt: now,
            updatedAt: now
        )
        records.removeAll { $0.fingerprint == fingerprint }
        records.append(record)
        privateMaterial[fingerprint] = material
        return record
    }
}

/// Read/remove access to private key material stored by older Keychain-backed
/// builds, used only to migrate those keys into files on first use.
enum LegacyKeychainStore {
    private static let service = "dev.vstack.keygate.keys"

    static func read(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func delete(account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ] as CFDictionary)
    }
}
