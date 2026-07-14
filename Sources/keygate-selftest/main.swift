import CryptoKit
import Foundation
import KeygateCore
import Security

struct TestFailure: Error, CustomStringConvertible {
    let description: String
}

@discardableResult
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws -> Bool {
    guard condition() else { throw TestFailure(description: message) }
    return true
}

func leftPad(_ data: Data, to length: Int) -> Data {
    if data.count >= length { return data.suffix(length) }
    return Data(repeating: 0, count: length - data.count) + data
}

/// Independently verifies an SSH-agent signature by reconstructing the public key
/// from its wire blob — an oracle separate from the signing code under test.
func verifySSHSignature(publicBlob: Data, algorithm: String, signature: Data, payload: Data) throws -> Bool {
    var reader = SSHReader(publicBlob)
    let type = try reader.readString()
    switch type {
    case "ssh-ed25519":
        let q = try reader.readDataString()
        let pub = try Curve25519.Signing.PublicKey(rawRepresentation: q)
        return pub.isValidSignature(signature, for: payload)
    case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
        _ = try reader.readString() // curve identifier
        let point = try reader.readDataString()
        var sigReader = SSHReader(signature)
        let r = try sigReader.readMPInt()
        let s = try sigReader.readMPInt()
        switch type {
        case "ecdsa-sha2-nistp256":
            let raw = leftPad(r, to: 32) + leftPad(s, to: 32)
            let pub = try P256.Signing.PublicKey(x963Representation: point)
            return pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: payload)
        case "ecdsa-sha2-nistp384":
            let raw = leftPad(r, to: 48) + leftPad(s, to: 48)
            let pub = try P384.Signing.PublicKey(x963Representation: point)
            return pub.isValidSignature(try P384.Signing.ECDSASignature(rawRepresentation: raw), for: payload)
        default:
            let raw = leftPad(r, to: 66) + leftPad(s, to: 66)
            let pub = try P521.Signing.PublicKey(x963Representation: point)
            return pub.isValidSignature(try P521.Signing.ECDSASignature(rawRepresentation: raw), for: payload)
        }
    case "ssh-rsa":
        let e = try reader.readMPInt()
        let n = try reader.readMPInt()
        let pkcs1 = ASN1.sequence([ASN1.integer(n), ASN1.integer(e)])
        var error: Unmanaged<CFError>?
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let pub = SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, &error) else {
            throw TestFailure(description: "could not rebuild RSA public key")
        }
        let secAlgorithm: SecKeyAlgorithm
        switch algorithm {
        case "rsa-sha2-512": secAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
        case "rsa-sha2-256": secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        default: secAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
        }
        return SecKeyVerifySignature(pub, secAlgorithm, payload as CFData, signature as CFData, &error)
    default:
        return false
    }
}

func testProtocolIdentities() throws {
    let payload = Data([AgentMessageType.requestIdentities])
    let request = try AgentProtocolCodec.parse(payload)
    try expect(request == .requestIdentities, "request identities did not parse")

    let keyBlob = Data([1, 2, 3])
    let response = AgentProtocolCodec.encode(.identities([
        AgentIdentity(keyBlob: keyBlob, comment: "test", fingerprint: "SHA256:test", keyType: "ssh-ed25519")
    ]))
    var reader = SSHReader(response)
    let responseType = try reader.readByte()
    let identityCount = try reader.readUInt32()
    let responseKeyBlob = try reader.readDataString()
    let responseComment = try reader.readString()
    try expect(responseType == AgentMessageType.identitiesAnswer, "identity response type mismatch")
    try expect(identityCount == 1, "identity count mismatch")
    try expect(responseKeyBlob == keyBlob, "identity key blob mismatch")
    try expect(responseComment == "test", "identity comment mismatch")
}

func testProtocolSignRequest() throws {
    var writer = SSHWriter()
    writer.writeByte(AgentMessageType.signRequest)
    writer.writeDataString(Data([1, 2, 3]))
    writer.writeDataString(Data([4, 5, 6]))
    writer.writeUInt32(0)

    guard case .sign(let request) = try AgentProtocolCodec.parse(writer.finish()) else {
        throw TestFailure(description: "sign request did not parse")
    }
    try expect(request.keyBlob == Data([1, 2, 3]), "sign key blob mismatch")
    try expect(request.payload == Data([4, 5, 6]), "sign payload mismatch")
    try expect(request.flags == 0, "sign flags mismatch")
}

func testMPIntRoundTrip() throws {
    // High-bit-set values must gain a sign byte; leading zeros must be stripped.
    let cases: [[UInt8]] = [[], [0x00], [0x01], [0x7f], [0x80], [0xff, 0x00], [0x00, 0x00, 0x2a]]
    for bytes in cases {
        var writer = SSHWriter()
        writer.writeMPInt(Data(bytes))
        var reader = SSHReader(writer.finish())
        let magnitude = try reader.readMPInt()
        // Expected magnitude is the input with leading zero bytes stripped.
        var expected = bytes
        while expected.first == 0 { expected.removeFirst() }
        try expect(Array(magnitude) == expected, "mpint round trip mismatch for \(bytes)")
    }
}

/// Validates public-blob byte layout and fingerprinting against real `ssh-keygen` output.
func testPublicBlobVectors() throws {
    let vectors: [(label: String, blob: String, fingerprint: String)] = [
        ("ed25519",
         "AAAAC3NzaC1lZDI1NTE5AAAAIPu/WzGbEXONCAO6hwgb2UE+tFyD3tPsITQkV/9622qo",
         "SHA256:yDteqHjuvO/rRvA3uFf75FGGqX22uX9ueK7kcCKB87E"),
        ("ecdsa-nistp256",
         "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFN+Qf0FBiuySlwh01dOadDGYH6sJ6MgsBlBSFNEp17qlbGYf4nfhfFXz4q/+59GV8dR+nRA1j3IER027kJmUxs=",
         "SHA256:qdkaK+2CQ61uFSKH5qIcxg88VehOVvT2QaMOgB+fzx8"),
        ("rsa",
         "AAAAB3NzaC1yc2EAAAADAQABAAABAQCqUbhGdzKYVC3hSeugdA2iCcydS8EnId8an+o2/F/ku7CaAC+UWDPSXggETJ+SsbTHWLB1OfHqqP096UiSsHoFg0Y17wKsqYycYKlXji0ax5vwM5mcJ9Dx3seQypKDKf13xnE0C9wcBAhQ+FGrPhG+WH90q8/fLlN4w1BAffV2r1yikfWo/7M8Z+LzCT3nrj7WrJwiKe268YoJ5tAOdAssB81ULm0S+H1rJQC2x0SYpbschP5EVPfuq/QTza6FkOJY4ffLFpNsNbQpltveuPLmSGPHq9PZAjcFtV9efhJPlzchnTVyAiUpSQ/3/mtw1T0yx6jCvTqQXstsZAmu1aLj",
         "SHA256:aYuhPlMBSuAxD3zM6S/BjmMTSY8/vYs0pPSdzj3l+7A"),
    ]
    for vector in vectors {
        guard let blob = Data(base64Encoded: vector.blob) else {
            throw TestFailure(description: "\(vector.label) vector base64 invalid")
        }
        try expect(Fingerprint.sha256(blob) == vector.fingerprint, "\(vector.label) fingerprint mismatch")

        // Re-encode from parsed components to check the blob writer against OpenSSH bytes.
        var reader = SSHReader(blob)
        let type = try reader.readString()
        let rebuilt: Data
        switch type {
        case "ssh-ed25519":
            rebuilt = SSHPublicKeyBlob.ed25519(try reader.readDataString())
        case "ecdsa-sha2-nistp256":
            _ = try reader.readString()
            rebuilt = SSHPublicKeyBlob.ecdsa(.ecdsaP256, point: try reader.readDataString())
        case "ssh-rsa":
            let e = try reader.readMPInt()
            let n = try reader.readMPInt()
            rebuilt = SSHPublicKeyBlob.rsa(e: e, n: n)
        default:
            rebuilt = Data()
        }
        try expect(rebuilt == blob, "\(vector.label) rebuilt blob does not match OpenSSH bytes")
    }
}

/// Generate → sign → verify for every algorithm, including RSA SHA-2 flag negotiation.
func testSigningRoundTrip() throws {
    let vault = InMemoryVault()
    let payload = Data("keygate round trip".utf8)
    let types: [SSHKeyType] = [.ed25519, .ecdsaP256, .ecdsaP384, .ecdsaP521, .rsa]
    var keyByType: [SSHKeyType: StoredKeyRecord] = [:]
    for type in types {
        keyByType[type] = try vault.generate(type, comment: "rt-\(type.rawValue)", syncToCloud: false)
    }

    let cases: [(type: SSHKeyType, flags: UInt32, algorithm: String)] = [
        (.ed25519, 0, "ssh-ed25519"),
        (.ecdsaP256, 0, "ecdsa-sha2-nistp256"),
        (.ecdsaP384, 0, "ecdsa-sha2-nistp384"),
        (.ecdsaP521, 0, "ecdsa-sha2-nistp521"),
        (.rsa, 0, "ssh-rsa"),
        (.rsa, 2, "rsa-sha2-256"),
        (.rsa, 4, "rsa-sha2-512"),
        (.rsa, 6, "rsa-sha2-512"), // both flags set -> SHA-512 wins
    ]
    for testCase in cases {
        let key = keyByType[testCase.type]!
        let result = try vault.sign(keyBlob: key.agentIdentity.keyBlob, payload: payload, flags: testCase.flags)
        try expect(result.algorithm == testCase.algorithm,
                   "\(testCase.type.rawValue) flags \(testCase.flags): algorithm \(result.algorithm) != \(testCase.algorithm)")
        let verified = try verifySSHSignature(publicBlob: key.wireBlob, algorithm: result.algorithm, signature: result.signature, payload: payload)
        try expect(verified, "\(testCase.type.rawValue) flags \(testCase.flags): signature did not verify")
    }
}

func testImportVectors() throws {
    let payload = Data("keygate import".utf8)
    for vector in importVectors {
        let vault = InMemoryVault()
        let record: StoredKeyRecord
        do {
            record = try vault.importPrivateKey(text: vector.pem, passphrase: vector.passphrase, comment: nil, syncToCloud: false)
        } catch {
            throw TestFailure(description: "\(vector.label): import threw \(error)")
        }
        try expect(record.keyType == vector.expectedType,
                   "\(vector.label): type \(record.keyType.rawValue) != \(vector.expectedType.rawValue)")
        try expect(record.fingerprint == vector.fingerprint,
                   "\(vector.label): fingerprint \(record.fingerprint) != \(vector.fingerprint)")
        let flags: UInt32 = record.keyType.isRSA ? 2 : 0
        let signature = try vault.sign(keyBlob: record.agentIdentity.keyBlob, payload: payload, flags: flags)
        let verified = try verifySSHSignature(publicBlob: record.wireBlob, algorithm: signature.algorithm, signature: signature.signature, payload: payload)
        try expect(verified, "\(vector.label): imported key signature did not verify")
    }
}

func testEncryptedOpenSSHImport() throws {
    let vector = encryptedOpenSSHVector
    if Bcrypt.isAvailable {
        let record = try InMemoryVault().importPrivateKey(text: vector.pem, passphrase: vector.passphrase, comment: nil, syncToCloud: false)
        try expect(record.fingerprint == vector.fingerprint,
                   "encrypted OpenSSH fingerprint \(record.fingerprint) != \(vector.fingerprint)")
        var wrongThrew = false
        do {
            _ = try InMemoryVault().importPrivateKey(text: vector.pem, passphrase: "wrong-passphrase", comment: nil, syncToCloud: false)
        } catch {
            wrongThrew = true
        }
        try expect(wrongThrew, "wrong passphrase should have failed")
    } else {
        // Without the bcrypt component the import must fail clearly rather than silently.
        var threw = false
        do {
            _ = try InMemoryVault().importPrivateKey(text: vector.pem, passphrase: vector.passphrase, comment: nil, syncToCloud: false)
        } catch {
            threw = true
        }
        try expect(threw, "encrypted OpenSSH import should report the bcrypt component is unavailable")
    }
}

/// Export in every supported format, re-import, and confirm the key survives:
/// same fingerprint, same comment (OpenSSH), and a signature that still verifies.
func testExportRoundTrip() throws {
    let payload = Data("keygate export".utf8)
    let dumpDir = ProcessInfo.processInfo.environment["KEYGATE_EXPORT_DUMP_DIR"]
    for type in [SSHKeyType.ed25519, .ecdsaP256, .ecdsaP384, .ecdsaP521, .rsa] {
        let vault = InMemoryVault()
        let key = try vault.generate(type, comment: "exp-\(type.accountPrefix)", syncToCloud: false)

        var formats: [KeyExportFormat] = [.openssh, .pkcs8]
        if type == .rsa { formats.append(.pkcs1) }
        for format in formats {
            let exported = try vault.exportPrivateKey(fingerprint: key.fingerprint, format: format, passphrase: nil)
            if let dumpDir {
                try Data(exported.utf8).write(to: URL(fileURLWithPath: dumpDir).appendingPathComponent("exp-\(type.accountPrefix)-\(format.rawValue)"))
            }
            let reimportVault = InMemoryVault()
            let reimported = try reimportVault.importPrivateKey(text: exported, passphrase: nil, comment: nil, syncToCloud: false)
            try expect(reimported.fingerprint == key.fingerprint,
                       "\(type.rawValue) \(format.rawValue): fingerprint \(reimported.fingerprint) != \(key.fingerprint)")
            let signature = try reimportVault.sign(keyBlob: reimported.agentIdentity.keyBlob, payload: payload, flags: type.isRSA ? 2 : 0)
            let verified = try verifySSHSignature(publicBlob: reimported.wireBlob, algorithm: signature.algorithm, signature: signature.signature, payload: payload)
            try expect(verified, "\(type.rawValue) \(format.rawValue): re-imported key signature did not verify")
            if format == .openssh {
                try expect(reimported.comment == key.comment,
                           "\(type.rawValue) openssh: comment '\(reimported.comment)' was not preserved")
            }
        }

        // 1Password-style restrictions: PKCS#1 is RSA-only, and only OpenSSH encrypts.
        if type != .rsa {
            var threw = false
            do { _ = try vault.exportPrivateKey(fingerprint: key.fingerprint, format: .pkcs1, passphrase: nil) } catch { threw = true }
            try expect(threw, "\(type.rawValue): PKCS#1 export should be rejected for non-RSA keys")
        }
        var passphraseThrew = false
        do { _ = try vault.exportPrivateKey(fingerprint: key.fingerprint, format: .pkcs8, passphrase: "secret") } catch { passphraseThrew = true }
        try expect(passphraseThrew, "\(type.rawValue): passphrase with PKCS#8 export should be rejected")
    }
}

func testEncryptedExportRoundTrip() throws {
    let vault = InMemoryVault()
    let key = try vault.generate(.ed25519, comment: "exp-encrypted", syncToCloud: false)
    guard Bcrypt.isAvailable else {
        var threw = false
        do { _ = try vault.exportPrivateKey(fingerprint: key.fingerprint, format: .openssh, passphrase: "pass") } catch { threw = true }
        try expect(threw, "encrypted export without bcrypt should fail clearly")
        return
    }

    let exported = try vault.exportPrivateKey(fingerprint: key.fingerprint, format: .openssh, passphrase: "round-trip-pass")
    if let dumpDir = ProcessInfo.processInfo.environment["KEYGATE_EXPORT_DUMP_DIR"] {
        try Data(exported.utf8).write(to: URL(fileURLWithPath: dumpDir).appendingPathComponent("exp-ed25519-openssh-encrypted"))
    }
    try expect(exported.contains("BEGIN OPENSSH PRIVATE KEY"), "encrypted export is not an OpenSSH container")

    let reimported = try InMemoryVault().importPrivateKey(text: exported, passphrase: "round-trip-pass", comment: nil, syncToCloud: false)
    try expect(reimported.fingerprint == key.fingerprint, "encrypted export round trip changed the fingerprint")

    var wrongThrew = false
    do { _ = try InMemoryVault().importPrivateKey(text: exported, passphrase: "wrong", comment: nil, syncToCloud: false) } catch { wrongThrew = true }
    try expect(wrongThrew, "encrypted export should reject a wrong passphrase")

    var missingThrew = false
    do { _ = try InMemoryVault().importPrivateKey(text: exported, passphrase: nil, comment: nil, syncToCloud: false) } catch { missingThrew = true }
    try expect(missingThrew, "encrypted export should reject a missing passphrase")
}

func testRSAKeySizes() throws {
    // Modulus length is visible in the public blob, so check each supported size
    // without a slow full signing pass (4096-bit generation is already the cost).
    for bits in SSHSigner.supportedRSABits {
        let vault = InMemoryVault()
        let key = try vault.generate(.rsa, comment: "rsa-\(bits)", syncToCloud: false, rsaBits: bits)
        var reader = SSHReader(key.wireBlob)
        _ = try reader.readString() // "ssh-rsa"
        _ = try reader.readMPInt()  // e
        let n = try reader.readMPInt()
        try expect(n.count * 8 == bits, "rsa \(bits): modulus is \(n.count * 8) bits")
    }

    var threw = false
    do { _ = try InMemoryVault().generate(.rsa, comment: "bad", syncToCloud: false, rsaBits: 1024) } catch { threw = true }
    try expect(threw, "unsupported RSA size should be rejected")
}

func testPassphraseEncryption() throws {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-fv-\(UUID().uuidString)")
    let metadataURL = dir.appendingPathComponent("keys.json")
    let keysDir = dir.appendingPathComponent("keys")
    let configURL = dir.appendingPathComponent("encryption.json")
    func makeVault() -> FileVault {
        FileVault(metadataURL: metadataURL, keysDirectory: keysDir, encryptionConfigURL: configURL, authorizer: AllowAllAuthorizer())
    }
    defer { try? FileManager.default.removeItem(at: dir) }

    let payload = Data("keygate passphrase".utf8)
    let vault = makeVault()

	// New private material must never be written before encryption is configured.
	var unencryptedWriteRejected = false
	do { _ = try vault.generate(.ed25519, comment: "unsafe", syncToCloud: false) }
	catch KeygateError.encryptionRequired { unencryptedWriteRejected = true }
	try expect(unencryptedWriteRejected, "unencrypted key generation must be rejected")

	try vault.enableEncryption(passphrase: "correct horse battery")
	try expect(vault.encryptionEnabled() && !vault.isLocked(), "vault should be enabled and unlocked after enabling")
	let key = try vault.generate(.ed25519, comment: "pw-test", syncToCloud: false)
    let account = key.keychainAccount.replacingOccurrences(of: "/", with: "_")
    let fileURL = keysDir.appendingPathComponent(account).appendingPathExtension("key")
    let record = try vault.listKeys().first { $0.fingerprint == key.fingerprint }!
    try expect(record.encryption == .passphrase, "record should be marked passphrase-encrypted")
    let encryptedBytes = try Data(contentsOf: fileURL)
    try expect(encryptedBytes.count != 32, "encrypted file must not be the raw 32-byte seed")

    // Signing works while unlocked.
    let sig1 = try vault.sign(keyBlob: key.agentIdentity.keyBlob, payload: payload, flags: 0)
    let ok1 = try verifySSHSignature(publicBlob: key.wireBlob, algorithm: sig1.algorithm, signature: sig1.signature, payload: payload)
    try expect(ok1, "sign while unlocked failed")

    // Locking blocks use until unlocked again.
    vault.lock()
    try expect(vault.isLocked(), "vault should report locked")
    var lockedThrew = false
    do { _ = try vault.sign(keyBlob: key.agentIdentity.keyBlob, payload: payload, flags: 0) } catch { lockedThrew = true }
    try expect(lockedThrew, "signing while locked should fail")

    // Wrong passphrase rejected; correct passphrase restores use.
    var wrongThrew = false
    do { try vault.unlock(passphrase: "wrong") } catch { wrongThrew = true }
    try expect(wrongThrew, "wrong passphrase should be rejected")
    try vault.unlock(passphrase: "correct horse battery")
    let sig2 = try vault.sign(keyBlob: key.agentIdentity.keyBlob, payload: payload, flags: 0)
    let ok2 = try verifySSHSignature(publicBlob: key.wireBlob, algorithm: sig2.algorithm, signature: sig2.signature, payload: payload)
    try expect(ok2, "sign after unlock failed")

    // A fresh instance (new process) starts locked and unlocks from disk config.
    let reopened = makeVault()
    try expect(reopened.isLocked(), "reopened vault should start locked")
    try reopened.unlock(passphrase: "correct horse battery")
    let sig3 = try reopened.sign(keyBlob: key.agentIdentity.keyBlob, payload: payload, flags: 0)
    let ok3 = try verifySSHSignature(publicBlob: key.wireBlob, algorithm: sig3.algorithm, signature: sig3.signature, payload: payload)
    try expect(ok3, "sign from reopened vault failed")
}

func testInterruptedEncryptionMigrationIsRecoverable() throws {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-fv-interrupted-\(UUID().uuidString)")
    let metadataURL = dir.appendingPathComponent("keys.json")
    let keysDir = dir.appendingPathComponent("keys")
    let configURL = dir.appendingPathComponent("encryption.json")
    defer { try? FileManager.default.removeItem(at: dir) }

	try FileManager.default.createDirectory(at: keysDir, withIntermediateDirectories: true)
	let generated = try [SSHSigner.generate(.ed25519), SSHSigner.generate(.ed25519)]
	let now = Date()
	let records = generated.enumerated().map { index, key -> StoredKeyRecord in
		let fingerprint = Fingerprint.sha256(key.publicBlob)
		let account = "ed25519-\(fingerprint.replacingOccurrences(of: ":", with: "-"))"
		try! key.privateMaterial.write(
			to: keysDir.appendingPathComponent(account.replacingOccurrences(of: "/", with: "_")).appendingPathExtension("key")
		)
		return StoredKeyRecord(
			fingerprint: fingerprint,
			keyType: .ed25519,
			comment: index == 0 ? "recoverable" : "missing",
			publicKey: key.publicBlob,
			keychainAccount: account,
			isSynced: false,
			createdAt: now,
			updatedAt: now,
			encryption: nil
		)
	}
	let encoder = JSONEncoder()
	encoder.dateEncodingStrategy = .iso8601
	try encoder.encode(records).write(to: metadataURL)
	let first = records[0]
	let missing = records[1]
	let vault = FileVault(metadataURL: metadataURL, keysDirectory: keysDir, encryptionConfigURL: configURL, authorizer: AllowAllAuthorizer())
    let missingURL = keysDir
        .appendingPathComponent(missing.keychainAccount.replacingOccurrences(of: "/", with: "_"))
        .appendingPathExtension("key")
    try FileManager.default.removeItem(at: missingURL)

    var migrationFailed = false
    do { try vault.enableEncryption(passphrase: "recovery secret") } catch { migrationFailed = true }
    try expect(migrationFailed, "migration with a missing file should report failure")
    try expect(vault.encryptionEnabled(), "failed migration must retain the encryption config")

    vault.lock()
    let reopened = FileVault(metadataURL: metadataURL, keysDirectory: keysDir, encryptionConfigURL: configURL, authorizer: AllowAllAuthorizer())
    try reopened.unlock(passphrase: "recovery secret")
    let signature = try reopened.sign(keyBlob: first.agentIdentity.keyBlob, payload: Data("recover".utf8), flags: 0)
    try expect(!signature.signature.isEmpty, "converted key must remain usable after an interrupted migration")
}

func testPolicyDefaultsAndMatches() throws {
    let key = "SHA256:abc"
    let context = PolicyContext(
		process: ProcessIdentity(bundleIdentifier: "com.apple.Terminal", teamIdentifier: "APPLE"),
        destination: DestinationIdentity(host: "github.com", user: "git"),
        keyFingerprint: key,
        requestFlags: 0
    )
    let defaultDecision = PolicyEngine().decide(context)
    try expect(defaultDecision.action == .requireUserPresence, "default policy should require user presence")

    let rule = PolicyRule(
        name: "Allow GitHub from Terminal",
        keyFingerprint: key,
        appBundleIdentifier: "com.apple.Terminal",
		teamIdentifier: "APPLE",
        destinationHost: "github.com",
        action: .alwaysAllow
    )
    let decision = PolicyEngine(rules: [rule]).decide(context)
    try expect(decision.action == .alwaysAllow, "specific policy did not match")

    // ssh peers have nil bundleIdentifier; the GUI app lives on terminalBundleIdentifier.
    let sshContext = PolicyContext(
        process: ProcessIdentity(
            executablePath: "/usr/bin/ssh",
			terminalBundleIdentifier: "com.apple.Terminal",
			terminalTeamIdentifier: "APPLE"
        ),
        destination: DestinationIdentity(host: "github.com", user: "git"),
        keyFingerprint: key,
        requestFlags: 0
    )
    let sshDecision = PolicyEngine(rules: [rule]).decide(sshContext)
    try expect(sshDecision.action == .alwaysAllow, "app rule should match terminal parent of ssh")

    let keygateOnly = PolicyRule(
        name: "Only Keygate",
        appBundleIdentifier: "dev.vstack.keygate",
		teamIdentifier: "VSTACK",
        action: .allowForDuration,
        durationSeconds: 600
    )
    let miss = PolicyEngine(rules: [keygateOnly]).decide(sshContext)
    try expect(miss.action == .requireUserPresence, "Keygate-only rule must not match ssh")
}

func testVaultAndAgentService() throws {
    let vault = InMemoryVault()
    let key = try vault.generateEd25519(comment: "selftest", syncToCloud: false)
    let rules = [PolicyRule(name: "Allow selftest", keyFingerprint: key.fingerprint, action: .alwaysAllow)]
    let policyURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-policy-\(UUID().uuidString).json")
    let auditURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-audit-\(UUID().uuidString).jsonl")
    let policyStore = PolicyStore(url: policyURL)
    try policyStore.save(rules)
    let service = AgentService(vault: vault, policyStore: policyStore, auditLog: AuditLog(url: auditURL))

    guard case .identities(let identities) = service.handle(.requestIdentities, process: ProcessIdentity()) else {
        throw TestFailure(description: "service did not return identities")
    }
    try expect(identities.count == 1, "service identity count mismatch")

    let binding = service.handle(
        .extensionRequest(name: "session-bind@openssh.com", payload: Data()),
        process: ProcessIdentity()
    )
    try expect(binding == .extensionFailure, "unverified session bindings must fail closed")

    let payload = Data("hello".utf8)
    let response = service.handle(.sign(AgentSignRequest(keyBlob: key.agentIdentity.keyBlob, payload: payload, flags: 0)), process: ProcessIdentity())
    guard case .signature(let algorithm, let signature) = response else {
        throw TestFailure(description: "service did not sign")
    }
    try expect(algorithm == "ssh-ed25519", "signature algorithm mismatch")
    let verified = try verifySSHSignature(publicBlob: key.wireBlob, algorithm: algorithm, signature: signature, payload: payload)
    try expect(verified, "signature did not verify")
}

/// Captures Touch ID reason strings so tests can assert the requesting app is named.
final class CapturingAuthorizer: SigningAuthorizer {
    private(set) var reasons: [String] = []
    var allow = true

    func authorize(reason: String) -> Bool {
        reasons.append(reason)
        return allow
    }

    func reset() {
        reasons.removeAll()
    }
}

func testAuthorizationReasonNamesRequestingApp() throws {
    let vault = InMemoryVault()
    let key = try vault.generateEd25519(comment: "deploy", syncToCloud: false)
    // Default policy requires user presence, which prompts the authorizer.
    let policyURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-policy-\(UUID().uuidString).json")
    let auditURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-audit-\(UUID().uuidString).jsonl")
    try PolicyStore(url: policyURL).save([])
    let authorizer = CapturingAuthorizer()
    let service = AgentService(
        vault: vault,
        policyStore: PolicyStore(url: policyURL),
        auditLog: AuditLog(url: auditURL),
        authorizer: authorizer
    )

    let process = ProcessIdentity(
        executablePath: "/usr/bin/ssh",
        terminalBundleIdentifier: "com.apple.Terminal"
    )
    let response = service.handle(
        .sign(AgentSignRequest(keyBlob: key.agentIdentity.keyBlob, payload: Data("auth-reason".utf8), flags: 0)),
        process: process
    )
    guard case .signature = response else {
        throw TestFailure(description: "expected signature after approval")
    }
    try expect(authorizer.reasons.count == 1, "authorizer should be invoked once")
    let reason = authorizer.reasons[0]
    try expect(reason.contains("Terminal"), "reason should name the requesting app: \(reason)")
    try expect(reason.contains("deploy"), "reason should name the key: \(reason)")

    // Cancellation is audited with the app name as well.
    authorizer.allow = false
    authorizer.reset()
    let denied = service.handle(
        .sign(AgentSignRequest(keyBlob: key.agentIdentity.keyBlob, payload: Data("denied".utf8), flags: 0)),
        process: process
    )
    guard case .failure = denied else {
        throw TestFailure(description: "expected failure when authorization is cancelled")
    }
    let events = try AuditLog(url: auditURL).recent()
    let cancelEvent = events.last { $0.decision == .deny && $0.reason.contains("cancelled") }
    try expect(cancelEvent != nil, "missing cancel audit event")
    try expect(cancelEvent!.reason.contains("Terminal"), "cancel audit should name app: \(cancelEvent!.reason)")
    try expect(cancelEvent!.process.terminalBundleIdentifier == "com.apple.Terminal",
               "audit event should retain process identity")
}

/// Locked vault must refuse signing *before* Touch ID, and request unlock via notification.
func testLockedVaultSkipsTouchID() throws {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-locked-agent-\(UUID().uuidString)")
    let metadataURL = dir.appendingPathComponent("keys.json")
    let keysDir = dir.appendingPathComponent("keys")
    let configURL = dir.appendingPathComponent("encryption.json")
    defer { try? FileManager.default.removeItem(at: dir) }

    let vault = FileVault(
        metadataURL: metadataURL,
        keysDirectory: keysDir,
        encryptionConfigURL: configURL,
        authorizer: AllowAllAuthorizer()
    )
    try vault.enableEncryption(passphrase: "session secret")
	let key = try vault.generate(.ed25519, comment: "locked-key", syncToCloud: false)
    vault.lock()
    try expect(vault.isLocked(), "vault must be locked for this test")

    let policyURL = dir.appendingPathComponent("policy.json")
    let auditURL = dir.appendingPathComponent("audit.jsonl")
    try PolicyStore(url: policyURL).save([]) // default: require user presence
    let authorizer = CapturingAuthorizer()
    let service = AgentService(
        vault: vault,
        policyStore: PolicyStore(url: policyURL),
        auditLog: AuditLog(url: auditURL),
        authorizer: authorizer
    )

    var unlockNotifications = 0
    let token = NotificationCenter.default.addObserver(
        forName: .keygateVaultNeedsUnlock,
        object: nil,
        queue: nil
    ) { _ in unlockNotifications += 1 }
    defer { NotificationCenter.default.removeObserver(token) }

    let response = service.handle(
        .sign(AgentSignRequest(keyBlob: key.agentIdentity.keyBlob, payload: Data("locked".utf8), flags: 0)),
        process: ProcessIdentity(executablePath: "/usr/bin/ssh")
    )
    guard case .failure = response else {
        throw TestFailure(description: "locked vault should refuse sign")
    }
    try expect(authorizer.reasons.isEmpty, "Touch ID must not run while vault is locked")
    try expect(unlockNotifications == 1, "should post vaultNeedsUnlock once")

    let events = try AuditLog(url: auditURL).recent()
    let lockedEvent = events.last { $0.decision == .deny && $0.reason.contains("locked") }
    try expect(lockedEvent != nil, "missing vault-locked audit event")

    // After unlock, the same request should proceed to authorization (and succeed with allow-all).
    try vault.unlock(passphrase: "session secret")
    authorizer.reset()
    let unlocked = service.handle(
        .sign(AgentSignRequest(keyBlob: key.agentIdentity.keyBlob, payload: Data("unlocked".utf8), flags: 0)),
        process: ProcessIdentity(executablePath: "/usr/bin/ssh")
    )
    guard case .signature = unlocked else {
        throw TestFailure(description: "sign should succeed after unlock")
    }
    try expect(authorizer.reasons.count == 1, "authorizer should run once vault is unlocked")
}

func testEnvironmentPassphraseUnlocksAgent() throws {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-env-agent-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let vault = FileVault(
        metadataURL: dir.appendingPathComponent("keys.json"),
        keysDirectory: dir.appendingPathComponent("keys"),
        encryptionConfigURL: dir.appendingPathComponent("encryption.json"),
        authorizer: AllowAllAuthorizer()
    )
    try vault.enableEncryption(passphrase: "environment secret")
	let key = try vault.generate(.ed25519, comment: "env-key", syncToCloud: false)
    vault.lock()
    setenv("KEYGATE_PASSPHRASE", "environment secret", 1)
    defer { unsetenv("KEYGATE_PASSPHRASE") }

    let policyURL = dir.appendingPathComponent("policy.json")
    try PolicyStore(url: policyURL).save([PolicyRule(name: "allow", action: .alwaysAllow)])
    let service = AgentService(
        vault: vault,
        policyStore: PolicyStore(url: policyURL),
        auditLog: AuditLog(url: dir.appendingPathComponent("audit.jsonl")),
        authorizer: AllowAllAuthorizer()
    )
    let response = service.handle(
        .sign(AgentSignRequest(keyBlob: key.agentIdentity.keyBlob, payload: Data("env".utf8), flags: 0)),
        process: ProcessIdentity(executablePath: "/usr/bin/ssh")
    )
    guard case .signature = response else {
        throw TestFailure(description: "agent should unlock with KEYGATE_PASSPHRASE")
    }
}

func testConcurrentAuditLogAndPrivatePermissions() throws {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-audit-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let url = dir.appendingPathComponent("audit.jsonl")
    let log = AuditLog(url: url)
    let errorLock = NSLock()
    var errors: [Error] = []
    DispatchQueue.concurrentPerform(iterations: 100) { index in
        do {
            try log.append(AuditEvent(keyFingerprint: "key-\(index)", process: ProcessIdentity(), destination: DestinationIdentity(), decision: .alwaysAllow, reason: "concurrent"))
        } catch {
            errorLock.lock(); errors.append(error); errorLock.unlock()
        }
    }
    try expect(errors.isEmpty, "concurrent audit append errors: \(errors)")
    let events = try log.recent(limit: 200)
    try expect(events.count == 100, "concurrent audit records must not be lost")
    let filePermissions = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
    let directoryPermissions = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? NSNumber
    try expect((filePermissions?.intValue ?? 0) & 0o777 == 0o600, "audit log must be owner-only")
    try expect((directoryPermissions?.intValue ?? 0) & 0o777 == 0o700, "audit directory must be owner-only")
}

func testProcessDisplayName() throws {
    let terminalPeer = ProcessIdentity(
        executablePath: "/usr/bin/ssh",
        terminalBundleIdentifier: "com.apple.Terminal"
    )
    try expect(ProcessResolver.displayName(terminalPeer) == "Terminal"
               || ProcessResolver.displayName(terminalPeer).contains("Terminal"),
               "displayName should resolve terminal app, got \(ProcessResolver.displayName(terminalPeer))")
    let activity = ProcessResolver.activityLabel(terminalPeer)
    try expect(activity.contains("Terminal"), "activityLabel should name terminal: \(activity)")
    try expect(activity.contains("ssh"), "activityLabel should include peer binary: \(activity)")

    let bareCLI = ProcessIdentity(executablePath: "/usr/bin/ssh")
    try expect(ProcessResolver.displayName(bareCLI) == "ssh",
               "CLI-only peer should use executable name")

    let unknown = ProcessIdentity()
    try expect(ProcessResolver.displayName(unknown) == "unknown app",
               "empty process should be unknown app")
}

func testNestedApplicationAttribution() throws {
    let helper = "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper"
    let bundles = ProcessResolver.enclosingApplicationBundlePaths(forExecutablePath: helper)
    try expect(bundles == [
        "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app",
        "/Applications/Visual Studio Code.app",
    ], "nested helpers must retain the outer owning application")

    let vscodeRule = PolicyRule(
        name: "Allow VS Code",
        appBundleIdentifier: "com.microsoft.VSCode",
		teamIdentifier: "MICROSOFT",
        action: .alwaysAllow
    )
    let helperContext = PolicyContext(
        process: ProcessIdentity(
            executablePath: "/usr/bin/ssh",
			terminalBundleIdentifier: "com.microsoft.VSCode",
			terminalTeamIdentifier: "MICROSOFT"
        ),
        destination: DestinationIdentity(),
        keyFingerprint: "SHA256:vscode",
        requestFlags: 0
    )
    try expect(PolicyEngine(rules: [vscodeRule]).decide(helperContext).action == .alwaysAllow,
               "a nested VS Code helper must be attributed to the outer VS Code rule")

	let spoofed = PolicyContext(
		process: ProcessIdentity(bundleIdentifier: "com.microsoft.VSCode"),
		destination: DestinationIdentity(),
		keyFingerprint: "SHA256:vscode",
		requestFlags: 0
	)
	try expect(PolicyEngine(rules: [vscodeRule]).decide(spoofed).action == .requireUserPresence,
	           "an unsigned bundle-ID spoof must not match an allow rule")
}

/// A client that disconnects before reading the response must not kill the agent
/// process via SIGPIPE (the historical crash when ssh/git hung up mid-exchange).
func testAgentSurvivesClientDisconnect() throws {
    signal(SIGPIPE, SIG_IGN)

    let vault = InMemoryVault()
    _ = try vault.generateEd25519(comment: "socktest", syncToCloud: false)
    let policyURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-policy-\(UUID().uuidString).json")
    let auditURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-audit-\(UUID().uuidString).jsonl")
    try PolicyStore(url: policyURL).save([
        PolicyRule(name: "allow", action: .alwaysAllow)
    ])
    let service = AgentService(
        vault: vault,
        policyStore: PolicyStore(url: policyURL),
        auditLog: AuditLog(url: auditURL),
        authorizer: AllowAllAuthorizer()
    )
    // sockaddr_un paths are capped (~104 bytes on macOS); keep this short.
    let socketURL = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("keygate-agent-\(UUID().uuidString.prefix(8))", isDirectory: true)
        .appendingPathComponent("agent.sock")
    let server = AgentSocketServer(socketURL: socketURL, service: service)
    try server.start()
    defer {
        server.stop()
        try? FileManager.default.removeItem(at: socketURL.deletingLastPathComponent())
    }
    let socketPermissions = try FileManager.default.attributesOfItem(atPath: socketURL.path)[.posixPermissions] as? NSNumber
    let directoryPermissions = try FileManager.default.attributesOfItem(atPath: socketURL.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber
    try expect((socketPermissions?.intValue ?? 0) & 0o777 == 0o600, "agent socket must be owner-only")
    try expect((directoryPermissions?.intValue ?? 0) & 0o777 == 0o700, "agent directory must be owner-only")

    // SSH_AGENTC_REQUEST_IDENTITIES (type 11), length-prefixed.
    let identitiesRequest = Data([0, 0, 0, 1, 11])

    // Connect, send a request, hang up before reading — this used to SIGPIPE the app.
    for _ in 0 ..< 3 {
        let fd = connectUnix(path: socketURL.path)
        try expect(fd >= 0, "failed to connect to agent socket")
        identitiesRequest.withUnsafeBytes { raw in
            _ = Darwin.write(fd, raw.baseAddress!, identitiesRequest.count)
        }
        close(fd)
    }

    // Give the server a moment to process the dead clients.
    Thread.sleep(forTimeInterval: 0.15)

    // Server must still answer a well-behaved client.
    let fd = connectUnix(path: socketURL.path)
    try expect(fd >= 0, "reconnect after disconnects failed")
    defer { close(fd) }
    identitiesRequest.withUnsafeBytes { raw in
        _ = Darwin.write(fd, raw.baseAddress!, identitiesRequest.count)
    }
    var lengthBytes = [UInt8](repeating: 0, count: 4)
    let n = lengthBytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, 4) }
    try expect(n == 4, "agent did not respond after client disconnects (got \(n))")
    let length = Int(lengthBytes[0]) << 24 | Int(lengthBytes[1]) << 16 | Int(lengthBytes[2]) << 8 | Int(lengthBytes[3])
    try expect(length > 0 && length < 64 * 1024, "invalid response length \(length)")
}

#if os(macOS)
private func connectUnix(path: String) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return -1 }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
        close(fd)
        return -1
    }
    let sunPathCapacity = MemoryLayout.size(ofValue: address.sun_path)
    withUnsafeMutablePointer(to: &address.sun_path) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: sunPathCapacity) { buffer in
            for index in 0 ..< pathBytes.count {
                buffer[index] = CChar(bitPattern: pathBytes[index])
            }
            buffer[pathBytes.count] = 0
        }
    }
    let result = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.connect(fd, socketAddress, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    if result != 0 {
        close(fd)
        return -1
    }
    return fd
}
#endif

func testKeyManagementOperations() throws {
    let vault = InMemoryVault()
    let key = try vault.generate(.ecdsaP256, comment: "original", syncToCloud: false)

    let renamed = try vault.rename(fingerprint: key.fingerprint, comment: "renamed")
    try expect(renamed.comment == "renamed", "rename did not update comment")

    let synced = try vault.setSync(fingerprint: key.fingerprint, syncToCloud: true)
    try expect(synced.isSynced, "setSync did not update flag")

    let line = try vault.authorizedKeysLine(fingerprint: key.fingerprint)
    try expect(line.hasPrefix("ecdsa-sha2-nistp256 AAAA"), "authorized_keys line malformed: \(line)")
    try expect(line.hasSuffix(" renamed"), "authorized_keys line missing comment: \(line)")

    try vault.delete(fingerprint: key.fingerprint)
    let remaining = try vault.listKeys()
    try expect(remaining.isEmpty, "delete did not remove key")
}

func testSetupInstaller() throws {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("keygate-setup-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }

    let profile = dir.appendingPathComponent(".zshrc")
    let socketA = "/tmp/keygate-test/agent.sock"
    let socketB = "/tmp/keygate-test/agent-b.sock"

    let first = try SetupInstaller.applyShellProfile(to: profile, socketPath: socketA)
    try expect(first.outcome == .installed, "first shell install should be installed")
    let content1 = try String(contentsOf: profile, encoding: .utf8)
    try expect(content1.contains(SetupInstaller.beginMarker), "missing begin marker")
    try expect(content1.contains("export SSH_AUTH_SOCK=\"\(socketA)\""), "missing export line")

    let second = try SetupInstaller.applyShellProfile(to: profile, socketPath: socketA)
    try expect(second.outcome == .alreadyConfigured, "repeat install should be already configured")

    let third = try SetupInstaller.applyShellProfile(to: profile, socketPath: socketB)
    try expect(third.outcome == .updated, "path change should update block")
    let content3 = try String(contentsOf: profile, encoding: .utf8)
    try expect(content3.contains(socketB), "updated path missing")
    try expect(!content3.contains(socketA), "old path should be replaced")

    // Manual snippet without markers is treated as already configured.
    let manual = dir.appendingPathComponent("manual.sh")
    try "export SSH_AUTH_SOCK=\"\(socketA)\"\n".write(to: manual, atomically: true, encoding: .utf8)
    let manualResult = try SetupInstaller.applyShellProfile(to: manual, socketPath: socketA)
    try expect(manualResult.outcome == .alreadyConfigured, "manual snippet should count as configured")

    let ssh = dir.appendingPathComponent("config")
    let sshFirst = try SetupInstaller.applySSHConfig(to: ssh, socketPath: socketA)
    try expect(sshFirst.outcome == .installed, "ssh config should install")
    let sshContent = try String(contentsOf: ssh, encoding: .utf8)
    try expect(sshContent.contains("IdentityAgent \(socketA)"), "missing IdentityAgent")

    let (upserted, outcome) = SetupInstaller.upsertMarkedBlock(
        in: "export FOO=1\n",
        body: "export BAR=2"
    )
    try expect(outcome == .installed, "upsert empty-marker content should install")
    try expect(upserted.contains(SetupInstaller.endMarker), "upsert should wrap markers")
}

func testVaultPassphraseStore() throws {
    let service = "\(VaultPassphraseStore.service).selftest.\(UUID().uuidString)"
    let account = "selftest"
    defer { _ = VaultPassphraseStore.delete(serviceName: service, accountName: account) }
    try expect(!VaultPassphraseStore.isStored(serviceName: service, accountName: account), "store should start empty")

    try VaultPassphraseStore.save("correct horse battery", serviceName: service, accountName: account)
    try expect(VaultPassphraseStore.isStored(serviceName: service, accountName: account), "store should report stored after save")
    let loaded = try VaultPassphraseStore.load(serviceName: service, accountName: account)
    try expect(loaded == "correct horse battery", "loaded passphrase mismatch: \(loaded ?? "nil")")

    // Replace in place.
    try VaultPassphraseStore.save("new secret", serviceName: service, accountName: account)
    let replaced = try VaultPassphraseStore.load(serviceName: service, accountName: account)
    try expect(replaced == "new secret", "replace should overwrite")

    try expect(VaultPassphraseStore.delete(serviceName: service, accountName: account), "delete should succeed")
    try expect(!VaultPassphraseStore.isStored(serviceName: service, accountName: account), "store should be empty after delete")
    let afterDelete = try VaultPassphraseStore.load(serviceName: service, accountName: account)
    try expect(afterDelete == nil, "load after delete should be nil")
}

func testGitSigningInstaller() throws {
    let home = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("keygate-git-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }

    // Pretend 1Password is configured so apply must replace it with Keygate’s wrapper.
    let gitconfig = home.appendingPathComponent(".gitconfig")
    try """
    [gpg "ssh"]
    \tprogram = /Applications/1Password.app/Contents/MacOS/op-ssh-sign
    [gpg]
    \tformat = openpgp
    """.write(to: gitconfig, atomically: true, encoding: .utf8)

    let before = GitSigningInstaller.status(home: home)
    try expect(!before.isConfigured, "should start unconfigured")
    try expect(GitSigningInstaller.isThirdPartySSHSignProgram(before.sshProgram ?? ""), "should detect op-ssh-sign")

    let socketPath = home.appendingPathComponent("agent.sock").path
    // Create a dummy socket path file entry isn't needed; script only checks -S at runtime.
    let pubLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILFxoOyDEW620PrgX1atOr0N5+35im37nko3KcY+odPq GitHub Signing Key"
    let result = try GitSigningInstaller.apply(
        publicKeyLine: pubLine,
        enableCommitSigning: true,
        enableTagSigning: true,
        home: home,
        socketPath: socketPath
    )
    try expect(result.outcome == .installed, "apply should install")

    let pubURL = GitSigningInstaller.publicKeyURL(home: home)
    let written = try String(contentsOf: pubURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    try expect(written == pubLine, "public key file content mismatch")

    let programURL = GitSigningInstaller.sshSignProgramURL(home: home)
    let script = try String(contentsOf: programURL, encoding: .utf8)
    try expect(script.contains(socketPath), "wrapper should pin Keygate socket")
    try expect(script.contains("ssh-keygen"), "wrapper should exec ssh-keygen")
    let attrs = try FileManager.default.attributesOfItem(atPath: programURL.path)
    let perms = attrs[.posixPermissions] as? NSNumber
    try expect((perms?.intValue ?? 0) & 0o111 != 0, "wrapper must be executable")

    let after = GitSigningInstaller.status(home: home)
    try expect(after.isConfigured, "should be configured after apply: \(after.message)")
    try expect(after.formatIsSSH, "gpg.format should be ssh")
    try expect(after.commitGPGSign, "commit.gpgsign should be true")
    try expect(after.tagGPGSign, "tag.gpgSign should be true")
    try expect(after.signingKey == pubURL.path, "signingkey should point at pub file")
    try expect(after.sshProgram == programURL.path, "gpg.ssh.program should be Keygate wrapper")
    try expect(GitSigningInstaller.isKeygateSSHSignProgram(after.sshProgram ?? ""), "should detect keygate program")
}

let tests: [(String, () throws -> Void)] = [
    ("protocol identities", testProtocolIdentities),
    ("protocol sign request", testProtocolSignRequest),
    ("mpint round trip", testMPIntRoundTrip),
    ("public blob vectors", testPublicBlobVectors),
    ("signing round trip", testSigningRoundTrip),
    ("import vectors", testImportVectors),
    ("encrypted openssh import", testEncryptedOpenSSHImport),
    ("export round trip", testExportRoundTrip),
    ("encrypted export round trip", testEncryptedExportRoundTrip),
    ("rsa key sizes", testRSAKeySizes),
    ("passphrase encryption", testPassphraseEncryption),
    ("interrupted encryption migration", testInterruptedEncryptionMigrationIsRecoverable),
    ("policy defaults and matches", testPolicyDefaultsAndMatches),
    ("vault and agent service", testVaultAndAgentService),
    ("authorization reason names app", testAuthorizationReasonNamesRequestingApp),
    ("locked vault skips Touch ID", testLockedVaultSkipsTouchID),
    ("environment passphrase unlocks agent", testEnvironmentPassphraseUnlocksAgent),
    ("concurrent audit log and private permissions", testConcurrentAuditLogAndPrivatePermissions),
    ("process display name", testProcessDisplayName),
    ("nested application attribution", testNestedApplicationAttribution),
    ("agent survives client disconnect", testAgentSurvivesClientDisconnect),
    ("key management operations", testKeyManagementOperations),
    ("setup installer", testSetupInstaller),
    ("vault passphrase store", testVaultPassphraseStore),
    ("git signing installer", testGitSigningInstaller),
]

var failures = 0
for (name, test) in tests {
    do {
        try test()
        print("PASS \(name)")
    } catch {
        failures += 1
        print("FAIL \(name): \(error)")
    }
}

if failures > 0 {
    Foundation.exit(1)
}
print("All Keygate selftests passed")
