import CryptoKit
import Foundation
import Security

/// A private key recovered from an imported file, in Keygate's canonical
/// per-type private-material encoding (see `SSHSigner`).
public struct ImportedKey {
    public let keyType: SSHKeyType
    public let privateMaterial: Data
    public let comment: String?

    public init(keyType: SSHKeyType, privateMaterial: Data, comment: String?) {
        self.keyType = keyType
        self.privateMaterial = privateMaterial
        self.comment = comment
    }
}

/// Parses private keys from paste/file text in the formats 1Password supports:
/// OpenSSH `openssh-key-v1` (via `OpenSSHKeyFile`) and PEM PKCS#1/PKCS#8/SEC1,
/// encrypted or not (via Apple's `SecItemImport`).
public enum KeyImporter {
    public static func parse(text: String, passphrase: String?) throws -> ImportedKey {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw KeygateError.unsupportedImportFormat }

        // OpenSSH's own container must be checked before the generic PEM path.
        if trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
            return try OpenSSHKeyFile.parse(trimmed, passphrase: passphrase)
        }
        if trimmed.contains("PRIVATE KEY-----") {
            return try PEMImporter.parse(text: trimmed, passphrase: passphrase)
        }
        throw KeygateError.unsupportedImportFormat
    }
}

/// PEM importer backed by `SecItemImport`, which auto-detects PKCS#1/PKCS#8/SEC1
/// and decrypts passphrase-protected keys.
enum PEMImporter {
    // CSSM key attributes: keys SecItemImport creates are otherwise non-extractable,
    // so SecKeyCopyExternalRepresentation fails. Requesting these yields a modern,
    // extractable key whose bytes we can persist.
    private static let cssmKeyAttrExtractable = 0x0000_0020
    private static let cssmKeyAttrReturnData = 0x1000_0000

    static func parse(text: String, passphrase: String?) throws -> ImportedKey {
        // SecItemImport rejects files that carry extra PEM blocks (e.g. the
        // `EC PARAMETERS` block openssl emits), so isolate the private-key block.
        guard let data = isolatePrivateKeyBlock(text) else { throw KeygateError.unsupportedImportFormat }
        let blockText = String(decoding: data, as: UTF8.self)

        // SecItemImport can't parse modern PBES2 (PBKDF2 + AES) encrypted PKCS#8,
        // so decrypt it ourselves and re-import the resulting plaintext PKCS#8.
        if blockText.contains("ENCRYPTED PRIVATE KEY") {
            guard let passphrase, !passphrase.isEmpty else { throw KeygateError.wrongPassphrase }
            guard let der = pemBodyDER(blockText) else { throw KeygateError.importFailed("invalid base64 in PEM") }
            let plaintext = try PBES2.decrypt(der, passphrase: passphrase)
            let pkcs8PEM = "-----BEGIN PRIVATE KEY-----\n"
                + plaintext.base64EncodedString(options: .lineLength64Characters)
                + "\n-----END PRIVATE KEY-----\n"
            return try parse(text: pkcs8PEM, passphrase: nil)
        }

        // SecItemImport predates Ed25519 and rejects EC-in-PKCS#8 (it only takes
        // SEC1 "EC PRIVATE KEY"), so those PKCS#8 shapes are parsed directly.
        if blockText.contains("BEGIN PRIVATE KEY"),
           let der = pemBodyDER(blockText),
           let parsed = try keyFromPKCS8(der) {
            return parsed
        }

        var keyParams = SecItemImportExportKeyParameters()
        keyParams.version = 0
        let cfPassphrase = passphrase as CFString?
        if let cfPassphrase {
            keyParams.passphrase = Unmanaged.passUnretained(cfPassphrase)
        }
        let keyAttributes = [NSNumber(value: cssmKeyAttrExtractable), NSNumber(value: cssmKeyAttrReturnData)] as CFArray
        keyParams.keyAttributes = Unmanaged.passUnretained(keyAttributes)

        var inputFormat: SecExternalFormat = .formatUnknown
        var itemType: SecExternalItemType = .itemTypeUnknown
        var items: CFArray?
        let status = SecItemImport(data as CFData, nil, &inputFormat, &itemType, SecItemImportExportFlags(), &keyParams, nil, &items)
        withExtendedLifetime((cfPassphrase, keyAttributes)) {} // keep params alive across the call

        guard status == errSecSuccess else {
            if passphrase != nil && (status == errSecAuthFailed || status == errSecPassphraseRequired || status == errSecDecode) {
                throw KeygateError.wrongPassphrase
            }
            if status == errSecPassphraseRequired {
                throw KeygateError.wrongPassphrase
            }
            throw KeygateError.importFailed("SecItemImport failed (\(status))")
        }

        guard let array = items as? [AnyObject] else { throw KeygateError.unsupportedImportFormat }
        for element in array where CFGetTypeID(element) == SecKeyGetTypeID() {
            return try importedKey(from: element as! SecKey)
        }
        throw KeygateError.unsupportedImportFormat
    }

    /// Parses PKCS#8 algorithms SecItemImport cannot: RFC 8410 Ed25519
    /// (`OCTET STRING { OCTET STRING seed }`) and RFC 5915 EC keys (SEC1
    /// `ECPrivateKey` with the curve named in the AlgorithmIdentifier).
    /// Returns nil for anything else so SecItemImport can take over.
    private static func keyFromPKCS8(_ der: Data) throws -> ImportedKey? {
        let ed25519OID = Data([0x2B, 0x65, 0x70])
        let ecPublicKeyOID = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        let algorithmOID: Data
        var algorithm: ASN1.Reader
        let wrapped: Data
        do {
            var outer = ASN1.Reader(der)
            var top = ASN1.Reader(try outer.readTLV(expect: ASN1.sequenceTag))
            _ = try top.readTLV(expect: ASN1.integerTag) // version
            algorithm = ASN1.Reader(try top.readTLV(expect: ASN1.sequenceTag))
            algorithmOID = try algorithm.readTLV(expect: ASN1.oidTag)
            wrapped = try top.readTLV(expect: ASN1.octetStringTag)
        } catch {
            return nil // not PKCS#8-shaped; let SecItemImport report the real error
        }

        if algorithmOID == ed25519OID {
            var inner = ASN1.Reader(wrapped)
            let seed = try inner.readTLV(expect: ASN1.octetStringTag)
            guard seed.count == 32 else { throw KeygateError.invalidPrivateKey }
            let key = try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            return ImportedKey(keyType: .ed25519, privateMaterial: key.rawRepresentation, comment: nil)
        }

        if algorithmOID == ecPublicKeyOID {
            let curveOID = try algorithm.readTLV(expect: ASN1.oidTag)
            let (keyType, width): (SSHKeyType, Int)
            switch Array(curveOID) {
            case [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]: (keyType, width) = (.ecdsaP256, 32)
            case [0x2B, 0x81, 0x04, 0x00, 0x22]: (keyType, width) = (.ecdsaP384, 48)
            case [0x2B, 0x81, 0x04, 0x00, 0x23]: (keyType, width) = (.ecdsaP521, 66)
            default: throw KeygateError.unsupportedKeyType("unrecognized EC curve")
            }
            var sec1 = ASN1.Reader(try {
                var inner = ASN1.Reader(wrapped)
                return try inner.readTLV(expect: ASN1.sequenceTag)
            }())
            _ = try sec1.readTLV(expect: ASN1.integerTag) // ECPrivateKey version 1
            var scalar = try sec1.readTLV(expect: ASN1.octetStringTag)
            if scalar.count < width { scalar = Data(repeating: 0, count: width - scalar.count) + scalar }
            guard scalar.count == width else { throw KeygateError.invalidPrivateKey }
            switch keyType {
            case .ecdsaP256:
                return ImportedKey(keyType: keyType, privateMaterial: try P256.Signing.PrivateKey(rawRepresentation: scalar).rawRepresentation, comment: nil)
            case .ecdsaP384:
                return ImportedKey(keyType: keyType, privateMaterial: try P384.Signing.PrivateKey(rawRepresentation: scalar).rawRepresentation, comment: nil)
            default:
                return ImportedKey(keyType: keyType, privateMaterial: try P521.Signing.PrivateKey(rawRepresentation: scalar).rawRepresentation, comment: nil)
            }
        }

        return nil
    }

    /// Returns just the first `-----BEGIN … PRIVATE KEY-----` block (with delimiters),
    /// dropping any surrounding blocks such as `EC PARAMETERS`.
    private static func isolatePrivateKeyBlock(_ text: String) -> Data? {
        var collecting = false
        var block: [String] = []
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            if !collecting {
                if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                    collecting = true
                    block.append(line)
                }
            } else {
                block.append(line)
                if line.contains("-----END") && line.contains("PRIVATE KEY-----") {
                    return Data((block.joined(separator: "\n") + "\n").utf8)
                }
            }
        }
        return nil
    }

    /// Base64 body of a single PEM block, decoded to DER.
    private static func pemBodyDER(_ block: String) -> Data? {
        var base64 = ""
        for rawLine in block.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----") { continue }
            base64 += line
        }
        return Data(base64Encoded: base64)
    }

    private static func importedKey(from key: SecKey) throws -> ImportedKey {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
            throw KeygateError.importFailed("no key attributes")
        }
        let keyTypeValue = attributes[kSecAttrKeyType] as? String
        let sizeInBits = attributes[kSecAttrKeySizeInBits] as? Int ?? 0
        let external = try SSHSigner.secKeyExternalRepresentation(key)

        if keyTypeValue == (kSecAttrKeyTypeRSA as String) {
            // External representation of an RSA private key is PKCS#1 DER — our canonical form.
            return ImportedKey(keyType: .rsa, privateMaterial: external, comment: nil)
        }
        if keyTypeValue == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            // External representation is X9.63 (0x04 || X || Y || K); hand to CryptoKit.
            switch sizeInBits {
            case 256:
                let key = try P256.Signing.PrivateKey(x963Representation: external)
                return ImportedKey(keyType: .ecdsaP256, privateMaterial: key.rawRepresentation, comment: nil)
            case 384:
                let key = try P384.Signing.PrivateKey(x963Representation: external)
                return ImportedKey(keyType: .ecdsaP384, privateMaterial: key.rawRepresentation, comment: nil)
            case 521:
                let key = try P521.Signing.PrivateKey(x963Representation: external)
                return ImportedKey(keyType: .ecdsaP521, privateMaterial: key.rawRepresentation, comment: nil)
            default:
                throw KeygateError.unsupportedKeyType("ecdsa-\(sizeInBits)")
            }
        }
        throw KeygateError.unsupportedImportFormat
    }
}
