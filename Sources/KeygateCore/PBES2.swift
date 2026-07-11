import CommonCrypto
import Foundation

/// Decrypts a PKCS#8 `EncryptedPrivateKeyInfo` that uses PBES2 (PBKDF2 + AES-CBC) —
/// the scheme `openssl`/`ssh-keygen` produce for encrypted PEM keys, which the legacy
/// `SecItemImport` cannot parse. Returns the plaintext PKCS#8 `PrivateKeyInfo` DER.
enum PBES2 {
    /// Allows well above the current 600k default while bounding work from
    /// attacker-controlled encrypted PEM input.
    private static let maxPBKDF2Iterations = 2_000_000
    // OID content bytes (without the 0x06/length prefix).
    private static let oidPBES2: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d]
    private static let oidPBKDF2: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c]
    private static let oidHMACSHA1: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07]
    private static let oidHMACSHA256: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09]
    private static let oidHMACSHA512: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b]
    private static let oidAES128CBC: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]
    private static let oidAES192CBC: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16]
    private static let oidAES256CBC: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]

    static func decrypt(_ encryptedPrivateKeyInfo: Data, passphrase: String) throws -> Data {
        // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData OCTET STRING }
        var top = ASN1.Reader(encryptedPrivateKeyInfo)
        var epki = ASN1.Reader(try top.readTLV(expect: ASN1.sequenceTag))
        var algorithm = ASN1.Reader(try epki.readTLV(expect: ASN1.sequenceTag))
        let encryptedData = try epki.readTLV(expect: ASN1.octetStringTag)

        guard try Array(algorithm.readTLV(expect: ASN1.oidTag)) == oidPBES2 else {
            throw KeygateError.importFailed("unsupported PEM encryption (not PBES2)")
        }

        // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
        var params = ASN1.Reader(try algorithm.readTLV(expect: ASN1.sequenceTag))
        var kdf = ASN1.Reader(try params.readTLV(expect: ASN1.sequenceTag))
        guard try Array(kdf.readTLV(expect: ASN1.oidTag)) == oidPBKDF2 else {
            throw KeygateError.importFailed("unsupported PBES2 KDF (not PBKDF2)")
        }

        // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
        //                              keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier OPTIONAL }
        var kdfParams = ASN1.Reader(try kdf.readTLV(expect: ASN1.sequenceTag))
        let salt = try kdfParams.readTLV(expect: ASN1.octetStringTag)
        let iterations = try kdfParams.readInt()
        guard iterations > 0 && iterations <= maxPBKDF2Iterations else {
            throw KeygateError.importFailed("PBKDF2 iterations must be between 1 and \(maxPBKDF2Iterations)")
        }
        var prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        while !kdfParams.isAtEnd {
            let (tag, value) = try kdfParams.read()
            if tag == ASN1.sequenceTag {
                var prfReader = ASN1.Reader(value)
                prf = try pseudoRandom(from: Array(prfReader.readTLV(expect: ASN1.oidTag)))
            }
            // A keyLength INTEGER, if present, is ignored: the cipher fixes the key size.
        }

        // encryptionScheme ::= SEQUENCE { OID cipher, IV OCTET STRING }
        var scheme = ASN1.Reader(try params.readTLV(expect: ASN1.sequenceTag))
        let cipherOID = try Array(scheme.readTLV(expect: ASN1.oidTag))
        let iv = try scheme.readTLV(expect: ASN1.octetStringTag)
        let keyLength = try aesKeyLength(for: cipherOID)

        let derivedKey = try pbkdf2(passphrase: passphrase, salt: salt, iterations: iterations, keyLength: keyLength, prf: prf)
        return try aesCBCDecrypt(key: derivedKey, iv: iv, data: encryptedData)
    }

    private static func pseudoRandom(from oid: [UInt8]) throws -> CCPseudoRandomAlgorithm {
        switch oid {
        case oidHMACSHA1: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case oidHMACSHA256: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case oidHMACSHA512: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        default: throw KeygateError.importFailed("unsupported PBKDF2 PRF")
        }
    }

    private static func aesKeyLength(for oid: [UInt8]) throws -> Int {
        switch oid {
        case oidAES128CBC: return 16
        case oidAES192CBC: return 24
        case oidAES256CBC: return 32
        default: throw KeygateError.importFailed("unsupported PBES2 cipher")
        }
    }

    private static func pbkdf2(passphrase: String, salt: Data, iterations: Int, keyLength: Int, prf: CCPseudoRandomAlgorithm) throws -> Data {
        let passwordBytes = Array(passphrase.utf8)
        var derived = [UInt8](repeating: 0, count: keyLength)
        let status = salt.withUnsafeBytes { saltBuffer -> Int32 in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passwordBytes.isEmpty ? "" : passphrase, passwordBytes.count,
                saltBuffer.bindMemory(to: UInt8.self).baseAddress, salt.count,
                prf, UInt32(iterations),
                &derived, keyLength
            )
        }
        guard status == kCCSuccess else { throw KeygateError.importFailed("PBKDF2 failed (\(status))") }
        return Data(derived)
    }

    private static func aesCBCDecrypt(key: Data, iv: Data, data: Data) throws -> Data {
        var output = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var moved = 0
        let status = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                data.withUnsafeBytes { dataBuffer in
                    CCCrypt(
                        CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                        keyBuffer.baseAddress, key.count,
                        ivBuffer.baseAddress,
                        dataBuffer.baseAddress, data.count,
                        &output, output.count, &moved
                    )
                }
            }
        }
        // A wrong passphrase yields invalid PKCS#7 padding -> kCCDecodeError.
        guard status == kCCSuccess else { throw KeygateError.wrongPassphrase }
        return Data(output.prefix(moved))
    }
}
