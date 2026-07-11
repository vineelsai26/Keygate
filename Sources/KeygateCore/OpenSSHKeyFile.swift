import CommonCrypto
import Foundation

/// Parser for OpenSSH's native private key container (`-----BEGIN OPENSSH PRIVATE KEY-----`,
/// the `openssh-key-v1` binary format). Handles unencrypted keys and, when the bcrypt
/// component is available, keys encrypted with `bcrypt` + an AES cipher.
enum OpenSSHKeyFile {
    private static let magic = Array("openssh-key-v1\u{0}".utf8) // 15 bytes incl. NUL
    /// OpenSSH's default is 16; reject pathological imported files before the
    /// deliberately expensive bcrypt_pbkdf loop can monopolize the process.
    private static let maxBcryptRounds: UInt32 = 1_000

    static func parse(_ text: String, passphrase: String?) throws -> ImportedKey {
        let body = try base64Body(text)
        var reader = SSHReader(body)
        for expected in magic {
            guard try reader.readByte() == expected else {
                throw KeygateError.importFailed("not an openssh-key-v1 file")
            }
        }

        let cipherName = try reader.readString()
        let kdfName = try reader.readString()
        let kdfOptions = try reader.readDataString()
        let keyCount = try reader.readUInt32()
        guard keyCount >= 1 else { throw KeygateError.importFailed("no keys in file") }
        for _ in 0 ..< keyCount { _ = try reader.readDataString() } // public blobs; derived from private
        let encrypted = try reader.readDataString()

        let privateSection = try decryptPrivateSection(
            encrypted,
            cipherName: cipherName,
            kdfName: kdfName,
            kdfOptions: kdfOptions,
            passphrase: passphrase
        )

        var priv = SSHReader(privateSection)
        let check1 = try priv.readUInt32()
        let check2 = try priv.readUInt32()
        guard check1 == check2 else { throw KeygateError.wrongPassphrase }

        // Only the first key in the container is imported.
        let keyType = try priv.readString()
        return try readPrivateKey(type: keyType, reader: &priv)
    }

    // MARK: Decryption

    private static func decryptPrivateSection(
        _ encrypted: Data,
        cipherName: String,
        kdfName: String,
        kdfOptions: Data,
        passphrase: String?
    ) throws -> Data {
        if cipherName == "none" { return encrypted }
        guard kdfName == "bcrypt" else { throw KeygateError.importFailed("unsupported KDF \(kdfName)") }
        guard let passphrase, !passphrase.isEmpty else { throw KeygateError.wrongPassphrase }

        let cipher = try Cipher(name: cipherName)
        var options = SSHReader(kdfOptions)
        let salt = try options.readDataString()
        let rounds = try options.readUInt32()
        guard rounds > 0 && rounds <= maxBcryptRounds else {
            throw KeygateError.importFailed("OpenSSH bcrypt rounds must be between 1 and \(maxBcryptRounds)")
        }
        let derived = try Bcrypt.pbkdf(passphrase: Data(passphrase.utf8), salt: salt, rounds: rounds, length: cipher.keyLength + cipher.ivLength)
        let key = derived.prefix(cipher.keyLength)
        let iv = derived.dropFirst(cipher.keyLength).prefix(cipher.ivLength)
        return try aesCrypt(CCOperation(kCCDecrypt), mode: cipher.mode, key: Data(key), iv: Data(iv), data: encrypted)
    }

    struct Cipher {
        let keyLength: Int
        let ivLength: Int
        let mode: AESMode

        init(name: String) throws {
            switch name {
            case "aes256-ctr": (keyLength, ivLength, mode) = (32, 16, .ctr)
            case "aes192-ctr": (keyLength, ivLength, mode) = (24, 16, .ctr)
            case "aes128-ctr": (keyLength, ivLength, mode) = (16, 16, .ctr)
            case "aes256-cbc": (keyLength, ivLength, mode) = (32, 16, .cbc)
            case "aes128-cbc": (keyLength, ivLength, mode) = (16, 16, .cbc)
            default: throw KeygateError.importFailed("unsupported cipher \(name)")
            }
        }
    }

    enum AESMode { case ctr, cbc }

    static func aesCrypt(_ operation: CCOperation, mode: AESMode, key: Data, iv: Data, data: Data) throws -> Data {
        var cryptorRef: CCCryptorRef?
        let ccMode = mode == .ctr ? CCMode(kCCModeCTR) : CCMode(kCCModeCBC)
        let modeOptions: CCModeOptions = mode == .ctr ? CCModeOptions(kCCModeOptionCTR_BE) : 0
        let createStatus = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    operation, ccMode, CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBuffer.baseAddress, keyBuffer.baseAddress, key.count,
                    nil, 0, 0, modeOptions, &cryptorRef
                )
            }
        }
        guard createStatus == kCCSuccess, let cryptor = cryptorRef else {
            throw KeygateError.importFailed("AES init failed (\(createStatus))")
        }
        defer { CCCryptorRelease(cryptor) }

        var output = Data(count: data.count)
        let outputCapacity = output.count
        var moved = 0
        let updateStatus = output.withUnsafeMutableBytes { outBuffer in
            data.withUnsafeBytes { inBuffer in
                CCCryptorUpdate(cryptor, inBuffer.baseAddress, data.count, outBuffer.baseAddress, outputCapacity, &moved)
            }
        }
        guard updateStatus == kCCSuccess else { throw KeygateError.importFailed("AES operation failed (\(updateStatus))") }
        return output.prefix(moved)
    }

    // MARK: Private key fields

    private static func readPrivateKey(type: String, reader: inout SSHReader) throws -> ImportedKey {
        switch type {
        case SSHKeyType.ed25519.rawValue:
            _ = try reader.readDataString()          // public Q
            let priv = try reader.readDataString()   // 64 bytes: seed || public
            guard priv.count >= 32 else { throw KeygateError.invalidPrivateKey }
            let comment = try? reader.readString()
            return ImportedKey(keyType: .ed25519, privateMaterial: priv.prefix(32), comment: comment)

        case SSHKeyType.ecdsaP256.rawValue, SSHKeyType.ecdsaP384.rawValue, SSHKeyType.ecdsaP521.rawValue:
            _ = try reader.readString()              // curve identifier
            _ = try reader.readDataString()          // Q point
            let scalar = try reader.readMPInt()      // private scalar magnitude
            let comment = try? reader.readString()
            let (keyType, width): (SSHKeyType, Int)
            switch type {
            case SSHKeyType.ecdsaP256.rawValue: (keyType, width) = (.ecdsaP256, 32)
            case SSHKeyType.ecdsaP384.rawValue: (keyType, width) = (.ecdsaP384, 48)
            default: (keyType, width) = (.ecdsaP521, 66)
            }
            return ImportedKey(keyType: keyType, privateMaterial: leftPad(scalar, to: width), comment: comment)

        case SSHKeyType.rsa.rawValue:
            let n = try reader.readMPInt()
            let e = try reader.readMPInt()
            let d = try reader.readMPInt()
            let iqmp = try reader.readMPInt()
            let p = try reader.readMPInt()
            let q = try reader.readMPInt()
            let comment = try? reader.readString()
            let pkcs1 = rsaPKCS1(n: n, e: e, d: d, p: p, q: q, iqmp: iqmp)
            return ImportedKey(keyType: .rsa, privateMaterial: pkcs1, comment: comment)

        default:
            throw KeygateError.unsupportedKeyType(type)
        }
    }

    /// Builds a PKCS#1 `RSAPrivateKey` DER, computing the CRT exponents dP/dQ that
    /// OpenSSH does not store (it keeps iqmp = coefficient).
    private static func rsaPKCS1(n: Data, e: Data, d: Data, p: Data, q: Data, iqmp: Data) -> Data {
        let dValue = BigUInt(d)
        let dp = dValue.modulo(BigUInt(p).subtracting(1)).toData()
        let dq = dValue.modulo(BigUInt(q).subtracting(1)).toData()
        return ASN1.sequence([
            ASN1.integer(Data([0])), // version
            ASN1.integer(n),
            ASN1.integer(e),
            ASN1.integer(d),
            ASN1.integer(p),
            ASN1.integer(q),
            ASN1.integer(dp),
            ASN1.integer(dq),
            ASN1.integer(iqmp),
        ])
    }

    // MARK: Helpers

    private static func leftPad(_ data: Data, to length: Int) -> Data {
        if data.count >= length { return data.suffix(length) }
        return Data(repeating: 0, count: length - data.count) + data
    }

    private static func base64Body(_ text: String) throws -> Data {
        var collecting = false
        var base64 = ""
        for line in text.split(whereSeparator: \.isNewline) {
            if line.contains("BEGIN OPENSSH PRIVATE KEY") { collecting = true; continue }
            if line.contains("END OPENSSH PRIVATE KEY") { break }
            if collecting { base64 += line.trimmingCharacters(in: .whitespaces) }
        }
        guard let data = Data(base64Encoded: base64) else {
            throw KeygateError.importFailed("invalid base64 in OpenSSH key")
        }
        return data
    }
}
