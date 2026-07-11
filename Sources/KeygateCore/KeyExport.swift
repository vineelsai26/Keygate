import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Private-key export formats, mirroring what 1Password offers: OpenSSH
/// (optionally passphrase-encrypted), PKCS#8, and PKCS#1 (RSA only).
public enum KeyExportFormat: String, CaseIterable, Sendable {
    case openssh
    case pkcs8
    case pkcs1

    public var displayName: String {
        switch self {
        case .openssh: return "OpenSSH"
        case .pkcs8: return "PKCS#8"
        case .pkcs1: return "PKCS#1"
        }
    }
}

/// Serializes canonical private material (see `SSHSigner`) back out to standard
/// key-file formats. Only the OpenSSH container supports passphrase encryption
/// (bcrypt + aes256-ctr, the `ssh-keygen` default).
public enum KeyExporter {
    public static func export(
        type: SSHKeyType,
        privateMaterial: Data,
        comment: String,
        format: KeyExportFormat,
        passphrase: String?
    ) throws -> String {
        let passphrase = (passphrase?.isEmpty == false) ? passphrase : nil
        switch format {
        case .openssh:
            return try opensshPEM(type: type, privateMaterial: privateMaterial, comment: comment, passphrase: passphrase)
        case .pkcs8:
            guard passphrase == nil else {
                throw KeygateError.exportFailed("passphrase encryption is only supported for the OpenSSH format")
            }
            return pem(header: "PRIVATE KEY", der: try pkcs8DER(type: type, privateMaterial: privateMaterial))
        case .pkcs1:
            guard passphrase == nil else {
                throw KeygateError.exportFailed("passphrase encryption is only supported for the OpenSSH format")
            }
            guard type == .rsa else {
                throw KeygateError.exportFailed("PKCS#1 export is only available for RSA keys")
            }
            return pem(header: "RSA PRIVATE KEY", der: privateMaterial)
        }
    }

    // MARK: OpenSSH container (openssh-key-v1)

    private static func opensshPEM(type: SSHKeyType, privateMaterial: Data, comment: String, passphrase: String?) throws -> String {
        let publicBlob = try SSHSigner.publicBlob(type: type, privateMaterial: privateMaterial)

        var priv = SSHWriter()
        let check = try randomUInt32()
        priv.writeUInt32(check)
        priv.writeUInt32(check)
        priv.writeString(type.rawValue)
        try writeOpenSSHPrivateFields(&priv, type: type, privateMaterial: privateMaterial, publicBlob: publicBlob)
        priv.writeString(comment)

        let cipherName: String
        let kdfName: String
        var kdfOptions = Data()
        var section: Data

        if let passphrase {
            cipherName = "aes256-ctr"
            kdfName = "bcrypt"
            let cipher = try OpenSSHKeyFile.Cipher(name: cipherName)
            let salt = try randomBytes(16)
            let rounds: UInt32 = 16 // ssh-keygen's default work factor
            var options = SSHWriter()
            options.writeDataString(salt)
            options.writeUInt32(rounds)
            kdfOptions = options.finish()

            section = pad(priv.finish(), to: 16)
            let derived = try Bcrypt.pbkdf(passphrase: Data(passphrase.utf8), salt: salt, rounds: rounds, length: cipher.keyLength + cipher.ivLength)
            let key = Data(derived.prefix(cipher.keyLength))
            let iv = Data(derived.dropFirst(cipher.keyLength).prefix(cipher.ivLength))
            section = try OpenSSHKeyFile.aesCrypt(CCOperation(kCCEncrypt), mode: cipher.mode, key: key, iv: iv, data: section)
        } else {
            cipherName = "none"
            kdfName = "none"
            section = pad(priv.finish(), to: 8)
        }

        var container = SSHWriter()
        for byte in "openssh-key-v1\u{0}".utf8 { container.writeByte(byte) }
        container.writeString(cipherName)
        container.writeString(kdfName)
        container.writeDataString(kdfOptions)
        container.writeUInt32(1)
        container.writeDataString(publicBlob)
        container.writeDataString(section)

        let base64 = wrap(container.finish().base64EncodedString(), width: 70)
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(base64)\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    private static func writeOpenSSHPrivateFields(_ writer: inout SSHWriter, type: SSHKeyType, privateMaterial: Data, publicBlob: Data) throws {
        switch type {
        case .ed25519:
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateMaterial)
            let publicKey = key.publicKey.rawRepresentation
            writer.writeDataString(publicKey)
            writer.writeDataString(privateMaterial + publicKey) // seed || public, 64 bytes
        case .ecdsaP256, .ecdsaP384, .ecdsaP521:
            // Q is already inside the public blob; reuse it rather than re-deriving.
            var reader = SSHReader(publicBlob)
            _ = try reader.readString() // key type
            _ = try reader.readString() // curve name
            let point = try reader.readDataString()
            writer.writeString(type.curveName ?? "")
            writer.writeDataString(point)
            writer.writeMPInt(privateMaterial)
        case .rsa:
            let (n, e, d, p, q, iqmp) = try ASN1.rsaPrivateComponents(fromPKCS1: privateMaterial)
            writer.writeMPInt(n)
            writer.writeMPInt(e)
            writer.writeMPInt(d)
            writer.writeMPInt(iqmp)
            writer.writeMPInt(p)
            writer.writeMPInt(q)
        }
    }

    /// Appends the sequential 1, 2, 3… padding OpenSSH requires up to `blockSize`.
    private static func pad(_ data: Data, to blockSize: Int) -> Data {
        var padded = data
        var padByte: UInt8 = 1
        while padded.count % blockSize != 0 {
            padded.append(padByte)
            padByte &+= 1
        }
        return padded
    }

    // MARK: PKCS#8

    private enum OID {
        static let rsaEncryption: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        static let ecPublicKey: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        static let prime256v1: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        static let secp384r1: [UInt8] = [0x2B, 0x81, 0x04, 0x00, 0x22]
        static let secp521r1: [UInt8] = [0x2B, 0x81, 0x04, 0x00, 0x23]
        static let ed25519: [UInt8] = [0x2B, 0x65, 0x70]
    }

    static func pkcs8DER(type: SSHKeyType, privateMaterial: Data) throws -> Data {
        switch type {
        case .rsa:
            return ASN1.sequence([
                ASN1.integer(Data([0])),
                ASN1.sequence([ASN1.objectIdentifier(OID.rsaEncryption), ASN1.null()]),
                ASN1.octetString(privateMaterial),
            ])
        case .ed25519:
            // RFC 8410: privateKey is an OCTET STRING that itself wraps the seed.
            return ASN1.sequence([
                ASN1.integer(Data([0])),
                ASN1.sequence([ASN1.objectIdentifier(OID.ed25519)]),
                ASN1.octetString(ASN1.octetString(privateMaterial)),
            ])
        case .ecdsaP256, .ecdsaP384, .ecdsaP521:
            let (curveOID, point) = try ecCurveInfo(type: type, privateMaterial: privateMaterial)
            // SEC1 ECPrivateKey; curve parameters live in the outer AlgorithmIdentifier.
            let sec1 = ASN1.sequence([
                ASN1.integer(Data([1])),
                ASN1.octetString(privateMaterial),
                ASN1.contextConstructed(1, ASN1.bitString(point)),
            ])
            return ASN1.sequence([
                ASN1.integer(Data([0])),
                ASN1.sequence([ASN1.objectIdentifier(OID.ecPublicKey), ASN1.objectIdentifier(curveOID)]),
                ASN1.octetString(sec1),
            ])
        }
    }

    private static func ecCurveInfo(type: SSHKeyType, privateMaterial: Data) throws -> (oid: [UInt8], point: Data) {
        switch type {
        case .ecdsaP256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return (OID.prime256v1, key.publicKey.x963Representation)
        case .ecdsaP384:
            let key = try P384.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return (OID.secp384r1, key.publicKey.x963Representation)
        case .ecdsaP521:
            let key = try P521.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return (OID.secp521r1, key.publicKey.x963Representation)
        default:
            throw KeygateError.exportFailed("not an ECDSA key")
        }
    }

    // MARK: Helpers

    private static func pem(header: String, der: Data) -> String {
        let base64 = wrap(der.base64EncodedString(), width: 64)
        return "-----BEGIN \(header)-----\n\(base64)\n-----END \(header)-----\n"
    }

    private static func wrap(_ base64: String, width: Int) -> String {
        var lines: [String] = []
        var remainder = Substring(base64)
        while !remainder.isEmpty {
            lines.append(String(remainder.prefix(width)))
            remainder = remainder.dropFirst(width)
        }
        return lines.joined(separator: "\n")
    }

    private static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw KeygateError.exportFailed("secure random generation failed")
        }
        return Data(bytes)
    }

    private static func randomUInt32() throws -> UInt32 {
        let bytes = try randomBytes(4)
        return bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
}
