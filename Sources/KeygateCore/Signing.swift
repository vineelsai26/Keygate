import CryptoKit
import Foundation
import Security

/// Per-algorithm key generation, public-blob derivation, and SSH-agent signing.
///
/// Canonical private material stored in the Keychain, by type:
///   - ed25519: 32-byte seed (`rawRepresentation`)
///   - ecdsa:   `rawRepresentation` (raw private scalar, fixed width per curve)
///   - rsa:     PKCS#1 `RSAPrivateKey` DER
///
/// RSA signing reconstructs a *transient* `SecKey` from the DER we already fetched,
/// so signing never triggers a second Touch ID prompt (the gated read already happened).
public enum SSHSigner {
    public struct GeneratedKey {
        public let privateMaterial: Data
        public let publicBlob: Data
    }

    // MARK: Generate

    /// RSA moduli offered on generation, matching 1Password's choices.
    public static let supportedRSABits = [2048, 3072, 4096]
    public static let defaultRSABits = 3072

    public static func generate(_ type: SSHKeyType, rsaBits: Int = SSHSigner.defaultRSABits) throws -> GeneratedKey {
        switch type {
        case .ed25519:
            let key = Curve25519.Signing.PrivateKey()
            return GeneratedKey(
                privateMaterial: key.rawRepresentation,
                publicBlob: SSHPublicKeyBlob.ed25519(key.publicKey.rawRepresentation)
            )
        case .ecdsaP256:
            let key = P256.Signing.PrivateKey()
            return GeneratedKey(privateMaterial: key.rawRepresentation,
                                publicBlob: SSHPublicKeyBlob.ecdsa(type, point: key.publicKey.x963Representation))
        case .ecdsaP384:
            let key = P384.Signing.PrivateKey()
            return GeneratedKey(privateMaterial: key.rawRepresentation,
                                publicBlob: SSHPublicKeyBlob.ecdsa(type, point: key.publicKey.x963Representation))
        case .ecdsaP521:
            let key = P521.Signing.PrivateKey()
            return GeneratedKey(privateMaterial: key.rawRepresentation,
                                publicBlob: SSHPublicKeyBlob.ecdsa(type, point: key.publicKey.x963Representation))
        case .rsa:
            guard supportedRSABits.contains(rsaBits) else {
                throw KeygateError.unsupportedKeyType("rsa-\(rsaBits) (choose \(supportedRSABits.map(String.init).joined(separator: ", ")))")
            }
            var error: Unmanaged<CFError>?
            let attrs: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: rsaBits,
            ]
            guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
                throw KeygateError.keychainFailure(cfErrorMessage(error) ?? "RSA key generation failed")
            }
            return GeneratedKey(
                privateMaterial: try secKeyExternalRepresentation(priv),
                publicBlob: try rsaPublicBlob(fromPrivate: priv)
            )
        }
    }

    // MARK: Public blob from private material (used on import)

    public static func publicBlob(type: SSHKeyType, privateMaterial: Data) throws -> Data {
        switch type {
        case .ed25519:
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SSHPublicKeyBlob.ed25519(key.publicKey.rawRepresentation)
        case .ecdsaP256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SSHPublicKeyBlob.ecdsa(type, point: key.publicKey.x963Representation)
        case .ecdsaP384:
            let key = try P384.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SSHPublicKeyBlob.ecdsa(type, point: key.publicKey.x963Representation)
        case .ecdsaP521:
            let key = try P521.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SSHPublicKeyBlob.ecdsa(type, point: key.publicKey.x963Representation)
        case .rsa:
            return try rsaPublicBlob(fromPrivate: try rsaSecKey(fromPKCS1: privateMaterial))
        }
    }

    // MARK: Sign

    public static func sign(type: SSHKeyType, privateMaterial: Data, payload: Data, flags: UInt32) throws -> SignatureResult {
        switch type {
        case .ed25519:
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SignatureResult(algorithm: type.rawValue, signature: try key.signature(for: payload))
        case .ecdsaP256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SignatureResult(algorithm: type.rawValue, signature: ecdsaSignatureBlob(try key.signature(for: payload).rawRepresentation))
        case .ecdsaP384:
            let key = try P384.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SignatureResult(algorithm: type.rawValue, signature: ecdsaSignatureBlob(try key.signature(for: payload).rawRepresentation))
        case .ecdsaP521:
            let key = try P521.Signing.PrivateKey(rawRepresentation: privateMaterial)
            return SignatureResult(algorithm: type.rawValue, signature: ecdsaSignatureBlob(try key.signature(for: payload).rawRepresentation))
        case .rsa:
            let priv = try rsaSecKey(fromPKCS1: privateMaterial)
            let (algorithmName, secAlgorithm) = rsaAlgorithm(for: flags)
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(priv, secAlgorithm, payload as CFData, &error) as Data? else {
                throw KeygateError.signingDenied(cfErrorMessage(error) ?? "RSA signing failed")
            }
            return SignatureResult(algorithm: algorithmName, signature: signature)
        }
    }

    /// Selects the RSA signature algorithm from the agent flags.
    /// SHA-512 (flag 4) wins over SHA-256 (flag 2); flags 0 is legacy SHA-1 `ssh-rsa`.
    static func rsaAlgorithm(for flags: UInt32) -> (name: String, algorithm: SecKeyAlgorithm) {
        if flags & SignatureFlag.rsaSHA512.rawValue != 0 {
            return ("rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512)
        }
        if flags & SignatureFlag.rsaSHA256.rawValue != 0 {
            return ("rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256)
        }
        return ("ssh-rsa", .rsaSignatureMessagePKCS1v15SHA1)
    }

    // MARK: Helpers

    /// ECDSA agent signature inner blob: `mpint r` + `mpint s` split from CryptoKit's fixed-width `r||s`.
    private static func ecdsaSignatureBlob(_ rawRS: Data) -> Data {
        let half = rawRS.count / 2
        var writer = SSHWriter()
        writer.writeMPInt(Data(rawRS.prefix(half)))
        writer.writeMPInt(Data(rawRS.dropFirst(half)))
        return writer.finish()
    }

    static func rsaSecKey(fromPKCS1 der: Data) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
            throw KeygateError.invalidPrivateKey
        }
        return key
    }

    static func secKeyExternalRepresentation(_ key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw KeygateError.keychainFailure(cfErrorMessage(error) ?? "SecKeyCopyExternalRepresentation failed")
        }
        return data
    }

    /// Builds the `ssh-rsa` public blob from a private/public RSA SecKey.
    static func rsaPublicBlob(fromPrivate priv: SecKey) throws -> Data {
        guard let pub = SecKeyCopyPublicKey(priv) else { throw KeygateError.invalidPrivateKey }
        let (n, e) = try ASN1.rsaPublicComponents(fromPKCS1: try secKeyExternalRepresentation(pub))
        return SSHPublicKeyBlob.rsa(e: e, n: n)
    }

    private static func cfErrorMessage(_ error: Unmanaged<CFError>?) -> String? {
        guard let error else { return nil }
        return (error.takeRetainedValue() as Error).localizedDescription
    }
}
