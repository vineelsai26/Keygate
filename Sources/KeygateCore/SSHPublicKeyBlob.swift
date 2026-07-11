import Foundation

/// Builders for SSH public-key wire blobs (RFC 8709 / RFC 5656 / RFC 4253).
/// The fingerprint (`Fingerprint.sha256`) and the agent identity both hash these
/// bytes, so the layout must match OpenSSH exactly.
public enum SSHPublicKeyBlob {
    /// `string "ssh-ed25519"` + `string Q` (32-byte public key).
    public static func ed25519(_ publicKey: Data) -> Data {
        var writer = SSHWriter()
        writer.writeString(SSHKeyType.ed25519.rawValue)
        writer.writeDataString(publicKey)
        return writer.finish()
    }

    /// `string "ecdsa-sha2-nistpXXX"` + `string "nistpXXX"` + `string Q` (`0x04||X||Y`).
    public static func ecdsa(_ type: SSHKeyType, point: Data) -> Data {
        var writer = SSHWriter()
        writer.writeString(type.rawValue)
        writer.writeString(type.curveName ?? "")
        writer.writeDataString(point)
        return writer.finish()
    }

    /// `string "ssh-rsa"` + `mpint e` + `mpint n` (public exponent before modulus).
    public static func rsa(e: Data, n: Data) -> Data {
        var writer = SSHWriter()
        writer.writeString(SSHKeyType.rsa.rawValue)
        writer.writeMPInt(e)
        writer.writeMPInt(n)
        return writer.finish()
    }
}
