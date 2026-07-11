import CryptoKit
import Foundation

public enum Fingerprint {
    public static func sha256(_ keyBlob: Data) -> String {
        let digest = SHA256.hash(data: keyBlob)
        let base64 = Data(digest).base64EncodedString()
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return "SHA256:\(base64)"
    }
}
