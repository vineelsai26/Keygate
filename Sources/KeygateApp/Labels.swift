import KeygateCore

/// Display names for core enum values, shared by the sections and sheets.
enum Labels {
    static func keyType(_ type: SSHKeyType) -> String {
        switch type {
        case .ed25519: return "Ed25519"
        case .rsa: return "RSA"
        case .ecdsaP256: return "ECDSA P-256"
        case .ecdsaP384: return "ECDSA P-384"
        case .ecdsaP521: return "ECDSA P-521"
        }
    }

    static func action(_ action: PolicyAction) -> String {
        switch action {
        case .alwaysAllow: return "Always allow"
        case .askEveryTime: return "Ask every time"
        case .allowForDuration: return "Allow for duration"
        case .deny: return "Deny"
        case .requireUserPresence: return "Require Touch ID/password"
        }
    }
}
