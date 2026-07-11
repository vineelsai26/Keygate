import Foundation

public enum KeygatePaths {
    public static var appSupportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return base.appendingPathComponent("Keygate", isDirectory: true)
    }

    public static var runtimeDirectory: URL {
        URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("keygate-\(getuid())", isDirectory: true)
    }

    public static var socketURL: URL {
        runtimeDirectory.appendingPathComponent("agent.sock")
    }

    public static var metadataURL: URL {
        appSupportDirectory.appendingPathComponent("keys.json")
    }

    /// Directory holding per-key private material files (0600), one per key.
    public static var keysDirectory: URL {
        appSupportDirectory.appendingPathComponent("keys", isDirectory: true)
    }

    /// Passphrase-encryption parameters (KDF salt, iterations, verifier).
    public static var encryptionConfigURL: URL {
        appSupportDirectory.appendingPathComponent("encryption.json")
    }

    public static var policyURL: URL {
        appSupportDirectory.appendingPathComponent("policy.json")
    }

    public static var auditLogURL: URL {
        appSupportDirectory.appendingPathComponent("audit.jsonl")
    }
}
