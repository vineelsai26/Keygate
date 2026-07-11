import Foundation
import KeygateCore

enum KeygateCLI {
    static func main() {
        var args = Array(CommandLine.arguments.dropFirst())
        let command = args.first ?? "help"
        if !args.isEmpty {
            args.removeFirst()
        }

        do {
            switch command {
            case "socket":
                print(KeygatePaths.socketURL.path)
            case "env":
                print(Diagnostics.shellSnippet)
            case "ssh-config":
                print(Diagnostics.sshConfigSnippet)
            case "list":
                try listKeys()
            case "generate":
                try generate(args)
            case "import":
                try importKey(args)
            case "rename":
                try rename(args)
            case "delete":
                try delete(args)
            case "pub":
                try printPublicKey(args)
            case "export":
                try export(args)
            case "encrypt":
                try enableEncryption(args)
            case "diagnose":
                for item in Diagnostics.run() {
                    print("[\(item.severity.rawValue)] \(item.name): \(item.message)")
                }
            case "install-snippet":
                print("Add this to your shell profile for opt-in mode:")
                print(Diagnostics.shellSnippet)
                print("")
                print("Or add this to ~/.ssh/config:")
                print(Diagnostics.sshConfigSnippet)
            case "install":
                try install(args)
            case "help", "--help", "-h":
                help()
            default:
                fputs("Unknown command: \(command)\n\n", stderr)
                help()
                Foundation.exit(2)
            }
        } catch {
            fputs("keygate: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    // MARK: Commands

    /// Writes Keygate into the shell profile and/or `~/.ssh/config`.
    /// Usage: `keygate install [--shell] [--ssh] [--all]` (default: both).
    static func install(_ args: [String]) throws {
        var shell = false
        var ssh = false
        for arg in args {
            switch arg {
            case "--shell": shell = true
            case "--ssh": ssh = true
            case "--all":
                shell = true
                ssh = true
            case "-h", "--help":
                print("Usage: keygate install [--shell] [--ssh] [--all]")
                print("  Default (no flags): configure both shell profile and SSH config.")
                return
            default:
                throw CLIError("unknown install option: \(arg)")
            }
        }
        if !shell && !ssh {
            shell = true
            ssh = true
        }
        if shell {
            let result = try SetupInstaller.applyShellProfile()
            print("[\(result.outcome.rawValue)] \(result.message)")
        }
        if ssh {
            let result = try SetupInstaller.applySSHConfig()
            print("[\(result.outcome.rawValue)] \(result.message)")
        }
    }

    static func generate(_ args: [String]) throws {
        var syncToCloud = false
        var type: SSHKeyType = .ed25519
        var rsaBits = SSHSigner.defaultRSABits
        var comments: [String] = []
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--sync":
                syncToCloud = true
            case "--type":
                index += 1
                guard index < args.count, let parsed = parseType(args[index]) else {
                    throw CLIError("--type expects one of: ed25519, rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521")
                }
                type = parsed
            case "--bits":
                index += 1
                guard index < args.count, let parsed = Int(args[index]), SSHSigner.supportedRSABits.contains(parsed) else {
                    throw CLIError("--bits expects one of: \(SSHSigner.supportedRSABits.map(String.init).joined(separator: ", ")) (RSA only)")
                }
                rsaBits = parsed
            default:
                comments.append(arg)
            }
            index += 1
        }
        let comment = comments.isEmpty ? "Keygate \(type.rawValue)" : comments.joined(separator: " ")
        let key = try FileVault().generate(type, comment: comment, syncToCloud: syncToCloud && CloudSyncService.canUseCloudKit, rsaBits: rsaBits)
        print("Generated \(key.keyType.rawValue) \(key.fingerprint) (\(key.isSynced ? "synced" : "local-only"))")
    }

    static func importKey(_ args: [String]) throws {
        var path: String?
        var passphrase: String?
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--passphrase-env":
                index += 1
                guard index < args.count else { throw CLIError("--passphrase-env expects an environment variable name") }
                passphrase = ProcessInfo.processInfo.environment[args[index]]
            case "--passphrase":
                index += 1
                guard index < args.count else { throw CLIError("--passphrase expects a value") }
                passphrase = args[index]
            default:
                path = arg
            }
            index += 1
        }
        guard let path else { throw CLIError("usage: keygate import <file> [--passphrase-env VAR]") }
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let key = try FileVault().importPrivateKey(text: text, passphrase: passphrase, comment: nil, syncToCloud: false)
        print("Imported \(key.keyType.rawValue) \(key.fingerprint)")
    }

    static func rename(_ args: [String]) throws {
        guard args.count >= 2 else { throw CLIError("usage: keygate rename <fingerprint> <comment>") }
        let vault = FileVault()
        let fingerprint = try resolve(args[0], in: vault)
        let key = try vault.rename(fingerprint: fingerprint, comment: args.dropFirst().joined(separator: " "))
        print("Renamed \(key.fingerprint) -> \(key.comment)")
    }

    static func delete(_ args: [String]) throws {
        guard let reference = args.first else { throw CLIError("usage: keygate delete <fingerprint>") }
        let vault = FileVault()
        let fingerprint = try resolve(reference, in: vault)
        try vault.delete(fingerprint: fingerprint)
        print("Deleted \(fingerprint)")
    }

    static func printPublicKey(_ args: [String]) throws {
        guard let reference = args.first else { throw CLIError("usage: keygate pub <fingerprint>") }
        let vault = FileVault()
        let fingerprint = try resolve(reference, in: vault)
        print(try vault.authorizedKeysLine(fingerprint: fingerprint))
    }

    static func export(_ args: [String]) throws {
        var reference: String?
        var format: KeyExportFormat = .openssh
        var passphrase: String?
        var outputPath: String?
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--format":
                index += 1
                guard index < args.count, let parsed = KeyExportFormat(rawValue: args[index].lowercased()) else {
                    throw CLIError("--format expects one of: openssh, pkcs8, pkcs1")
                }
                format = parsed
            case "--passphrase":
                index += 1
                guard index < args.count else { throw CLIError("--passphrase expects a value") }
                passphrase = args[index]
            case "--passphrase-env":
                index += 1
                guard index < args.count else { throw CLIError("--passphrase-env expects an environment variable name") }
                passphrase = ProcessInfo.processInfo.environment[args[index]]
            case "--output", "-o":
                index += 1
                guard index < args.count else { throw CLIError("--output expects a file path") }
                outputPath = args[index]
            default:
                reference = arg
            }
            index += 1
        }
        guard let reference else {
            throw CLIError("usage: keygate export <fingerprint> [--format openssh|pkcs8|pkcs1] [--passphrase VALUE | --passphrase-env VAR] [--output FILE]")
        }
        let vault = FileVault()
        let fingerprint = try resolve(reference, in: vault)
        let exported = try vault.exportPrivateKey(fingerprint: fingerprint, format: format, passphrase: passphrase)
        if let outputPath {
            let url = URL(fileURLWithPath: outputPath)
            try Data(exported.utf8).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            print("Exported \(fingerprint) to \(outputPath) (\(format.displayName)\(passphrase != nil ? ", encrypted" : ""))")
        } else {
            print(exported, terminator: "")
        }
    }

    static func enableEncryption(_ args: [String]) throws {
        var passphrase: String?
        var index = 0
        while index < args.count {
            switch args[index] {
            case "--passphrase":
                index += 1
                guard index < args.count else { throw CLIError("--passphrase expects a value") }
                passphrase = args[index]
            case "--passphrase-env":
                index += 1
                guard index < args.count else { throw CLIError("--passphrase-env expects an environment variable name") }
                passphrase = ProcessInfo.processInfo.environment[args[index]]
            default:
                break
            }
            index += 1
        }
        guard let passphrase, !passphrase.isEmpty else {
            throw CLIError("usage: keygate encrypt --passphrase VALUE | --passphrase-env VAR")
        }
        try FileVault().enableEncryption(passphrase: passphrase)
        print("Encryption enabled. Set KEYGATE_PASSPHRASE to unlock keys in non-interactive use.")
    }

    static func listKeys() throws {
        let keys = try FileVault().listKeys()
        if keys.isEmpty {
            print("No keys")
            return
        }
        for key in keys {
            print("\(key.keyType.rawValue) \(key.fingerprint) \(key.comment)")
        }
    }

    // MARK: Helpers

    /// Resolves a user-supplied key reference (full fingerprint, fingerprint
    /// substring, or exact comment) to a unique stored fingerprint.
    static func resolve(_ reference: String, in vault: FileVault) throws -> String {
        let keys = try vault.listKeys()
        if let exact = keys.first(where: { $0.fingerprint == reference }) {
            return exact.fingerprint
        }
        let matches = keys.filter { $0.fingerprint.contains(reference) || $0.comment == reference }
        switch matches.count {
        case 1: return matches[0].fingerprint
        case 0: throw CLIError("no key matches '\(reference)'")
        default: throw CLIError("'\(reference)' is ambiguous; use the full fingerprint")
        }
    }

    static func parseType(_ value: String) -> SSHKeyType? {
        switch value.lowercased() {
        case "ed25519": return .ed25519
        case "rsa": return .rsa
        case "ecdsa", "ecdsa-p256", "ecdsa-nistp256", "p256": return .ecdsaP256
        case "ecdsa-p384", "ecdsa-nistp384", "p384": return .ecdsaP384
        case "ecdsa-p521", "ecdsa-nistp521", "p521": return .ecdsaP521
        default: return nil
        }
    }

    static func help() {
        print("""
        Keygate SSH key manager

        Usage:
          keygate socket             Print the Keygate SSH_AUTH_SOCK path
          keygate env                Print shell export snippet
          keygate ssh-config         Print OpenSSH IdentityAgent snippet
          keygate list               List app-owned SSH public keys
          keygate generate [--type TYPE] [--bits N] [--sync] [comment]
                                     Generate a key (TYPE: ed25519 (default),
                                     rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521;
                                     N: RSA size 2048, 3072 (default), or 4096)
          keygate import <file> [--passphrase-env VAR] [--passphrase VALUE]
                                     Import an existing OpenSSH or PEM private key
          keygate rename <fp> <comment>
                                     Rename a stored key
          keygate delete <fp>        Delete a stored key
          keygate pub <fp>           Print the authorized_keys line for a key
          keygate export <fp> [--format openssh|pkcs8|pkcs1] [--passphrase VALUE |
                              --passphrase-env VAR] [--output FILE]
                                     Export the private key (Touch ID gated;
                                     passphrase encrypts OpenSSH format only)
          keygate encrypt --passphrase VALUE | --passphrase-env VAR
                                     Encrypt keys at rest with a passphrase.
                                     Set KEYGATE_PASSPHRASE to unlock in scripts.
          keygate diagnose           Check local setup
          keygate install-snippet    Print opt-in setup instructions
          keygate install [--shell] [--ssh] [--all]
                                     Write snippets into shell profile and/or
                                     ~/.ssh/config (default: both)
        """)
    }
}

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

KeygateCLI.main()
