import Foundation

/// Configures global Git settings so commits/tags are signed with an SSH key
/// that lives in Keygate (agent-backed).
///
/// Git invokes `ssh-keygen -Y sign`, which only talks to `SSH_AUTH_SOCK` — not
/// OpenSSH `IdentityAgent`. On macOS, `SSH_AUTH_SOCK` is usually the empty
/// launchd agent, so signing fails with “No private key found” even when
/// Keygate is configured in `~/.ssh/config`.
///
/// This installer therefore writes a small `gpg.ssh.program` wrapper that
/// points `SSH_AUTH_SOCK` at Keygate’s socket before exec’ing `ssh-keygen`
/// (same pattern as 1Password’s `op-ssh-sign`).
///
/// Also sets:
/// - `gpg.format=ssh`
/// - `user.signingkey` → `~/.ssh/keygate_signing.pub` (public key only)
/// - optional `commit.gpgsign` / `tag.gpgSign`
public enum GitSigningInstaller {
    public static let publicKeyFileName = "keygate_signing.pub"
    public static let sshSignProgramFileName = "ssh-sign"

    public struct Status: Equatable, Sendable {
        public var formatIsSSH: Bool
        public var signingKey: String?
        public var commitGPGSign: Bool
        public var tagGPGSign: Bool
        public var sshProgram: String?
        /// True when format is ssh, signing key is set, and gpg.ssh.program is Keygate’s wrapper.
        public var isConfigured: Bool
        public var message: String

        public init(
            formatIsSSH: Bool,
            signingKey: String?,
            commitGPGSign: Bool,
            tagGPGSign: Bool,
            sshProgram: String?,
            isConfigured: Bool,
            message: String
        ) {
            self.formatIsSSH = formatIsSSH
            self.signingKey = signingKey
            self.commitGPGSign = commitGPGSign
            self.tagGPGSign = tagGPGSign
            self.sshProgram = sshProgram
            self.isConfigured = isConfigured
            self.message = message
        }
    }

    public enum InstallError: Error, CustomStringConvertible {
        case gitNotFound
        case gitFailed(String)
        case unwritable(URL, String)

        public var description: String {
            switch self {
            case .gitNotFound:
                return "git was not found on PATH"
            case .gitFailed(let detail):
                return "git config failed: \(detail)"
            case .unwritable(let url, let detail):
                return "Could not write \(url.path): \(detail)"
            }
        }
    }

    // MARK: Paths

    public static func publicKeyURL(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        home
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent(publicKeyFileName)
    }

    /// Wrapper invoked by `git` as `gpg.ssh.program`.
    public static func sshSignProgramURL(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        home
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Keygate", isDirectory: true)
            .appendingPathComponent(sshSignProgramFileName)
    }

    // MARK: Status

    /// Reads global git signing-related config. Optional `home` overrides where
    /// git looks for `~/.gitconfig` (used by tests).
    public static func status(home: URL? = nil) -> Status {
        let format = (try? gitConfigGet("gpg.format", home: home))?.trimmingCharacters(in: .whitespacesAndNewlines)
        let signingKey = try? gitConfigGet("user.signingkey", home: home)
        let commitSign = (try? gitConfigGet("commit.gpgsign", home: home))?.lowercased() == "true"
        let tagSign = (try? gitConfigGet("tag.gpgsign", home: home))?.lowercased() == "true"
            || (try? gitConfigGet("tag.gpgSign", home: home))?.lowercased() == "true"
        let sshProgram = try? gitConfigGet("gpg.ssh.program", home: home)

        let formatIsSSH = format == "ssh"
        let keySet = !(signingKey?.isEmpty ?? true)
        let usesKeygateProgram = sshProgram.map { isKeygateSSHSignProgram($0) } ?? false
        let programBlocks = sshProgram.map { isThirdPartySSHSignProgram($0) } ?? false

        let isConfigured = formatIsSSH && keySet && usesKeygateProgram
        let message: String
        if isConfigured {
            let key = signingKey ?? ""
            message = "Git SSH signing configured via Keygate (\(key))"
        } else if programBlocks, let program = sshProgram {
            message = "gpg.ssh.program is \(program) — re-run Configure Git Signing to switch to Keygate"
        } else if formatIsSSH && keySet && !usesKeygateProgram {
            message = "signing key set, but gpg.ssh.program is not Keygate’s wrapper (GUI git often cannot see IdentityAgent)"
        } else if !formatIsSSH && !keySet {
            message = "Not configured — set gpg.format=ssh, user.signingkey, and Keygate gpg.ssh.program"
        } else if !formatIsSSH {
            message = "gpg.format is \(format ?? "unset"); expected ssh"
        } else {
            message = "user.signingkey is not set"
        }

        return Status(
            formatIsSSH: formatIsSSH,
            signingKey: signingKey,
            commitGPGSign: commitSign,
            tagGPGSign: tagSign,
            sshProgram: sshProgram,
            isConfigured: isConfigured,
            message: message
        )
    }

    public static func isConfigured(home: URL? = nil) -> Bool {
        status(home: home).isConfigured
    }

    // MARK: Apply

    /// Writes the public key file + ssh-sign wrapper and configures global git signing.
    @discardableResult
    public static func apply(
        publicKeyLine: String,
        enableCommitSigning: Bool = true,
        enableTagSigning: Bool = true,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        socketPath: String = KeygatePaths.socketURL.path
    ) throws -> SetupInstaller.ApplyResult {
        let line = publicKeyLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty else {
            throw InstallError.gitFailed("public key line is empty")
        }

        let pubURL = publicKeyURL(home: home)
        let programURL = sshSignProgramURL(home: home)

        do {
            try FileManager.default.createDirectory(
                at: pubURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try (line + "\n").write(to: pubURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
        } catch {
            throw InstallError.unwritable(pubURL, "\(error)")
        }

        do {
            try FileManager.default.createDirectory(
                at: programURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try sshSignWrapperScript(socketPath: socketPath)
                .write(to: programURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: programURL.path)
        } catch {
            throw InstallError.unwritable(programURL, "\(error)")
        }

        try gitConfigSet("gpg.format", "ssh", home: home)
        try gitConfigSet("user.signingkey", pubURL.path, home: home)
        try gitConfigSet("commit.gpgsign", enableCommitSigning ? "true" : "false", home: home)
        try gitConfigSet("tag.gpgSign", enableTagSigning ? "true" : "false", home: home)
        try gitConfigSet("gpg.ssh.program", programURL.path, home: home)

        let status = status(home: home)
        let message: String
        if status.isConfigured {
            message = "Git signing configured: \(pubURL.path) via \(programURL.path)"
        } else {
            message = "Git signing wrote files but status is incomplete: \(status.message)"
        }
        return SetupInstaller.ApplyResult(path: pubURL, outcome: .installed, message: message)
    }

    // MARK: Helpers

    /// Shell wrapper git runs instead of bare `ssh-keygen`.
    public static func sshSignWrapperScript(socketPath: String) -> String {
        """
        #!/bin/sh
        # Keygate git SSH signing helper.
        # Forces SSH_AUTH_SOCK to the Keygate agent so `ssh-keygen -Y sign`
        # finds agent-backed keys (IdentityAgent alone is not enough).
        export SSH_AUTH_SOCK="\(socketPath)"
        if [ ! -S "$SSH_AUTH_SOCK" ]; then
          echo "keygate-ssh-sign: Keygate agent socket not found at $SSH_AUTH_SOCK" >&2
          echo "keygate-ssh-sign: is Keygate running with the agent started?" >&2
          exit 1
        fi
        exec /usr/bin/ssh-keygen "$@"

        """
    }

    /// True when `gpg.ssh.program` is Keygate’s installed wrapper.
    public static func isKeygateSSHSignProgram(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        return url.lastPathComponent == sshSignProgramFileName
            && url.path.contains("Keygate")
    }

    /// Programs that sign outside the Keygate agent.
    public static func isThirdPartySSHSignProgram(_ path: String) -> Bool {
        if isKeygateSSHSignProgram(path) { return false }
        let lower = path.lowercased()
        if lower.contains("op-ssh-sign") { return true }
        if lower.contains("1password") { return true }
        return false
    }

    private static func gitConfigGet(_ key: String, home: URL?) throws -> String? {
        let result = try runGit(["config", "--global", "--get", key], home: home, allowNonZeroExit: true)
        if result.exitCode == 1 { return nil } // unset
        if result.exitCode != 0 {
            throw InstallError.gitFailed(result.stderr.isEmpty ? "exit \(result.exitCode)" : result.stderr)
        }
        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private static func gitConfigSet(_ key: String, _ value: String, home: URL?) throws {
        let result = try runGit(["config", "--global", key, value], home: home)
        if result.exitCode != 0 {
            throw InstallError.gitFailed(result.stderr.isEmpty ? "failed to set \(key)" : result.stderr)
        }
    }

    private struct GitResult {
        var exitCode: Int32
        var stdout: String
        var stderr: String
    }

    private static func runGit(
        _ arguments: [String],
        home: URL?,
        allowNonZeroExit: Bool = false
    ) throws -> GitResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        if !FileManager.default.isExecutableFile(atPath: process.executableURL!.path) {
            process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/git")
            if !FileManager.default.isExecutableFile(atPath: process.executableURL!.path) {
                throw InstallError.gitNotFound
            }
        }
        process.arguments = arguments

        var env = ProcessInfo.processInfo.environment
        if let home {
            env["HOME"] = home.path
            env["GIT_CONFIG_GLOBAL"] = home.appendingPathComponent(".gitconfig").path
            env["GIT_CONFIG_NOSYSTEM"] = "1"
        }
        process.environment = env

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        process.waitUntilExit()

        let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if !allowNonZeroExit && process.terminationStatus != 0 {
            throw InstallError.gitFailed(stderr.isEmpty ? stdout : stderr)
        }
        return GitResult(exitCode: process.terminationStatus, stdout: stdout, stderr: stderr)
    }
}
