import Foundation

/// Idempotent installer for Keygate shell and OpenSSH config snippets.
///
/// Writes (or updates) a marked block so re-running is safe and socket path
/// changes replace the previous Keygate entry instead of stacking duplicates.
public enum SetupInstaller {
    public static let beginMarker = "# >>> keygate >>>"
    public static let endMarker = "# <<< keygate <<<"

    public enum Outcome: String, Equatable, Sendable {
        case installed
        case updated
        case alreadyConfigured
    }

    public struct ApplyResult: Equatable, Sendable {
        public let path: URL
        public let outcome: Outcome
        public let message: String

        public init(path: URL, outcome: Outcome, message: String) {
            self.path = path
            self.outcome = outcome
            self.message = message
        }
    }

    public enum InstallError: Error, CustomStringConvertible {
        case unreadable(URL)
        case unwritable(URL, String)

        public var description: String {
            switch self {
            case .unreadable(let url):
                return "Could not read \(url.path)"
            case .unwritable(let url, let detail):
                return "Could not write \(url.path): \(detail)"
            }
        }
    }

    // MARK: Paths

    /// Preferred shell profile for the current login shell.
    public static func preferredShellProfileURL(
        shell: String = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh",
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        let name = (shell as NSString).lastPathComponent.lowercased()
        switch name {
        case "fish":
            return home
                .appendingPathComponent(".config", isDirectory: true)
                .appendingPathComponent("fish", isDirectory: true)
                .appendingPathComponent("config.fish")
        case "bash":
            let bashProfile = home.appendingPathComponent(".bash_profile")
            if FileManager.default.fileExists(atPath: bashProfile.path) {
                return bashProfile
            }
            return home.appendingPathComponent(".bashrc")
        default:
            return home.appendingPathComponent(".zshrc")
        }
    }

    public static func sshConfigURL(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        home
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent("config")
    }

    // MARK: Status

    public static func isShellProfileConfigured(
        at url: URL? = nil,
        socketPath: String = KeygatePaths.socketURL.path
    ) -> Bool {
        let path = url ?? preferredShellProfileURL()
        guard let content = try? String(contentsOf: path, encoding: .utf8) else { return false }
        return content.contains(socketPath) || containsMarkedBlock(content)
    }

    public static func isSSHConfigConfigured(
        at url: URL? = nil,
        socketPath: String = KeygatePaths.socketURL.path
    ) -> Bool {
        let path = url ?? sshConfigURL()
        guard let content = try? String(contentsOf: path, encoding: .utf8) else { return false }
        return content.contains(socketPath) || containsMarkedBlock(content)
    }

    // MARK: Apply

    /// Appends or updates the shell export snippet in the preferred profile.
    @discardableResult
    public static func applyShellProfile(
        to url: URL? = nil,
        socketPath: String = KeygatePaths.socketURL.path
    ) throws -> ApplyResult {
        let path = url ?? preferredShellProfileURL()
        let body = shellSnippet(for: path, socketPath: socketPath)
        return try apply(body: body, to: path, label: "Shell profile")
    }

    /// Appends or updates the OpenSSH `IdentityAgent` block in `~/.ssh/config`.
    @discardableResult
    public static func applySSHConfig(
        to url: URL? = nil,
        socketPath: String = KeygatePaths.socketURL.path
    ) throws -> ApplyResult {
        let path = url ?? sshConfigURL()
        let body = """
        Host *
          IdentityAgent \(socketPath)
        """
        return try apply(body: body, to: path, label: "SSH config")
    }

    // MARK: Internals

    private static func shellSnippet(for profile: URL, socketPath: String) -> String {
        if profile.path.hasSuffix("config.fish") {
            return "set -gx SSH_AUTH_SOCK \"\(socketPath)\""
        }
        return "export SSH_AUTH_SOCK=\"\(socketPath)\""
    }

    private static func apply(body: String, to path: URL, label: String) throws -> ApplyResult {
        let fm = FileManager.default
        let parent = path.deletingLastPathComponent()
        if !fm.fileExists(atPath: parent.path) {
            try fm.createDirectory(at: parent, withIntermediateDirectories: true)
        }

        let existing: String
        if fm.fileExists(atPath: path.path) {
            guard let text = try? String(contentsOf: path, encoding: .utf8) else {
                throw InstallError.unreadable(path)
            }
            existing = text
        } else {
            existing = ""
        }

        let (next, outcome) = upsertMarkedBlock(in: existing, body: body)
        if outcome != .alreadyConfigured {
            do {
                try next.write(to: path, atomically: true, encoding: .utf8)
                // OpenSSH expects restrictive permissions on config files.
                if path.lastPathComponent == "config", path.path.contains("/.ssh/") {
                    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
                }
            } catch {
                throw InstallError.unwritable(path, "\(error)")
            }
        }

        let message: String
        switch outcome {
        case .installed:
            message = "\(label) updated: added Keygate to \(path.path)"
        case .updated:
            message = "\(label) updated: refreshed Keygate block in \(path.path)"
        case .alreadyConfigured:
            message = "\(label) already configured at \(path.path)"
        }
        return ApplyResult(path: path, outcome: outcome, message: message)
    }

    /// Inserts or replaces the marked Keygate block. Exposed for selftests.
    public static func upsertMarkedBlock(in content: String, body: String) -> (String, Outcome) {
        let trimmedBody = body.trimmingCharacters(in: .newlines)
        let block = """
        \(beginMarker)
        \(trimmedBody)
        \(endMarker)
        """

        if let range = markedRange(in: content) {
            let existing = String(content[range]).trimmingCharacters(in: .newlines)
            if existing == block {
                return (content, .alreadyConfigured)
            }
            var next = content
            next.replaceSubrange(range, with: block)
            return (ensureTrailingNewline(next), .updated)
        }

        // Manual install without markers: treat matching body as already done.
        if content.contains(trimmedBody) {
            return (content, .alreadyConfigured)
        }

        var next = content
        if !next.isEmpty && !next.hasSuffix("\n") {
            next += "\n"
        }
        if !next.isEmpty {
            next += "\n"
        }
        next += block + "\n"
        return (next, .installed)
    }

    public static func containsMarkedBlock(_ content: String) -> Bool {
        markedRange(in: content) != nil
    }

    private static func markedRange(in content: String) -> Range<String.Index>? {
        guard let begin = content.range(of: beginMarker) else { return nil }
        let afterBegin = begin.upperBound
        if let end = content.range(of: endMarker, range: afterBegin..<content.endIndex) {
            // Include a trailing newline after the end marker when present.
            var upper = end.upperBound
            if upper < content.endIndex, content[upper] == "\n" {
                upper = content.index(after: upper)
            }
            return begin.lowerBound..<upper
        }
        // Broken marker pair: replace from begin through end of file.
        return begin.lowerBound..<content.endIndex
    }

    private static func ensureTrailingNewline(_ text: String) -> String {
        if text.isEmpty || text.hasSuffix("\n") { return text }
        return text + "\n"
    }
}
