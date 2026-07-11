import Foundation

public struct DiagnosticItem: Identifiable, Equatable {
    public enum Severity: String {
        case ok
        case warning
        case error
    }

    public var id: String { name }
    public let name: String
    public let severity: Severity
    public let message: String

    public init(name: String, severity: Severity, message: String) {
        self.name = name
        self.severity = severity
        self.message = message
    }
}

public enum Diagnostics {
    public static func run() -> [DiagnosticItem] {
        var items: [DiagnosticItem] = []
        let socket = KeygatePaths.socketURL.path
        items.append(DiagnosticItem(
            name: "Keygate socket",
            severity: FileManager.default.fileExists(atPath: socket) ? .ok : .warning,
            message: socket
        ))

        if let existing = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], !existing.isEmpty {
            items.append(DiagnosticItem(
                name: "Current SSH_AUTH_SOCK",
                severity: existing == socket ? .ok : .warning,
                message: existing
            ))
        } else {
            items.append(DiagnosticItem(
                name: "Current SSH_AUTH_SOCK",
                severity: .warning,
                message: "SSH_AUTH_SOCK is not set in this process"
            ))
        }

        let appSupport = KeygatePaths.appSupportDirectory.path
        items.append(DiagnosticItem(
            name: "Application Support",
            severity: FileManager.default.isWritableFile(atPath: appSupport) || !FileManager.default.fileExists(atPath: appSupport) ? .ok : .error,
            message: appSupport
        ))

        let shellProfile = SetupInstaller.preferredShellProfileURL()
        items.append(DiagnosticItem(
            name: "Shell profile",
            severity: SetupInstaller.isShellProfileConfigured(at: shellProfile) ? .ok : .warning,
            message: SetupInstaller.isShellProfileConfigured(at: shellProfile)
                ? "Keygate configured in \(shellProfile.path)"
                : "Not configured — add the shell snippet to \(shellProfile.path)"
        ))

        let sshConfig = SetupInstaller.sshConfigURL()
        items.append(DiagnosticItem(
            name: "SSH config",
            severity: SetupInstaller.isSSHConfigConfigured(at: sshConfig) ? .ok : .warning,
            message: SetupInstaller.isSSHConfigConfigured(at: sshConfig)
                ? "Keygate configured in \(sshConfig.path)"
                : "Not configured — add IdentityAgent to \(sshConfig.path)"
        ))

        let git = GitSigningInstaller.status()
        items.append(DiagnosticItem(
            name: "Git SSH signing",
            severity: git.isConfigured ? .ok : .warning,
            message: git.message
        ))
        return items
    }

    public static var shellSnippet: String {
        "export SSH_AUTH_SOCK=\"\(KeygatePaths.socketURL.path)\""
    }

    public static var sshConfigSnippet: String {
        """
        Host *
          IdentityAgent \(KeygatePaths.socketURL.path)
        """
    }
}
