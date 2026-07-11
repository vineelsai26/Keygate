import AppKit
import Foundation
import KeygateCore
import SwiftUI

@MainActor
final class KeygateController: ObservableObject {
    @Published var keys: [StoredKeyRecord] = []
    @Published var rules: [PolicyRule] = []
    @Published var auditEvents: [AuditEvent] = []
    @Published var diagnostics: [DiagnosticItem] = []
    @Published var syncStatus = CloudSyncStatus(state: .localOnly, message: "Not checked yet")
    @Published var errorMessage: String?
    /// Non-error feedback (e.g. successful automatic setup installs).
    @Published var noticeMessage: String?
    @Published var agentRunning = false
    @Published var encryptionEnabled = false
    @Published var vaultLocked = false
    @Published var shellProfileConfigured = false
    @Published var sshConfigConfigured = false
    @Published var gitSigningConfigured = false
    @Published var gitSigningStatusMessage = "Not checked yet"
    /// Vault passphrase is present in the login Keychain (for Touch ID unlock).
    @Published var passphraseStoredInKeychain = false

    private let vault = FileVault()
    private let policyStore = PolicyStore()
    private let auditLog = AuditLog()
    private let cloudSync = CloudSyncService()
    private var server: AgentSocketServer?

    init() {
        refresh()
        if AppSettings.shared.autostartAgent, !agentRunning {
            toggleAgent()
        }
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, AppSettings.shared.lockOnSleep, self.encryptionEnabled else { return }
                self.lockVault()
            }
        }
    }

    func refresh() {
        do {
            keys = try vault.listKeys()
            rules = try policyStore.load()
            auditEvents = try auditLog.recent(limit: 50).reversed()
            diagnostics = Diagnostics.run()
            encryptionEnabled = vault.encryptionEnabled()
            vaultLocked = vault.isLocked()
            shellProfileConfigured = SetupInstaller.isShellProfileConfigured()
            sshConfigConfigured = SetupInstaller.isSSHConfigConfigured()
            let gitStatus = GitSigningInstaller.status()
            gitSigningConfigured = gitStatus.isConfigured
            gitSigningStatusMessage = gitStatus.message
            passphraseStoredInKeychain = VaultPassphraseStore.isStored()
            errorMessage = nil
        } catch {
            errorMessage = "\(error)"
        }
    }

    /// Preferred key for git signing UI: comment contains "sign", else first key.
    func preferredSigningKey() -> StoredKeyRecord? {
        if let sign = keys.first(where: { $0.comment.localizedCaseInsensitiveContains("sign") }) {
            return sign
        }
        return keys.first
    }

    /// Turns on passphrase encryption and re-encrypts existing keys. Runs off the
    /// main thread since re-encryption reads/writes every key.
    func enableEncryption(passphrase: String, saveToKeychain: Bool = true) {
        let vault = self.vault
        let persistPassphrase = saveToKeychain && AppSettings.shared.unlockWithTouchID
        DispatchQueue.global(qos: .userInitiated).async {
            var failure: Error?
            do {
                try vault.enableEncryption(passphrase: passphrase)
                if persistPassphrase {
                    try VaultPassphraseStore.save(passphrase)
                }
            } catch { failure = error }
            DispatchQueue.main.async {
                if let failure { self.errorMessage = "\(failure)" }
                else if persistPassphrase {
                    self.noticeMessage = "Vault encrypted. Passphrase saved for Touch ID unlock."
                }
                self.refresh()
            }
        }
    }

    /// Unlocks with a typed passphrase. Optionally stores it for future Touch ID unlocks.
    func unlockVault(passphrase: String, saveToKeychain: Bool? = nil) {
        do {
            try vault.unlock(passphrase: passphrase)
            let shouldSave = saveToKeychain ?? AppSettings.shared.unlockWithTouchID
            if shouldSave {
                try VaultPassphraseStore.save(passphrase)
                AppSettings.shared.unlockWithTouchID = true
                noticeMessage = "Vault unlocked. Passphrase saved for Touch ID."
            } else if saveToKeychain == false {
                _ = VaultPassphraseStore.delete()
            }
            errorMessage = nil
        } catch {
            errorMessage = "\(error)"
        }
        refresh()
    }

    /// Touch ID (or Mac password) → load passphrase from Keychain → unlock vault.
    ///
    /// LocalAuthentication must not block the main thread (its callback needs the
    /// run loop), so work runs on a background queue and results hop back to MainActor.
    func tryBiometricUnlockIfAvailable(completion: ((Bool) -> Void)? = nil) {
        guard vault.encryptionEnabled(), vault.isLocked() else {
            completion?(!vault.isLocked() || !vault.encryptionEnabled())
            return
        }
        guard VaultPassphraseStore.isStored() else {
            completion?(false)
            return
        }

        let vault = self.vault
        DispatchQueue.global(qos: .userInitiated).async {
            let authorized = LocalAuthorizer().authorize(reason: "Unlock Keygate vault")
            guard authorized else {
                DispatchQueue.main.async {
                    self.errorMessage = "Touch ID was cancelled or failed"
                    completion?(false)
                }
                return
            }
            do {
                guard let passphrase = try VaultPassphraseStore.load() else {
                    DispatchQueue.main.async {
                        self.errorMessage = "No passphrase found in Keychain"
                        self.refresh()
                        completion?(false)
                    }
                    return
                }
                try vault.unlock(passphrase: passphrase)
                DispatchQueue.main.async {
                    self.errorMessage = nil
                    self.noticeMessage = "Vault unlocked with Touch ID"
                    self.refresh()
                    completion?(true)
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = "\(error)"
                    self.refresh()
                    completion?(false)
                }
            }
        }
    }

    func lockVault() {
        vault.lock()
        refresh()
    }

    func clearStoredPassphrase() {
        _ = VaultPassphraseStore.delete()
        AppSettings.shared.unlockWithTouchID = false
        noticeMessage = "Saved vault passphrase removed from Keychain"
        refresh()
    }

    func checkCloudStatus() {
        Task {
            let status = await cloudSync.status()
            await MainActor.run {
                syncStatus = status
            }
        }
    }

    private func uploadCloudMetadataIfAvailable() {
        guard syncStatus.state == .ready, CloudSyncService.canUseCloudKit else { return }
        let keys = self.keys
        Task {
            syncStatus = CloudSyncStatus(state: .syncing, message: "Uploading metadata to iCloud")
            let status = await cloudSync.uploadMetadata(keys: keys)
            await MainActor.run { self.syncStatus = status }
        }
    }

    func generateKey(type: SSHKeyType, rsaBits: Int = SSHSigner.defaultRSABits) {
        do {
            let shouldSync = syncStatus.state == .ready && CloudSyncService.canUseCloudKit
            _ = try vault.generate(type, comment: "Keygate \(type.rawValue) \(Date().formatted(date: .numeric, time: .shortened))", syncToCloud: shouldSync, rsaBits: rsaBits)
            refresh()
            uploadCloudMetadataIfAvailable()
        } catch {
            errorMessage = "\(error)"
        }
    }

    func importKey(text: String, passphrase: String?) {
        do {
            let shouldSync = syncStatus.state == .ready && CloudSyncService.canUseCloudKit
            let trimmedPassphrase = (passphrase?.isEmpty == false) ? passphrase : nil
            _ = try vault.importPrivateKey(text: text, passphrase: trimmedPassphrase, comment: nil, syncToCloud: shouldSync)
            refresh()
            uploadCloudMetadataIfAvailable()
        } catch {
            errorMessage = "\(error)"
        }
    }

    func rename(_ key: StoredKeyRecord, to comment: String) {
        do {
            _ = try vault.rename(fingerprint: key.fingerprint, comment: comment)
            refresh()
            uploadCloudMetadataIfAvailable()
        } catch {
            errorMessage = "\(error)"
        }
    }

    func delete(_ key: StoredKeyRecord) {
        do {
            try vault.delete(fingerprint: key.fingerprint)
            refresh()
            uploadCloudMetadataIfAvailable()
        } catch {
            errorMessage = "\(error)"
        }
    }

    func toggleSync(_ key: StoredKeyRecord) {
        do {
            _ = try vault.setSync(fingerprint: key.fingerprint, syncToCloud: !key.isSynced)
            refresh()
            uploadCloudMetadataIfAvailable()
        } catch {
            errorMessage = "\(error)"
        }
    }

    /// Reads the private key out of the Keychain (Touch ID gated) and serializes
    /// it in the requested format. Runs off the main thread so the Touch ID sheet
    /// can present while the UI stays responsive; the completion returns on main
    /// with the exported text, or nil (with an error surfaced) on failure.
    func exportPrivateKey(_ key: StoredKeyRecord, format: KeyExportFormat, passphrase: String?, completion: @escaping (String?) -> Void) {
        let vault = self.vault
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<String, Error>
            do {
                result = .success(try vault.exportPrivateKey(fingerprint: key.fingerprint, format: format, passphrase: passphrase))
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                switch result {
                case .success(let text):
                    completion(text)
                case .failure(let error):
                    self.errorMessage = "\(error)"
                    completion(nil)
                }
            }
        }
    }

    func copyPublicKey(_ key: StoredKeyRecord) {
        do {
            let line = try vault.authorizedKeysLine(fingerprint: key.fingerprint)
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(line, forType: .string)
        } catch {
            errorMessage = "\(error)"
        }
    }

    /// Adds a new rule, or replaces the stored rule with the same id when editing.
    func upsertRule(_ rule: PolicyRule) {
        var next = rules
        if let index = next.firstIndex(where: { $0.id == rule.id }) {
            var updated = rule
            updated.updatedAt = Date()
            next[index] = updated
        } else {
            next.append(rule)
        }
        saveRules(next)
    }

    func deleteRule(_ rule: PolicyRule) {
        saveRules(rules.filter { $0.id != rule.id })
    }

    func addAlwaysAllowRule(for key: StoredKeyRecord) {
        let bundleID = Bundle.main.bundleIdentifier
        guard !rules.contains(where: {
            $0.action == .alwaysAllow && $0.keyFingerprint == key.fingerprint && $0.appBundleIdentifier == bundleID
        }) else { return }
        var next = rules
        next.append(PolicyRule(
            name: "Always allow current app for \(key.comment)",
            keyFingerprint: key.fingerprint,
            appBundleIdentifier: bundleID,
            action: .alwaysAllow
        ))
        saveRules(next)
    }

    func saveRules(_ next: [PolicyRule]) {
        do {
            try policyStore.save(next)
            refresh()
            uploadCloudMetadataIfAvailable()
        } catch {
            errorMessage = "\(error)"
        }
    }

    func toggleAgent() {
        if agentRunning {
            server?.stop()
            server = nil
            agentRunning = false
            refresh()
            return
        }
        do {
            let service = AgentService(vault: vault, policyStore: policyStore, auditLog: auditLog)
            let server = AgentSocketServer(service: service)
            try server.start()
            self.server = server
            agentRunning = true
            refresh()
        } catch {
            errorMessage = "\(error)"
        }
    }

    func copySocketPath() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(Diagnostics.shellSnippet, forType: .string)
        noticeMessage = "Shell snippet copied"
    }

    /// Writes/updates the Keygate export in the preferred shell profile (`~/.zshrc`, etc.).
    func installShellProfile() {
        do {
            let result = try SetupInstaller.applyShellProfile()
            noticeMessage = result.message
            errorMessage = nil
            refresh()
        } catch {
            noticeMessage = nil
            errorMessage = "\(error)"
        }
    }

    /// Writes/updates the Keygate `IdentityAgent` block in `~/.ssh/config`.
    func installSSHConfig() {
        do {
            let result = try SetupInstaller.applySSHConfig()
            noticeMessage = result.message
            errorMessage = nil
            refresh()
        } catch {
            noticeMessage = nil
            errorMessage = "\(error)"
        }
    }

    /// Applies both shell profile and SSH config installs.
    func installAutomatically() {
        do {
            let shell = try SetupInstaller.applyShellProfile()
            let ssh = try SetupInstaller.applySSHConfig()
            noticeMessage = "\(shell.message)\n\(ssh.message)"
            errorMessage = nil
            refresh()
        } catch {
            noticeMessage = nil
            errorMessage = "\(error)"
        }
    }

    /// Configures global git to sign commits/tags with a Keygate SSH public key (agent-backed).
    func installGitSigning(
        key: StoredKeyRecord,
        enableCommitSigning: Bool = true,
        enableTagSigning: Bool = true
    ) {
        do {
            let line = try vault.authorizedKeysLine(fingerprint: key.fingerprint)
            let result = try GitSigningInstaller.apply(
                publicKeyLine: line,
                enableCommitSigning: enableCommitSigning,
                enableTagSigning: enableTagSigning
            )
            noticeMessage = result.message
                + "\nAdd this public key on GitHub as a Signing key if you have not already."
            errorMessage = nil
            refresh()
        } catch {
            noticeMessage = nil
            errorMessage = "\(error)"
        }
    }
}
