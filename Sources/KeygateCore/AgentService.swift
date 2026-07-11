import Foundation

public final class AgentService {
    private let vault: KeyVault
    private let policyStore: PolicyStore
    private let auditLog: AuditLog
    private let authorizer: SigningAuthorizer

    // Cache of active "allow for duration" grants, keyed by rule + key fingerprint.
    private var grantExpiry: [String: Date] = [:]
    private let grantLock = NSLock()

    public init(
        vault: KeyVault = FileVault(),
        policyStore: PolicyStore = PolicyStore(),
        auditLog: AuditLog = AuditLog(),
        authorizer: SigningAuthorizer = LocalAuthorizer()
    ) {
        self.vault = vault
        self.policyStore = policyStore
        self.auditLog = auditLog
        self.authorizer = authorizer
    }

    public func handle(_ request: AgentRequest, process: ProcessIdentity, destination: DestinationIdentity = DestinationIdentity()) -> AgentResponse {
        do {
            switch request {
            case .requestIdentities:
                return .identities(try vault.listKeys().map(\.agentIdentity))
            case .sign(let signRequest):
                return try handleSign(signRequest, process: process, destination: destination)
            case .extensionRequest(let name, _):
                // OpenSSH's session-bind extension must verify the server's
                // KEX signature and retain the binding for this connection
                // before it can safely distinguish forwarding from direct use.
                // Do not acknowledge a binding that this agent cannot enforce.
                if name == "session-bind@openssh.com" {
                    return .extensionFailure
                }
                return .extensionFailure
            case .unsupported:
                return .failure
            }
        } catch {
            return .failure
        }
    }

    private func handleSign(_ request: AgentSignRequest, process: ProcessIdentity, destination: DestinationIdentity) throws -> AgentResponse {
        guard let key = try vault.listKeys().first(where: { $0.agentIdentity.keyBlob == request.keyBlob }) else {
            return .failure
        }

        // Refuse before Touch ID / policy prompts. A locked vault cannot decrypt
        // private material, so asking for fingerprint first only confuses the user
        // (approve biometrics, then still get "agent refused operation").
        if vault.isLocked() {
            try auditLog.append(AuditEvent(
                keyFingerprint: key.fingerprint,
                process: process,
                destination: destination,
                decision: .deny,
                reason: KeygateError.vaultLocked.description
            ))
            NotificationCenter.default.post(name: .keygateVaultNeedsUnlock, object: nil)
            return .failure
        }

        let context = PolicyContext(
            process: process,
            destination: destination,
            keyFingerprint: key.fingerprint,
            requestFlags: request.flags
        )
        let decision = PolicyEngine(rules: try policyStore.load()).decide(context)
        try auditLog.append(AuditEvent(
            keyFingerprint: key.fingerprint,
            process: process,
            destination: destination,
            decision: decision.action,
            reason: decision.reason
        ))

        switch decision.action {
        case .deny:
            return .failure

        case .alwaysAllow:
            break // no prompt

        case .askEveryTime, .requireUserPresence:
            guard authorizer.authorize(reason: authorizationReason(for: key, process: process, destination: destination)) else {
                try? auditLog.append(AuditEvent(
                    keyFingerprint: key.fingerprint,
                    process: process,
                    destination: destination,
                    decision: .deny,
                    reason: "Authorization was cancelled or failed for \(ProcessResolver.displayName(process))"
                ))
                return .failure
            }

        case .allowForDuration:
            if !hasActiveGrant(decision: decision, fingerprint: key.fingerprint) {
                guard authorizer.authorize(reason: authorizationReason(for: key, process: process, destination: destination)) else {
                    try? auditLog.append(AuditEvent(
                        keyFingerprint: key.fingerprint,
                        process: process,
                        destination: destination,
                        decision: .deny,
                        reason: "Authorization was cancelled or failed for \(ProcessResolver.displayName(process))"
                    ))
                    return .failure
                }
                recordGrant(decision: decision, fingerprint: key.fingerprint)
            }
        }

        do {
            let signature = try vault.sign(keyBlob: request.keyBlob, payload: request.payload, flags: request.flags)
            return .signature(algorithm: signature.algorithm, signature: signature.signature)
        } catch KeygateError.vaultLocked {
            // Race: vault locked between the pre-check and sign (e.g. lock-on-sleep).
            try? auditLog.append(AuditEvent(
                keyFingerprint: key.fingerprint,
                process: process,
                destination: destination,
                decision: .deny,
                reason: KeygateError.vaultLocked.description
            ))
            NotificationCenter.default.post(name: .keygateVaultNeedsUnlock, object: nil)
            return .failure
        }
    }

    /// Text shown in the system Touch ID / password sheet.
    /// Always names the requesting app so the user can see who is asking for the key.
    private func authorizationReason(
        for key: StoredKeyRecord,
        process: ProcessIdentity,
        destination: DestinationIdentity
    ) -> String {
        let label = key.comment.isEmpty ? key.fingerprint : key.comment
        let app = ProcessResolver.displayName(process)
        if let host = destination.host {
            let target = destination.user.map { "\($0)@\(host)" } ?? host
            return "“\(app)” wants to use the key “\(label)” to connect to \(target)"
        }
        return "“\(app)” wants to use the key “\(label)”"
    }

    // MARK: allow-for-duration grant cache

    private func grantKey(decision: PolicyDecision, fingerprint: String) -> String {
        let ruleID = decision.rule?.id.uuidString ?? "no-rule"
        return "\(ruleID):\(fingerprint)"
    }

    private func hasActiveGrant(decision: PolicyDecision, fingerprint: String) -> Bool {
        let key = grantKey(decision: decision, fingerprint: fingerprint)
        grantLock.lock()
        defer { grantLock.unlock() }
        guard let expiry = grantExpiry[key] else { return false }
        if expiry > Date() { return true }
        grantExpiry[key] = nil
        return false
    }

    private func recordGrant(decision: PolicyDecision, fingerprint: String) {
        let seconds = decision.rule?.durationSeconds ?? 0
        guard seconds > 0 else { return }
        let key = grantKey(decision: decision, fingerprint: fingerprint)
        grantLock.lock()
        grantExpiry[key] = Date().addingTimeInterval(seconds)
        grantLock.unlock()
    }
}
