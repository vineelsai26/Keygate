import Foundation

public enum PolicyAction: String, Codable, CaseIterable {
    case alwaysAllow
    case askEveryTime
    case allowForDuration
    case deny
    case requireUserPresence
}

public struct ProcessIdentity: Codable, Equatable {
    public var pid: Int32?
    public var uid: UInt32?
    public var executablePath: String?
    public var bundleIdentifier: String?
    public var teamIdentifier: String?
    public var signingIdentifier: String?
    public var codeHash: String?
    public var parentPID: Int32?
    public var terminalBundleIdentifier: String?
	public var terminalTeamIdentifier: String?

    public init(
        pid: Int32? = nil,
        uid: UInt32? = nil,
        executablePath: String? = nil,
        bundleIdentifier: String? = nil,
        teamIdentifier: String? = nil,
        signingIdentifier: String? = nil,
        codeHash: String? = nil,
        parentPID: Int32? = nil,
		terminalBundleIdentifier: String? = nil,
		terminalTeamIdentifier: String? = nil
    ) {
        self.pid = pid
        self.uid = uid
        self.executablePath = executablePath
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.signingIdentifier = signingIdentifier
        self.codeHash = codeHash
        self.parentPID = parentPID
        self.terminalBundleIdentifier = terminalBundleIdentifier
		self.terminalTeamIdentifier = terminalTeamIdentifier
    }
}

public struct DestinationIdentity: Codable, Equatable {
    public var host: String?
    public var user: String?
    public var port: Int?
    public var repo: String?
    public var sessionIdentifier: String?
    public var isForwarding: Bool

    public init(
        host: String? = nil,
        user: String? = nil,
        port: Int? = nil,
        repo: String? = nil,
        sessionIdentifier: String? = nil,
        isForwarding: Bool = false
    ) {
        self.host = host
        self.user = user
        self.port = port
        self.repo = repo
        self.sessionIdentifier = sessionIdentifier
        self.isForwarding = isForwarding
    }
}

public struct PolicyRule: Codable, Equatable, Identifiable {
    public var id: UUID
    public var name: String
    public var keyFingerprint: String?
    public var appBundleIdentifier: String?
    public var executablePath: String?
    public var teamIdentifier: String?
    public var destinationHost: String?
    public var destinationUser: String?
    public var forwardingOnly: Bool?
    public var action: PolicyAction
    public var durationSeconds: TimeInterval?
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        keyFingerprint: String? = nil,
        appBundleIdentifier: String? = nil,
        executablePath: String? = nil,
        teamIdentifier: String? = nil,
        destinationHost: String? = nil,
        destinationUser: String? = nil,
        forwardingOnly: Bool? = nil,
        action: PolicyAction,
        durationSeconds: TimeInterval? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.keyFingerprint = keyFingerprint
        self.appBundleIdentifier = appBundleIdentifier
        self.executablePath = executablePath
        self.teamIdentifier = teamIdentifier
        self.destinationHost = destinationHost
        self.destinationUser = destinationUser
        self.forwardingOnly = forwardingOnly
        self.action = action
        self.durationSeconds = durationSeconds
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct PolicyDecision: Equatable {
    public let action: PolicyAction
    public let rule: PolicyRule?
    public let reason: String

    public init(action: PolicyAction, rule: PolicyRule?, reason: String) {
        self.action = action
        self.rule = rule
        self.reason = reason
    }
}

public struct PolicyContext: Equatable {
    public let process: ProcessIdentity
    public let destination: DestinationIdentity
    public let keyFingerprint: String
    public let requestFlags: UInt32

    public init(process: ProcessIdentity, destination: DestinationIdentity, keyFingerprint: String, requestFlags: UInt32) {
        self.process = process
        self.destination = destination
        self.keyFingerprint = keyFingerprint
        self.requestFlags = requestFlags
    }
}

public struct PolicyEngine {
    public var rules: [PolicyRule]
    public var now: () -> Date

    public init(rules: [PolicyRule] = [], now: @escaping () -> Date = Date.init) {
        self.rules = rules
        self.now = now
    }

    public func decide(_ context: PolicyContext) -> PolicyDecision {
        for rule in rules where matches(rule, context) {
            return PolicyDecision(action: rule.action, rule: rule, reason: "Matched rule: \(rule.name)")
        }

        if context.destination.isForwarding {
            return PolicyDecision(action: .askEveryTime, rule: nil, reason: "Agent forwarding requires explicit approval")
        }

        return PolicyDecision(action: .requireUserPresence, rule: nil, reason: "No matching rule; required Touch ID/password by default")
    }

    private func matches(_ rule: PolicyRule, _ context: PolicyContext) -> Bool {
        if let key = rule.keyFingerprint, key != context.keyFingerprint { return false }
        // Socket peers are often CLI tools (`ssh`, `git`). Match the rule's app
        // against either the peer's own bundle or the parent terminal/GUI app.
        if let bundle = rule.appBundleIdentifier {
			// Bundle IDs come from Info.plist and are spoofable. Bundle-scoped
			// rules therefore require a team constraint bound to the same signed
			// process (the direct peer or its owning terminal application).
			guard let requiredTeam = rule.teamIdentifier else { return false }
			let directMatch = context.process.bundleIdentifier == bundle
				&& context.process.teamIdentifier == requiredTeam
			let terminalMatch = context.process.terminalBundleIdentifier == bundle
				&& context.process.terminalTeamIdentifier == requiredTeam
			if !directMatch && !terminalMatch { return false }
        }
        if let path = rule.executablePath, path != context.process.executablePath { return false }
		if rule.appBundleIdentifier == nil,
		   let team = rule.teamIdentifier,
		   team != context.process.teamIdentifier { return false }
        // Destination host/user are only available when the agent protocol
        // provides them; unset destination fields never match a host-restricted rule.
        if let host = rule.destinationHost, host != context.destination.host { return false }
        if let user = rule.destinationUser, user != context.destination.user { return false }
        if let forwarding = rule.forwardingOnly, forwarding != context.destination.isForwarding { return false }
        return true
    }
}
