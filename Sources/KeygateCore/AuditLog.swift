import Foundation

public struct AuditEvent: Codable, Equatable, Identifiable {
    public var id: UUID
    public var timestamp: Date
    public var keyFingerprint: String
    public var process: ProcessIdentity
    public var destination: DestinationIdentity
    public var decision: PolicyAction
    public var reason: String

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        keyFingerprint: String,
        process: ProcessIdentity,
        destination: DestinationIdentity,
        decision: PolicyAction,
        reason: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.keyFingerprint = keyFingerprint
        self.process = process
        self.destination = destination
        self.decision = decision
        self.reason = reason
    }
}

public final class AuditLog {
    private let url: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let lock = NSLock()

    public init(url: URL = KeygatePaths.auditLogURL) {
        self.url = url
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func append(_ event: AuditEvent) throws {
        lock.lock(); defer { lock.unlock() }
        // Keep the log private without modifying an injected/shared parent
        // directory such as NSTemporaryDirectory. A directory this store creates
        // itself is safe to make owner-only.
        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
        let data = try encoder.encode(event)
        var line = data
        line.append(UInt8(ascii: "\n"))
        if FileManager.default.fileExists(atPath: url.path) {
            let handle = try FileHandle(forWritingTo: url)
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
            try handle.close()
        } else {
            try line.write(to: url, options: .atomic)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public func recent(limit: Int = 100) throws -> [AuditEvent] {
        lock.lock(); defer { lock.unlock() }
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let contents = try String(contentsOf: url, encoding: .utf8)
        let lines = contents.split(separator: "\n").suffix(limit)
        return lines.compactMap { line in
            try? decoder.decode(AuditEvent.self, from: Data(line.utf8))
        }
    }
}
