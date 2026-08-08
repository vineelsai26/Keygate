import Foundation

public final class PolicyStore {
    private let url: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(url: URL = KeygatePaths.policyURL) {
        self.url = url
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func load() throws -> [PolicyRule] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try Data(contentsOf: url)
        return try decoder.decode([PolicyRule].self, from: data)
    }

    public func save(_ rules: [PolicyRule]) throws {
        // Create the Keygate directory owner-only when this store is the first to
        // make it, mirroring AuditLog / FileVault. Callers may inject a shared
        // parent (e.g. NSTemporaryDirectory in self-tests), so an already-existing
        // directory outside this store's ownership is left untouched.
        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
        let data = try encoder.encode(rules)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
