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
        // Callers may inject a shared directory (e.g. NSTemporaryDirectory in
        // self-tests), so constrain the policy file itself rather than chmod an
        // existing parent outside this store's ownership.
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try encoder.encode(rules)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
