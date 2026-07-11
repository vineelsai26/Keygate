import CloudKit
import Foundation
import Security

public enum CloudSyncState: String, Codable {
    case unavailable
    case localOnly
    case ready
    case syncing
    case failed
}

public struct CloudSyncStatus: Equatable {
    public var state: CloudSyncState
    public var message: String
    public var updatedAt: Date

    public init(state: CloudSyncState, message: String, updatedAt: Date = Date()) {
        self.state = state
        self.message = message
        self.updatedAt = updatedAt
    }
}

public final class CloudSyncService {
    private let containerIdentifier: String?

    public init(containerIdentifier: String? = nil) {
        self.containerIdentifier = containerIdentifier
    }

    public static var canUseCloudKit: Bool {
        hasCloudKitEntitlement
    }

    public func status() async -> CloudSyncStatus {
        guard Self.canUseCloudKit else {
            return CloudSyncStatus(
                state: .localOnly,
                message: "CloudKit entitlement is not available in this build"
            )
        }

        do {
            let container: CKContainer
            if let containerIdentifier {
                container = CKContainer(identifier: containerIdentifier)
            } else {
                container = CKContainer.default()
            }
            let accountStatus = try await container.accountStatus()
            switch accountStatus {
            case .available:
                return CloudSyncStatus(state: .ready, message: "iCloud account is available")
            case .noAccount:
                return CloudSyncStatus(state: .localOnly, message: "No iCloud account is signed in")
            case .restricted:
                return CloudSyncStatus(state: .unavailable, message: "iCloud access is restricted")
            case .couldNotDetermine:
                return CloudSyncStatus(state: .unavailable, message: "Could not determine iCloud account status")
            case .temporarilyUnavailable:
                return CloudSyncStatus(state: .unavailable, message: "iCloud is temporarily unavailable")
            @unknown default:
                return CloudSyncStatus(state: .unavailable, message: "Unknown iCloud account status")
            }
        } catch {
            return CloudSyncStatus(state: .failed, message: error.localizedDescription)
        }
    }

    /// Uploads only explicitly opted-in public key metadata to the user's
    /// private CloudKit database. Rules and audit history remain local.
    public func uploadMetadata(keys: [StoredKeyRecord]) async -> CloudSyncStatus {
        guard Self.canUseCloudKit else {
            return CloudSyncStatus(state: .localOnly, message: "CloudKit entitlement is not available in this build")
        }

        let container = containerIdentifier.map(CKContainer.init(identifier:)) ?? CKContainer.default()
        do {
            let records = exportRecordMetadata(keys: keys.filter(\.isSynced), rules: [], auditEvents: [])
            guard !records.isEmpty else {
                return CloudSyncStatus(state: .ready, message: "No metadata is opted into CloudKit sync")
            }
            let result = try await container.privateCloudDatabase.modifyRecords(
                saving: records,
                deleting: [],
                savePolicy: .changedKeys,
                atomically: false
            )
            let savedCount = result.saveResults.values.compactMap { try? $0.get() }.count
            guard savedCount == records.count else {
                return CloudSyncStatus(state: .failed, message: "CloudKit saved \(savedCount) of \(records.count) metadata records")
            }
            return CloudSyncStatus(state: .ready, message: "CloudKit saved \(records.count) metadata records")
        } catch {
            return CloudSyncStatus(state: .failed, message: error.localizedDescription)
        }
    }

    public func exportRecordMetadata(keys: [StoredKeyRecord], rules: [PolicyRule], auditEvents: [AuditEvent]) -> [CKRecord] {
        keys.map { key in
            let recordID = CKRecord.ID(recordName: "key-\(key.fingerprint.base64FilenameSafe)")
            let record = CKRecord(recordType: "KeygateKey", recordID: recordID)
            record["fingerprint"] = key.fingerprint
            record["keyType"] = key.keyType.rawValue
            record["comment"] = key.comment
            record["publicKey"] = key.publicKey
            record["updatedAt"] = key.updatedAt
            record["isSynced"] = key.isSynced ? 1 : 0
            return record
        } + rules.map { rule in
            let record = CKRecord(recordType: "KeygatePolicyRule", recordID: CKRecord.ID(recordName: "rule-\(rule.id.uuidString)"))
            record["name"] = rule.name
            record["action"] = rule.action.rawValue
            record["keyFingerprint"] = rule.keyFingerprint
            record["appBundleIdentifier"] = rule.appBundleIdentifier
            record["executablePath"] = rule.executablePath
            record["teamIdentifier"] = rule.teamIdentifier
            record["destinationHost"] = rule.destinationHost
            record["destinationUser"] = rule.destinationUser
            record["forwardingOnly"] = rule.forwardingOnly
            record["updatedAt"] = rule.updatedAt
            return record
        } + auditEvents.map { event in
            let record = CKRecord(recordType: "KeygateAuditSummary", recordID: CKRecord.ID(recordName: "audit-\(event.id.uuidString)"))
            record["timestamp"] = event.timestamp
            record["keyFingerprint"] = event.keyFingerprint
            record["decision"] = event.decision.rawValue
            record["reason"] = event.reason
            return record
        }
    }

    private static var hasCloudKitEntitlement: Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        let value = SecTaskCopyValueForEntitlement(task, "com.apple.developer.icloud-services" as CFString, nil)
        guard let services = value as? [String] else { return false }
        return services.contains("CloudKit")
    }
}

private extension String {
    var base64FilenameSafe: String {
        Data(utf8).base64EncodedString()
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }
}
