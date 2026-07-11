import Foundation

public enum AgentMessageType {
    public static let failure: UInt8 = 5
    public static let success: UInt8 = 6
    public static let requestIdentities: UInt8 = 11
    public static let identitiesAnswer: UInt8 = 12
    public static let signRequest: UInt8 = 13
    public static let signResponse: UInt8 = 14
    public static let extensionRequest: UInt8 = 27
    public static let extensionFailure: UInt8 = 28
}

public enum SignatureFlag: UInt32 {
    case rsaSHA256 = 2
    case rsaSHA512 = 4
}

public struct AgentIdentity: Equatable, Codable, Identifiable {
    public var id: String { fingerprint }
    public let keyBlob: Data
    public let comment: String
    public let fingerprint: String
    public let keyType: String

    public init(keyBlob: Data, comment: String, fingerprint: String, keyType: String) {
        self.keyBlob = keyBlob
        self.comment = comment
        self.fingerprint = fingerprint
        self.keyType = keyType
    }
}

public struct AgentSignRequest: Equatable {
    public let keyBlob: Data
    public let payload: Data
    public let flags: UInt32

    public init(keyBlob: Data, payload: Data, flags: UInt32) {
        self.keyBlob = keyBlob
        self.payload = payload
        self.flags = flags
    }
}

public enum AgentRequest: Equatable {
    case requestIdentities
    case sign(AgentSignRequest)
    case extensionRequest(name: String, payload: Data)
    case unsupported(type: UInt8)
}

public enum AgentResponse: Equatable {
    case success
    case failure
    case identities([AgentIdentity])
    case signature(algorithm: String, signature: Data)
    case extensionFailure
}

public enum AgentProtocolCodec {
    public static func parse(_ payload: Data) throws -> AgentRequest {
        var reader = SSHReader(payload)
        let type = try reader.readByte()
        switch type {
        case AgentMessageType.requestIdentities:
            try reader.requireEOF()
            return .requestIdentities
        case AgentMessageType.signRequest:
            let keyBlob = try reader.readDataString()
            let signPayload = try reader.readDataString()
            let flags = try reader.readUInt32()
            try reader.requireEOF()
            return .sign(AgentSignRequest(keyBlob: keyBlob, payload: signPayload, flags: flags))
        case AgentMessageType.extensionRequest:
            let name = try reader.readString()
            let remaining = reader.remaining
            var extensionPayload = Data()
            if remaining > 0 {
                for _ in 0 ..< remaining {
                    extensionPayload.append(try reader.readByte())
                }
            }
            return .extensionRequest(name: name, payload: extensionPayload)
        default:
            return .unsupported(type: type)
        }
    }

    public static func encode(_ response: AgentResponse) -> Data {
        var writer = SSHWriter()
        switch response {
        case .success:
            writer.writeByte(AgentMessageType.success)
        case .failure:
            writer.writeByte(AgentMessageType.failure)
        case .extensionFailure:
            writer.writeByte(AgentMessageType.extensionFailure)
        case .identities(let identities):
            writer.writeByte(AgentMessageType.identitiesAnswer)
            writer.writeUInt32(UInt32(identities.count))
            for identity in identities {
                writer.writeDataString(identity.keyBlob)
                writer.writeString(identity.comment)
            }
        case .signature(let algorithm, let signature):
            writer.writeByte(AgentMessageType.signResponse)
            var blob = SSHWriter()
            blob.writeString(algorithm)
            blob.writeDataString(signature)
            writer.writeDataString(blob.finish())
        }
        return writer.finish()
    }

    public static func packet(_ response: AgentResponse) -> Data {
        let payload = encode(response)
        var packet = Data()
        packet.append(UInt8((payload.count >> 24) & 0xff))
        packet.append(UInt8((payload.count >> 16) & 0xff))
        packet.append(UInt8((payload.count >> 8) & 0xff))
        packet.append(UInt8(payload.count & 0xff))
        packet.append(payload)
        return packet
    }
}
