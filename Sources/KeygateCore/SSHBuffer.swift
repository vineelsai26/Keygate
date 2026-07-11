import Foundation

public enum SSHCodecError: Error, CustomStringConvertible {
    case shortRead
    case invalidUtf8
    case trailingBytes(Int)

    public var description: String {
        switch self {
        case .shortRead:
            return "SSH agent message ended unexpectedly"
        case .invalidUtf8:
            return "SSH string was not valid UTF-8"
        case .trailingBytes(let count):
            return "SSH agent message had \(count) trailing bytes"
        }
    }
}

public struct SSHReader {
    private let bytes: [UInt8]
    private var offset: Int = 0

    public init(_ data: Data) {
        self.bytes = Array(data)
    }

    public var remaining: Int {
        bytes.count - offset
    }

    public mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw SSHCodecError.shortRead }
        let value = bytes[offset]
        offset += 1
        return value
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= bytes.count else { throw SSHCodecError.shortRead }
        let value = UInt32(bytes[offset]) << 24
            | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8
            | UInt32(bytes[offset + 3])
        offset += 4
        return value
    }

    public mutating func readBool() throws -> Bool {
        try readByte() != 0
    }

    public mutating func readDataString() throws -> Data {
        let length = Int(try readUInt32())
        guard offset + length <= bytes.count else { throw SSHCodecError.shortRead }
        let value = Data(bytes[offset ..< offset + length])
        offset += length
        return value
    }

    public mutating func readString() throws -> String {
        let data = try readDataString()
        guard let value = String(data: data, encoding: .utf8) else {
            throw SSHCodecError.invalidUtf8
        }
        return value
    }

    /// Reads an SSH `mpint` and returns its unsigned big-endian magnitude
    /// (leading sign/zero bytes stripped). SSH keys only carry positive values.
    public mutating func readMPInt() throws -> Data {
        let raw = try readDataString()
        let bytes = Array(raw)
        var start = 0
        while start < bytes.count && bytes[start] == 0 { start += 1 }
        return Data(bytes[start...])
    }

    public func requireEOF() throws {
        if remaining != 0 {
            throw SSHCodecError.trailingBytes(remaining)
        }
    }
}

public struct SSHWriter {
    private var data = Data()

    public init() {}

    public mutating func writeByte(_ value: UInt8) {
        data.append(value)
    }

    public mutating func writeBool(_ value: Bool) {
        writeByte(value ? 1 : 0)
    }

    public mutating func writeUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    public mutating func writeDataString(_ value: Data) {
        writeUInt32(UInt32(value.count))
        data.append(value)
    }

    public mutating func writeString(_ value: String) {
        writeDataString(Data(value.utf8))
    }

    /// Writes an unsigned big-endian magnitude as an SSH `mpint`: minimal length,
    /// with a leading `0x00` prepended when the high bit of the first byte is set
    /// (so it is never interpreted as negative). Zero encodes as an empty string.
    public mutating func writeMPInt(_ magnitude: Data) {
        let bytes = Array(magnitude)
        var start = 0
        while start < bytes.count && bytes[start] == 0 { start += 1 }
        var trimmed = Array(bytes[start...])
        if trimmed.isEmpty {
            writeDataString(Data())
            return
        }
        if trimmed[0] & 0x80 != 0 {
            trimmed.insert(0, at: 0)
        }
        writeDataString(Data(trimmed))
    }

    public func finish() -> Data {
        data
    }

    public func finishPacket() -> Data {
        var packet = Data()
        packet.append(UInt8((data.count >> 24) & 0xff))
        packet.append(UInt8((data.count >> 16) & 0xff))
        packet.append(UInt8((data.count >> 8) & 0xff))
        packet.append(UInt8(data.count & 0xff))
        packet.append(data)
        return packet
    }
}
