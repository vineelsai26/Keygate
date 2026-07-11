import Foundation

/// Minimal DER support: enough to read RSA private/public components, build a
/// PKCS#1 `RSAPrivateKey` from OpenSSH's raw integers (Phase 3 import), and
/// wrap key material in PKCS#8 / SEC1 structures for export.
public enum ASN1 {
    public enum ASN1Error: Error, CustomStringConvertible {
        case truncated
        case unexpectedTag(UInt8)
        case lengthTooLarge

        public var description: String {
            switch self {
            case .truncated: return "DER data ended unexpectedly"
            case .unexpectedTag(let tag): return "Unexpected DER tag 0x\(String(tag, radix: 16))"
            case .lengthTooLarge: return "DER length field is too large"
            }
        }
    }

    static let integerTag: UInt8 = 0x02
    static let bitStringTag: UInt8 = 0x03
    static let octetStringTag: UInt8 = 0x04
    static let nullTag: UInt8 = 0x05
    static let oidTag: UInt8 = 0x06
    static let sequenceTag: UInt8 = 0x30

    // MARK: Reading

    public struct Reader {
        private let bytes: [UInt8]
        private var offset = 0

        public init(_ data: Data) { bytes = Array(data) }

        public var isAtEnd: Bool { offset >= bytes.count }

        /// Reads one tag-length-value triple, returning the tag and raw value bytes.
        public mutating func read() throws -> (tag: UInt8, value: Data) {
            guard offset < bytes.count else { throw ASN1Error.truncated }
            let tag = bytes[offset]; offset += 1
            let length = try readLength()
            guard offset + length <= bytes.count else { throw ASN1Error.truncated }
            let value = Data(bytes[offset ..< offset + length])
            offset += length
            return (tag, value)
        }

        /// Reads one TLV and returns its value, optionally asserting the tag.
        public mutating func readTLV(expect tag: UInt8? = nil) throws -> Data {
            let (actual, value) = try read()
            if let tag, tag != actual { throw ASN1Error.unexpectedTag(actual) }
            return value
        }

        /// Reads a DER INTEGER as an `Int` (for small values like iteration counts).
        public mutating func readInt() throws -> Int {
            let value = try readTLV(expect: integerTag)
            var result = 0
            for byte in value { result = (result << 8) | Int(byte) }
            return result
        }

        private mutating func readLength() throws -> Int {
            guard offset < bytes.count else { throw ASN1Error.truncated }
            let first = bytes[offset]; offset += 1
            if first & 0x80 == 0 { return Int(first) }
            let count = Int(first & 0x7f)
            guard count > 0 && count <= 4 else { throw ASN1Error.lengthTooLarge }
            var length = 0
            for _ in 0 ..< count {
                guard offset < bytes.count else { throw ASN1Error.truncated }
                length = (length << 8) | Int(bytes[offset]); offset += 1
            }
            return length
        }
    }

    /// Parses a PKCS#1 `RSAPublicKey` (`SEQUENCE { INTEGER n, INTEGER e }`).
    /// Returned magnitudes are DER INTEGER content bytes; `SSHWriter.writeMPInt` normalizes them.
    public static func rsaPublicComponents(fromPKCS1 der: Data) throws -> (n: Data, e: Data) {
        var top = Reader(der)
        var seq = Reader(try top.readTLV(expect: sequenceTag))
        let n = try seq.readTLV(expect: integerTag)
        let e = try seq.readTLV(expect: integerTag)
        return (n, e)
    }

    /// Parses a PKCS#1 `RSAPrivateKey`, returning the components OpenSSH stores.
    /// (dP/dQ are present in the DER but recomputed on import, so they are skipped.)
    public static func rsaPrivateComponents(fromPKCS1 der: Data) throws -> (n: Data, e: Data, d: Data, p: Data, q: Data, iqmp: Data) {
        var top = Reader(der)
        var seq = Reader(try top.readTLV(expect: sequenceTag))
        _ = try seq.readTLV(expect: integerTag) // version
        let n = try seq.readTLV(expect: integerTag)
        let e = try seq.readTLV(expect: integerTag)
        let d = try seq.readTLV(expect: integerTag)
        let p = try seq.readTLV(expect: integerTag)
        let q = try seq.readTLV(expect: integerTag)
        _ = try seq.readTLV(expect: integerTag) // dP
        _ = try seq.readTLV(expect: integerTag) // dQ
        let iqmp = try seq.readTLV(expect: integerTag)
        return (n, e, d, p, q, iqmp)
    }

    // MARK: Writing

    public static func lengthBytes(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)] + bytes)
    }

    public static func tlv(_ tag: UInt8, _ value: Data) -> Data {
        var out = Data([tag])
        out.append(lengthBytes(value.count))
        out.append(value)
        return out
    }

    /// Encodes an unsigned big-endian magnitude as a DER INTEGER (minimal, non-negative).
    public static func integer(_ magnitude: Data) -> Data {
        let bytes = Array(magnitude)
        var start = 0
        while start < bytes.count - 1 && bytes[start] == 0 { start += 1 }
        var value = bytes.isEmpty ? [0] : Array(bytes[start...])
        if value.isEmpty { value = [0] }
        if value[0] & 0x80 != 0 { value.insert(0, at: 0) }
        return tlv(integerTag, Data(value))
    }

    public static func sequence(_ elements: [Data]) -> Data {
        var body = Data()
        for element in elements { body.append(element) }
        return tlv(sequenceTag, body)
    }

    public static func octetString(_ value: Data) -> Data {
        tlv(octetStringTag, value)
    }

    /// DER BIT STRING with zero unused bits (the only shape SSH keys need).
    public static func bitString(_ value: Data) -> Data {
        tlv(bitStringTag, Data([0]) + value)
    }

    public static func null() -> Data {
        tlv(nullTag, Data())
    }

    /// OBJECT IDENTIFIER from pre-encoded content bytes.
    public static func objectIdentifier(_ contentBytes: [UInt8]) -> Data {
        tlv(oidTag, Data(contentBytes))
    }

    /// Context-specific constructed tag `[n]` (e.g. SEC1's `[1] publicKey`).
    public static func contextConstructed(_ number: UInt8, _ value: Data) -> Data {
        tlv(0xA0 | number, value)
    }
}
