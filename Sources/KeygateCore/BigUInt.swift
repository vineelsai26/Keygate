import Foundation

/// Minimal unsigned big integer — just enough to compute the RSA CRT exponents
/// (`dP = d mod (p-1)`, `dQ = d mod (q-1)`) that OpenSSH omits but PKCS#1 requires.
/// Big-endian byte representation; correctness over speed (import is one-shot).
struct BigUInt {
    /// Normalized big-endian magnitude with no leading zero bytes (empty == 0).
    private(set) var bytes: [UInt8]

    init(_ data: Data) {
        self.init(bytes: Array(data))
    }

    init(bytes: [UInt8]) {
        var value = bytes
        while value.first == 0 { value.removeFirst() }
        self.bytes = value
    }

    var isZero: Bool { bytes.isEmpty }

    func toData() -> Data { Data(bytes) }

    /// Subtracts a small value (used for `p - 1`). Assumes the result is non-negative.
    func subtracting(_ value: UInt8) -> BigUInt {
        var result = bytes
        var borrow = Int(value)
        var index = result.count - 1
        while borrow > 0 && index >= 0 {
            let current = Int(result[index]) - (borrow & 0xff)
            if current < 0 {
                result[index] = UInt8(current + 256)
                borrow = 1
            } else {
                result[index] = UInt8(current)
                borrow = 0
            }
            index -= 1
        }
        return BigUInt(bytes: result)
    }

    private static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
        if a.count != b.count { return a.count < b.count ? -1 : 1 }
        for i in 0 ..< a.count where a[i] != b[i] {
            return a[i] < b[i] ? -1 : 1
        }
        return 0
    }

    /// `a - b`, big-endian, assuming `a >= b`.
    private static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = a
        var borrow = 0
        var ai = a.count - 1
        var bi = b.count - 1
        while ai >= 0 {
            let bv = bi >= 0 ? Int(b[bi]) : 0
            var diff = Int(result[ai]) - bv - borrow
            if diff < 0 { diff += 256; borrow = 1 } else { borrow = 0 }
            result[ai] = UInt8(diff)
            ai -= 1; bi -= 1
        }
        while result.first == 0 { result.removeFirst() }
        return result
    }

    /// Remainder of `self mod modulus` via binary long division.
    func modulo(_ modulus: BigUInt) -> BigUInt {
        precondition(!modulus.isZero, "modulo by zero")
        if BigUInt.compare(bytes, modulus.bytes) < 0 { return self }
        var remainder: [UInt8] = []
        let divisor = modulus.bytes
        for byte in bytes {
            for bit in stride(from: 7, through: 0, by: -1) {
                // remainder = (remainder << 1) | nextBit
                var carry = UInt8((byte >> UInt8(bit)) & 1)
                for i in stride(from: remainder.count - 1, through: 0, by: -1) {
                    let shifted = (UInt16(remainder[i]) << 1) | UInt16(carry)
                    remainder[i] = UInt8(shifted & 0xff)
                    carry = UInt8(shifted >> 8)
                }
                if carry != 0 { remainder.insert(carry, at: 0) }
                while remainder.first == 0 { remainder.removeFirst() }
                if BigUInt.compare(remainder, divisor) >= 0 {
                    remainder = BigUInt.subtract(remainder, divisor)
                }
            }
        }
        return BigUInt(bytes: remainder)
    }
}
