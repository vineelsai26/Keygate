import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// Presents a biometric / password prompt before a gated signature.
///
/// This is deliberately independent of the Keychain item's own access control:
/// the data-protection Keychain (and its `.userPresence` Touch ID gate) is only
/// available to provisioned apps, so ad-hoc and self-signed builds fall back to
/// plain accessibility with no biometric prompt. Gating here in the app means
/// Touch ID works regardless of how the build is signed.
public protocol SigningAuthorizer {
    /// Returns true when the user approves. `reason` is shown in the system sheet.
    func authorize(reason: String) -> Bool
}

/// Prompts with Touch ID, falling back to the login password, via LocalAuthentication.
public struct LocalAuthorizer: SigningAuthorizer {
    public init() {}

    public func authorize(reason: String) -> Bool {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password…"
        // deviceOwnerAuthentication = biometrics with automatic password fallback,
        // so it still works on Macs without a Touch ID sensor.
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            return false
        }
        // evaluatePolicy is async and delivers its result on a private queue, so
        // blocking here is safe: signing runs on the socket server's background queue.
        let semaphore = DispatchSemaphore(value: 0)
        var granted = false
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            granted = success
            semaphore.signal()
        }
        semaphore.wait()
        return granted
        #else
        return false
        #endif
    }
}

/// Approves without prompting. Used by the CLI and self-tests, where there is no
/// interactive session to present a biometric sheet.
public struct AllowAllAuthorizer: SigningAuthorizer {
    public init() {}
    public func authorize(reason: String) -> Bool { true }
}
