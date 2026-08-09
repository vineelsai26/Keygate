/// Coalesces overlapping biometric-unlock requests into one system operation.
///
/// Keygate's SwiftUI surfaces can be reconstructed while controller state is
/// refreshing. Every caller still receives the shared result, but only the
/// first caller starts authentication. Call this object from one serialized
/// executor (KeygateController uses the main actor).
package final class BiometricUnlockSingleFlight {
    package private(set) var isRunning = false

    private var completions: [(Bool) -> Void] = []

    package init() {}

    package func run(
        completion: ((Bool) -> Void)?,
        operation: (@escaping (Bool) -> Void) -> Void
    ) {
        if let completion { completions.append(completion) }
        guard !isRunning else { return }

        isRunning = true
        operation { [weak self] success in
            self?.finish(success: success)
        }
    }

    private func finish(success: Bool) {
        isRunning = false
        let pending = completions
        completions.removeAll(keepingCapacity: true)
        for completion in pending {
            completion(success)
        }
    }
}
