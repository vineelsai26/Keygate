import AppKit
import Foundation
import KeygateCore
import ServiceManagement

/// User-configurable app behavior, persisted in `UserDefaults`. Toggles that have
/// system side effects (login item, Dock visibility) apply them from `didSet`.
@MainActor
final class AppSettings: ObservableObject {
    static let shared = AppSettings()

    private let defaults = UserDefaults.standard

    /// Register Keygate as a macOS login item so it starts at boot/login.
    @Published var launchAtLogin: Bool { didSet { applyLoginItem() } }
    /// Start the SSH agent automatically when the app launches.
    @Published var autostartAgent: Bool { didSet { defaults.set(autostartAgent, forKey: Keys.autostartAgent) } }
    /// Launch straight to the menu bar without opening the main window.
    @Published var startInMenuBar: Bool { didSet { defaults.set(startInMenuBar, forKey: Keys.startInMenuBar) } }
    /// Closing the main window keeps the app running in the menu bar instead of quitting.
    @Published var closeToMenuBar: Bool { didSet { defaults.set(closeToMenuBar, forKey: Keys.closeToMenuBar) } }
    /// Show the Dock icon. When off, Keygate runs as a menu-bar-only accessory.
    @Published var showInDock: Bool { didSet { defaults.set(showInDock, forKey: Keys.showInDock); applyActivationPolicy() } }
    /// Lock the (encrypted) vault automatically when the Mac goes to sleep.
    @Published var lockOnSleep: Bool { didSet { defaults.set(lockOnSleep, forKey: Keys.lockOnSleep) } }
    /// Keep the vault passphrase in the login Keychain so unlock can use Touch ID.
    /// Turning this off deletes the stored passphrase.
    @Published var unlockWithTouchID: Bool {
        didSet {
            defaults.set(unlockWithTouchID, forKey: Keys.unlockWithTouchID)
            if !unlockWithTouchID {
                _ = VaultPassphraseStore.delete()
            }
        }
    }

    private enum Keys {
        static let autostartAgent = "autostartAgent"
        static let startInMenuBar = "startInMenuBar"
        static let closeToMenuBar = "closeToMenuBar"
        static let showInDock = "showInDock"
        static let lockOnSleep = "lockOnSleep"
        static let unlockWithTouchID = "unlockWithTouchID"
    }

    private init() {
        defaults.register(defaults: [
            Keys.showInDock: true,
            Keys.unlockWithTouchID: true,
        ])
        autostartAgent = defaults.bool(forKey: Keys.autostartAgent)
        startInMenuBar = defaults.bool(forKey: Keys.startInMenuBar)
        closeToMenuBar = defaults.bool(forKey: Keys.closeToMenuBar)
        showInDock = defaults.bool(forKey: Keys.showInDock)
        lockOnSleep = defaults.bool(forKey: Keys.lockOnSleep)
        unlockWithTouchID = defaults.bool(forKey: Keys.unlockWithTouchID)
        // Reflect the real login-item state rather than a stored guess.
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    /// Whether closing the last window should keep the app alive in the menu bar.
    var keepRunningWithoutWindows: Bool {
        closeToMenuBar || startInMenuBar || !showInDock
    }

    func applyActivationPolicy() {
        NSApp.setActivationPolicy(showInDock ? .regular : .accessory)
    }

    private func applyLoginItem() {
        do {
            switch (launchAtLogin, SMAppService.mainApp.status) {
            case (true, let status) where status != .enabled:
                try SMAppService.mainApp.register()
            case (false, .enabled):
                try SMAppService.mainApp.unregister()
            default:
                break
            }
        } catch {
            NSLog("Keygate: failed to update login item: \(error)")
        }
    }
}
