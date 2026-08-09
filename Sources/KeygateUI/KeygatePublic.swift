import AppKit
import Combine
import SwiftUI

// Public embedding API for Keygate. View/controller types stay internal;
// consumers (the standalone KeygateApp and the PowerTools suite) use only
// these wrappers.

/// Owns one Keygate instance's controller. `allowAutostart` is false when
/// embedded, so an embedded Keygate never auto-binds the singleton SSH agent
/// socket and cannot fight a standalone Keygate for it.
@MainActor
public final class KeygateRuntime: ObservableObject {
    let controller: KeygateController
    private var forward: AnyCancellable?

    public init(allowAutostart: Bool = true) {
        self.controller = KeygateController(allowAutostart: allowAutostart)
        // The menu views observe the runtime but read controller state
        // (agentRunning, vaultLocked, …), so controller changes must
        // republish here or the menus go stale.
        forward = controller.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
    }

    /// Release the SSH agent socket if this instance holds it (called when an
    /// embedded Keygate tool is disabled).
    public func stopAgentIfRunning() {
        if controller.agentRunning { controller.toggleAgent() }
    }

    /// Apply a host-owned runtime preference without exposing the internal
    /// controller. Embedded hosts use this to restore an explicit prior choice;
    /// controller autostart remains disabled to avoid implicit socket ownership.
    public func setAgentRunning(_ running: Bool) {
        if controller.agentRunning != running { controller.toggleAgent() }
    }

    public var isAgentRunning: Bool { controller.agentRunning }
}

/// The main Keygate window content (keys, policy, activity, setup).
public struct KeygateMainView: View {
    @ObservedObject private var runtime: KeygateRuntime
    private let showsHeader: Bool

    public init(runtime: KeygateRuntime, showsHeader: Bool = true) {
        self.runtime = runtime
        self.showsHeader = showsHeader
    }

    public var body: some View {
        ContentView(showsHeader: showsHeader)
            .environmentObject(runtime.controller)
    }
}

/// Settings-window content.
public struct KeygateSettingsContent: View {
    private let embedded: Bool

    public init(embedded: Bool = false) {
        self.embedded = embedded
    }

    public var body: some View { SettingsView(embedded: embedded) }
}

/// The full menu-bar menu, used by the standalone app.
public struct KeygateMenuContent: View {
    @ObservedObject private var runtime: KeygateRuntime
    @Environment(\.openWindow) private var openWindow

    public init(runtime: KeygateRuntime) { self.runtime = runtime }

    private var controller: KeygateController { runtime.controller }

    public var body: some View {
        Button(controller.agentRunning ? "Stop Agent" : "Start Agent") {
            controller.toggleAgent()
        }
        if controller.encryptionEnabled && controller.vaultLocked {
            Button(controller.passphraseStoredInKeychain ? "Unlock with Touch ID" : "Unlock…") {
                if controller.passphraseStoredInKeychain {
                    controller.tryBiometricUnlockIfAvailable { success in
                        if !success {
                            openWindow(id: "main")
                            NSApplication.shared.activate(ignoringOtherApps: true)
                        }
                    }
                } else {
                    openWindow(id: "main")
                    NSApplication.shared.activate(ignoringOtherApps: true)
                }
            }
        }
        Button("Open Keygate") {
            openWindow(id: "main")
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
        SettingsLink { Text("Settings…") }
        Divider()
        Button("Copy SSH_AUTH_SOCK") { controller.copySocketPath() }
        Button("Quit") { NSApplication.shared.terminate(nil) }
    }
}

/// Compact agent controls for embedding in another app's menu (no Quit).
public struct KeygateEmbeddedMenu: View {
    @ObservedObject private var runtime: KeygateRuntime

    public init(runtime: KeygateRuntime) { self.runtime = runtime }

    public var body: some View {
        Text(runtime.controller.agentRunning ? "SSH agent running" : "SSH agent stopped")
        Button(runtime.controller.agentRunning ? "Stop Agent" : "Start Agent") {
            runtime.controller.toggleAgent()
        }
    }
}

/// App-lifecycle helpers for the standalone app delegate.
@MainActor
public enum KeygateAppSupport {
    public static func applyActivationPolicy() { AppSettings.shared.applyActivationPolicy() }
    public static var startInMenuBar: Bool { AppSettings.shared.startInMenuBar }
    public static var keepRunningWithoutWindows: Bool { AppSettings.shared.keepRunningWithoutWindows }
    public static func renderUI() { RenderHarness.run() }
}
