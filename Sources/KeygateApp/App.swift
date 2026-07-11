import AppKit
import SwiftUI

final class KeygateAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let settings = AppSettings.shared
        settings.applyActivationPolicy()
        DispatchQueue.main.async {
            if settings.startInMenuBar {
                // Launch straight to the menu bar: close the auto-opened window.
                NSApplication.shared.windows.filter { $0.canBecomeMain }.forEach { $0.close() }
            } else {
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
        }
    }

    // Keep the app alive in the menu bar when the window closes, if configured.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !AppSettings.shared.keepRunningWithoutWindows
    }

    // Re-show the single window when the app is reactivated from the Dock.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        sender.activate(ignoringOtherApps: true)
        sender.windows.first?.makeKeyAndOrderFront(nil)
        return true
    }
}

struct KeygateApplication: App {
    @NSApplicationDelegateAdaptor(KeygateAppDelegate.self) private var appDelegate
    @StateObject private var controller = KeygateController()

    var body: some Scene {
        // `Window` (vs. `WindowGroup`) is a single-instance scene, so the app
        // never opens more than one main window.
        Window("Keygate", id: "main") {
            ContentView()
                .environmentObject(controller)
                .frame(minWidth: 760, minHeight: 620)
        }
        .windowResizability(.contentMinSize)

        MenuBarExtra("Keygate", systemImage: "key.horizontal.fill") {
            KeygateMenu()
                .environmentObject(controller)
        }

        Settings {
            SettingsView()
        }
    }
}

/// Entry point. Supports a hidden `--render-ui <out.png>` mode that renders
/// the UI off-screen to a PNG (used for verification) instead of launching
/// the windowed app.
@main
enum AppMain {
    static func main() {
        // The SSH agent writes to Unix sockets; a client disconnect must not
        // terminate the process via the default SIGPIPE disposition.
        signal(SIGPIPE, SIG_IGN)

        if CommandLine.arguments.contains("--render-ui") {
            RenderHarness.run()
        } else {
            KeygateApplication.main()
        }
    }
}

private struct KeygateMenu: View {
    @EnvironmentObject var controller: KeygateController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
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
        SettingsLink {
            Text("Settings…")
        }
        Divider()
        Button("Copy SSH_AUTH_SOCK") {
            controller.copySocketPath()
        }
        Button("Quit") {
            NSApplication.shared.terminate(nil)
        }
    }
}
