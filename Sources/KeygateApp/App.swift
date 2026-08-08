import AppKit
import KeygateUI
import SwiftUI

final class KeygateAppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // Info.plist starts Keygate as an accessory app. Apply the saved override
        // before SwiftUI creates its scenes so a disabled Dock icon never flashes.
        KeygateAppSupport.applyActivationPolicy()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async {
            // SwiftUI finishes registering its Window and Settings scenes after the
            // launch callback. Reassert the preference once that setup is complete.
            KeygateAppSupport.applyActivationPolicy()
            if KeygateAppSupport.startInMenuBar {
                // Launch straight to the menu bar: close the auto-opened window.
                NSApplication.shared.windows.filter { $0.canBecomeMain }.forEach { $0.close() }
            } else {
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
        }
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        // Opening or restoring a SwiftUI window must not promote a menu-bar-only
        // Keygate process back to a regular Dock application.
        KeygateAppSupport.applyActivationPolicy()
    }

    // Keep the app alive in the menu bar when the window closes, if configured.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !KeygateAppSupport.keepRunningWithoutWindows
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
    @StateObject private var runtime = KeygateRuntime()

    var body: some Scene {
        // `Window` (vs. `WindowGroup`) is a single-instance scene, so the app
        // never opens more than one main window.
        Window("Keygate", id: "main") {
            KeygateMainView(runtime: runtime)
                .frame(minWidth: 760, minHeight: 620)
        }
        .windowResizability(.contentMinSize)

        MenuBarExtra("Keygate", systemImage: "key.horizontal.fill") {
            KeygateMenuContent(runtime: runtime)
        }

        Settings {
            KeygateSettingsContent()
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
            KeygateAppSupport.renderUI()
        } else {
            KeygateApplication.main()
        }
    }
}
