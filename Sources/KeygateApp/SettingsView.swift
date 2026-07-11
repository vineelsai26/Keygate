import SwiftUI

struct SettingsView: View {
    @ObservedObject var settings = AppSettings.shared

    var body: some View {
        Form {
            Section("Startup") {
                Toggle("Launch Keygate at login", isOn: $settings.launchAtLogin)
                Toggle("Start the SSH agent automatically", isOn: $settings.autostartAgent)
                Toggle("Start in the menu bar (don't open the window)", isOn: $settings.startInMenuBar)
            }

            Section("Window & Dock") {
                Toggle("Keep running in the menu bar when the window is closed", isOn: $settings.closeToMenuBar)
                Toggle("Show icon in the Dock", isOn: $settings.showInDock)
                Text("Turn off the Dock icon to run Keygate as a menu-bar-only app.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Security") {
                Toggle("Lock the vault when the Mac sleeps", isOn: $settings.lockOnSleep)
                Text("Requires passphrase encryption. On wake you'll unlock once before keys can be used.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Toggle("Unlock with Touch ID", isOn: $settings.unlockWithTouchID)
                Text("Saves the vault passphrase in your login Keychain. Unlock prompts for Touch ID (or your Mac password) instead of retyping the passphrase. Turning this off removes the saved passphrase.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460, height: 440)
    }
}
