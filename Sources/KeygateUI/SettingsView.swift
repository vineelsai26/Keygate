import SwiftUI

struct SettingsView: View {
    @ObservedObject var settings = AppSettings.shared
    let embedded: Bool

    init(embedded: Bool = false) {
        self.embedded = embedded
    }

    @ViewBuilder
    var body: some View {
        if embedded {
            settingsForm(includeStandaloneBehavior: false)
                .formStyle(.grouped)
                .scrollContentBackground(.hidden)
        } else {
            settingsForm(includeStandaloneBehavior: true)
                .formStyle(.grouped)
                .frame(width: 460, height: 440)
        }
    }

    private func settingsForm(includeStandaloneBehavior: Bool) -> some View {
        Form {
            if includeStandaloneBehavior {
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
            }

            securitySection
        }
    }

    private var securitySection: some View {
        Section("Security") {
            Toggle("Lock the vault when the Mac sleeps", isOn: $settings.lockOnSleep)
            Text("Requires passphrase encryption. On wake you'll unlock once before keys can be used.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Toggle("Allow Touch ID unlock", isOn: $settings.unlockWithTouchID)
            Text("When enabled, a passphrase unlock can save the passphrase in your login Keychain for later Touch ID (or Mac password) prompts. Turning this off removes any saved passphrase.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
