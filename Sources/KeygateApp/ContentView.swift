import KeygateCore
import SwiftUI
import VKit

/// The main window sections, shown one at a time behind a segmented picker.
enum KeygateTab: String, CaseIterable, Identifiable {
    case keys = "Keys"
    case policy = "Policy"
    case activity = "Activity"
    case setup = "Setup"

    var id: String { rawValue }
}

/// The main window shell: app header, always-visible status band, and a
/// segmented picker switching between the four content sections. Each
/// section owns its own sheets; only vault unlocking is handled here since
/// it can be triggered app-wide.
struct ContentView: View {
    @EnvironmentObject var controller: KeygateController
    @State private var tab: KeygateTab
    @State private var showUnlockSheet = false
    /// Off for `RenderHarness`: ImageRenderer can't render ScrollViews, so the
    /// sections lay out at their natural height instead.
    private let scrollsContent: Bool

    init(initialTab: KeygateTab = .keys, scrollsContent: Bool = true) {
        _tab = State(initialValue: initialTab)
        self.scrollsContent = scrollsContent
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.sectionSpacing) {
            AppHeader(
                title: "Keygate",
                subtitle: "SSH keys with app, destination, and Touch ID policy",
                systemImage: "key.horizontal.fill"
            ) {
                Button {
                    controller.refresh()
                    controller.checkCloudStatus()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh")
            }

            statusBand

            if let error = controller.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let notice = controller.noticeMessage {
                Label(notice, systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Picker("Section", selection: $tab) {
                ForEach(KeygateTab.allCases) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if scrollsContent {
                ScrollView {
                    sections
                }
            } else {
                sections
            }
        }
        .padding([.top, .horizontal], Theme.pagePadding)
        .background(Palette.background)
        .tint(Palette.accent)
        .onAppear {
            controller.refresh()
            controller.checkCloudStatus()
            presentUnlockIfNeeded()
        }
        .onChange(of: controller.vaultLocked) { _, locked in
            if locked { presentUnlockIfNeeded() }
        }
        // Agent sign requests refuse while locked and post this so we re-prompt
        // even if the user already dismissed the unlock sheet.
        .onReceive(NotificationCenter.default.publisher(for: .keygateVaultNeedsUnlock)) { _ in
            controller.refresh()
            presentUnlockIfNeeded()
        }
        .sheet(isPresented: $showUnlockSheet) {
            UnlockSheet(
                canUseTouchID: controller.passphraseStoredInKeychain,
                onUnlock: { passphrase, save in
                    controller.unlockVault(passphrase: passphrase, saveToKeychain: save)
                },
                onTouchID: { completion in
                    controller.tryBiometricUnlockIfAvailable(completion: completion)
                }
            )
        }
    }

    private var sections: some View {
        VStack(alignment: .leading, spacing: Theme.sectionSpacing) {
            switch tab {
            case .keys: KeysSection()
            case .policy: PolicySection()
            case .activity: ActivitySection()
            case .setup: SetupSection()
            }
        }
        .padding(.bottom, Theme.pagePadding)
    }

    /// Show the unlock sheet when locked. The sheet auto-offers Touch ID when a
    /// passphrase is already stored in the Keychain.
    private func presentUnlockIfNeeded() {
        guard controller.vaultLocked else { return }
        showUnlockSheet = true
    }

    private var statusBand: some View {
        HStack(spacing: 12) {
            StatusPill(
                controller.agentRunning ? "Agent running" : "Agent stopped",
                systemImage: "bolt.horizontal.circle",
                tone: controller.agentRunning ? .good : .neutral
            )
            if controller.encryptionEnabled {
                StatusPill(
                    controller.vaultLocked ? "Locked" : "Unlocked",
                    systemImage: controller.vaultLocked ? "lock.fill" : "lock.open.fill",
                    tone: controller.vaultLocked ? .warning : .good
                )
            }
            Spacer()
            if controller.encryptionEnabled {
                if controller.vaultLocked {
                    if controller.passphraseStoredInKeychain {
                        Button("Unlock with Touch ID") {
                            controller.tryBiometricUnlockIfAvailable { success in
                                if !success { showUnlockSheet = true }
                            }
                        }
                    }
                    Button("Unlock…") { showUnlockSheet = true }
                } else {
                    Button("Lock") { controller.lockVault() }
                }
            }
            Button(controller.agentRunning ? "Stop Agent" : "Start Agent") {
                controller.toggleAgent()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(12)
        .background(Palette.surface.opacity(0.06), in: RoundedRectangle(cornerRadius: Theme.cardRadius))
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cardRadius)
                .strokeBorder(Palette.border.opacity(0.6), lineWidth: 1)
        )
    }
}
