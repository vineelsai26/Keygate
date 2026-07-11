import KeygateCore
import SwiftUI
import VKit

/// The Setup tab: shell/SSH config snippets, git signing, and environment diagnostics.
struct SetupSection: View {
    @EnvironmentObject var controller: KeygateController
    @State private var selectedSigningKeyFingerprint: String = ""
    @State private var enableCommitSigning = true
    @State private var enableTagSigning = true

    var body: some View {
        Card(title: "Setup", systemImage: "terminal") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Shell")
                    .font(.headline)
                CodeBlock(Diagnostics.shellSnippet)
                Text("SSH config")
                    .font(.headline)
                CodeBlock(Diagnostics.sshConfigSnippet)
            }

            Text("Apply the snippets for you, or copy them to paste manually.")
                .font(.caption)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Button {
                        controller.installAutomatically()
                    } label: {
                        Label("Configure Automatically", systemImage: "wand.and.stars")
                    }
                    .buttonStyle(.borderedProminent)
                    .help("Write Keygate into your shell profile and ~/.ssh/config")

                    Button {
                        controller.copySocketPath()
                    } label: {
                        Label("Copy Shell Snippet", systemImage: "doc.on.doc")
                    }
                }

                HStack(spacing: 8) {
                    Button {
                        controller.installShellProfile()
                    } label: {
                        Label(
                            controller.shellProfileConfigured ? "Update Shell Profile" : "Add to Shell Profile",
                            systemImage: controller.shellProfileConfigured ? "checkmark.circle" : "text.badge.plus"
                        )
                    }
                    .help("Edit \(SetupInstaller.preferredShellProfileURL().path)")

                    Button {
                        controller.installSSHConfig()
                    } label: {
                        Label(
                            controller.sshConfigConfigured ? "Update SSH Config" : "Add to SSH Config",
                            systemImage: controller.sshConfigConfigured ? "checkmark.circle" : "doc.badge.plus"
                        )
                    }
                    .help("Edit \(SetupInstaller.sshConfigURL().path)")
                }
            }
        }

        Card(title: "Git commit signing", systemImage: "pencil.and.outline") {
            Text("Sign commits and tags with a Keygate SSH key over the agent (no private key on disk for git).")
                .font(.caption)
                .foregroundStyle(.secondary)

            if controller.keys.isEmpty {
                Text("Generate or import a signing key on the Keys tab first.")
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Signing key", selection: $selectedSigningKeyFingerprint) {
                        ForEach(controller.keys) { key in
                            Text("\(key.comment)  \(key.fingerprint)")
                                .tag(key.fingerprint)
                        }
                    }
                    .labelsHidden()

                    Toggle("Sign commits (`commit.gpgsign`)", isOn: $enableCommitSigning)
                    Toggle("Sign tags (`tag.gpgSign`)", isOn: $enableTagSigning)

                    HStack(spacing: 6) {
                        Image(systemName: controller.gitSigningConfigured ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(controller.gitSigningConfigured ? .green : .orange)
                        Text(controller.gitSigningStatusMessage)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }

                    HStack(spacing: 8) {
                        Button {
                            guard let key = controller.keys.first(where: { $0.fingerprint == selectedSigningKeyFingerprint })
                                    ?? controller.preferredSigningKey()
                            else { return }
                            controller.installGitSigning(
                                key: key,
                                enableCommitSigning: enableCommitSigning,
                                enableTagSigning: enableTagSigning
                            )
                        } label: {
                            Label(
                                controller.gitSigningConfigured ? "Update Git Signing" : "Configure Git Signing",
                                systemImage: controller.gitSigningConfigured ? "checkmark.circle" : "signature"
                            )
                        }
                        .buttonStyle(.borderedProminent)
                        .help("Writes ~/.ssh/keygate_signing.pub, installs Keygate’s gpg.ssh.program wrapper, and enables SSH commit/tag signing")

                        Button {
                            guard let key = controller.keys.first(where: { $0.fingerprint == selectedSigningKeyFingerprint })
                                    ?? controller.preferredSigningKey()
                            else { return }
                            controller.copyPublicKey(key)
                            controller.noticeMessage = "Public key copied — add it on GitHub as a Signing key"
                        } label: {
                            Label("Copy Public Key", systemImage: "doc.on.doc")
                        }
                        .help("Copy the public key for GitHub → Settings → SSH and GPG keys → New SSH key → Key type: Signing Key")
                    }
                }
                .onAppear { selectDefaultSigningKey() }
                .onChange(of: controller.keys.map(\.fingerprint)) { _, _ in
                    selectDefaultSigningKey()
                }
            }
        }

        Card(title: "Diagnostics", systemImage: "stethoscope") {
            ForEach(controller.diagnostics) { item in
                HStack {
                    Image(systemName: icon(for: item.severity))
                        .foregroundStyle(color(for: item.severity))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.name)
                        Text(item.message)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Spacer()
                }
            }
        }
    }

    private func selectDefaultSigningKey() {
        if !selectedSigningKeyFingerprint.isEmpty,
           controller.keys.contains(where: { $0.fingerprint == selectedSigningKeyFingerprint }) {
            return
        }
        selectedSigningKeyFingerprint = controller.preferredSigningKey()?.fingerprint ?? ""
    }

    private func icon(for severity: DiagnosticItem.Severity) -> String {
        switch severity {
        case .ok: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    private func color(for severity: DiagnosticItem.Severity) -> Color {
        switch severity {
        case .ok: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }
}
