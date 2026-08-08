import KeygateCore
import SwiftUI
import VKit

/// The Keys tab: the stored key list with per-key actions, plus controls to
/// generate, import, and encrypt keys. Owns the sheets those actions open.
struct KeysSection: View {
    @EnvironmentObject var controller: KeygateController
    @State private var newKeyType: SSHKeyType = .ed25519
    @State private var newKeyRSABits = SSHSigner.defaultRSABits
    @State private var showImport = false
    @State private var renameTarget: StoredKeyRecord?
    @State private var renameText = ""
    @State private var exportTarget: StoredKeyRecord?
    @State private var ruleEditor: RuleEditorContext?
    @State private var showEncryptSheet = false

    var body: some View {
        Card(title: "Keys", systemImage: "key") {
            if controller.keys.isEmpty {
				Text(controller.encryptionEnabled
					 ? "No SSH keys yet. Generate one below, or import an existing key."
					 : "Encrypt the vault before generating or importing private keys.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(controller.keys) { key in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(key.comment).font(.headline)
                            Text("\(key.keyType.rawValue)  \(key.fingerprint)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        Spacer()
                        if key.isSynced {
                            Image(systemName: "icloud.fill").foregroundStyle(Palette.accentSecondary)
                        }
                        keyActions(for: key)
                    }
                    Divider()
                }
            }
            HStack(spacing: 8) {
                Picker("Type", selection: $newKeyType) {
                    ForEach(SSHKeyType.allCases, id: \.self) { type in
                        Text(Labels.keyType(type)).tag(type)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 190)
                if newKeyType == .rsa {
                    Picker("Bits", selection: $newKeyRSABits) {
                        ForEach(SSHSigner.supportedRSABits, id: \.self) { bits in
                            Text("\(bits)").tag(bits)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 90)
                }
                Button {
                    controller.generateKey(type: newKeyType, rsaBits: newKeyRSABits)
                } label: {
                    Label("Generate", systemImage: "plus")
                }
				.disabled(!controller.encryptionEnabled || controller.vaultLocked)
                Button {
                    showImport = true
                } label: {
                    Label("Import…", systemImage: "square.and.arrow.down")
                }
				.disabled(!controller.encryptionEnabled || controller.vaultLocked)
                Spacer()
                if !controller.encryptionEnabled {
                    Button {
                        showEncryptSheet = true
                    } label: {
					Label("Set Vault Passphrase…", systemImage: "lock")
                    }
                    .help("Encrypt private keys at rest with a passphrase you enter once per launch.")
                }
            }
        }
        .sheet(isPresented: $showImport) {
            ImportSheet { text, passphrase in
                controller.importKey(text: text, passphrase: passphrase)
            }
        }
        .sheet(item: $exportTarget) { key in
            ExportSheet(key: key) { format, passphrase, completion in
                controller.exportPrivateKey(key, format: format, passphrase: passphrase, completion: completion)
            }
        }
        .sheet(item: $ruleEditor) { context in
            RuleEditorSheet(rule: context.rule, isNew: context.isNew, keys: controller.keys) { rule in
                controller.upsertRule(rule)
            }
        }
        .sheet(isPresented: $showEncryptSheet) {
            EncryptSheet { passphrase, saveToKeychain in
                controller.enableEncryption(passphrase: passphrase, saveToKeychain: saveToKeychain)
            }
        }
        .alert("Rename Key", isPresented: Binding(
            get: { renameTarget != nil },
            set: { if !$0 { renameTarget = nil } }
        )) {
            TextField("Comment", text: $renameText)
            Button("Cancel", role: .cancel) { renameTarget = nil }
            Button("Save") {
                if let target = renameTarget {
                    controller.rename(target, to: renameText)
                }
                renameTarget = nil
            }
        }
    }

    private func keyActions(for key: StoredKeyRecord) -> some View {
        Menu {
            Button("Copy Public Key") { controller.copyPublicKey(key) }
            Button("Export Private Key…") { exportTarget = key }
            Button("Rename…") {
                renameText = key.comment
                renameTarget = key
            }
            Button(key.isSynced ? "Stop iCloud Sync" : "Sync to iCloud") {
                controller.toggleSync(key)
            }
            Button("Always Allow This App") { controller.addAlwaysAllowRule(for: key) }
            Button("Add Rule for This Key…") {
                ruleEditor = RuleEditorContext(
                    rule: PolicyRule(name: "Rule for \(key.comment)", keyFingerprint: key.fingerprint, action: .alwaysAllow),
                    isNew: true
                )
            }
            Divider()
            Button("Delete", role: .destructive) { controller.delete(key) }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }
}
