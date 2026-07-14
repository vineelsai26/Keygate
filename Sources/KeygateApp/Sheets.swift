import AppKit
import KeygateCore
import SwiftUI
import UniformTypeIdentifiers
import VKit

struct ImportSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var keyText = ""
    @State private var passphrase = ""
    @State private var isDropTargeted = false
    let onImport: (String, String?) -> Void

    var body: some View {
        SheetScaffold(
            title: "Import Private Key",
            subtitle: "Paste an OpenSSH or PEM private key, choose a file, or drop one here. Enter the passphrase if the key is encrypted.",
            width: 520
        ) {
            TextEditor(text: $keyText)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 170)
                .overlay(RoundedRectangle(cornerRadius: Theme.insetRadius).stroke(isDropTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(Palette.border.opacity(0.6)), lineWidth: isDropTargeted ? 2 : 1))
            SecureField("Passphrase (if encrypted)", text: $passphrase)
                .textFieldStyle(.roundedBorder)
        } actions: {
            Button("Choose File…") { chooseFile() }
            Spacer()
            Button("Cancel") { dismiss() }
            Button("Import") {
                onImport(keyText, passphrase.isEmpty ? nil : passphrase)
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .disabled(keyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            loadDroppedFile(providers)
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose an SSH private key file"
        if panel.runModal() == .OK, let url = panel.url, let contents = try? String(contentsOf: url, encoding: .utf8) {
            keyText = contents
        }
    }

    private func loadDroppedFile(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }) else {
            return false
        }
        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier) { item, _ in
            var url: URL?
            if let data = item as? Data {
                url = URL(dataRepresentation: data, relativeTo: nil)
            } else if let itemURL = item as? URL {
                url = itemURL
            }
            guard let url, let contents = try? String(contentsOf: url, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                keyText = contents
            }
        }
        return true
    }
}

struct ExportSheet: View {
    @Environment(\.dismiss) private var dismiss
    let key: StoredKeyRecord
    /// Performs the gated Keychain read off the main thread; the completion is
    /// called on the main thread with the exported text, or nil on failure/denial.
    let onExport: (KeyExportFormat, String?, @escaping (String?) -> Void) -> Void
    @State private var format: KeyExportFormat = .openssh
    @State private var passphrase = ""
    @State private var confirmPassphrase = ""
    @State private var isExporting = false

    var body: some View {
        SheetScaffold(title: "Export Private Key", width: 460) {
            Text("\(key.comment) — \(key.fingerprint)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Picker("Format", selection: $format) {
                ForEach(availableFormats, id: \.self) { format in
                    Text(format.displayName).tag(format)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if format == .openssh {
                SecureField("Passphrase (optional)", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                SecureField("Confirm passphrase", text: $confirmPassphrase)
                    .textFieldStyle(.roundedBorder)
                    .disabled(passphrase.isEmpty)
            } else {
                Text("\(format.displayName) exports are always unencrypted. Use the OpenSSH format to protect the file with a passphrase.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Label("The exported file contains the unlocked private key. Anyone with the file\(format == .openssh && !passphrase.isEmpty ? " and passphrase" : "") can use it.", systemImage: "exclamationmark.shield")
                .font(.caption)
                .foregroundStyle(.orange)
        } actions: {
            if isExporting {
                ProgressView().controlSize(.small)
                Text("Waiting for authorization…").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Cancel") { dismiss() }
            Button("Copy to Clipboard") {
                export { exported in
                    guard let exported else { return }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(exported, forType: .string)
                    dismiss()
                }
            }
            .disabled(!passphrasesMatch || isExporting)
            Button("Save to File…") { saveToFile() }
                .buttonStyle(.borderedProminent)
                .disabled(!passphrasesMatch || isExporting)
        }
    }

    private var availableFormats: [KeyExportFormat] {
        KeyExportFormat.allCases.filter { $0 != .pkcs1 || key.keyType.isRSA }
    }

    private var passphrasesMatch: Bool {
        format != .openssh || passphrase.isEmpty || passphrase == confirmPassphrase
    }

    private func export(_ completion: @escaping (String?) -> Void) {
        let effective = (format == .openssh && !passphrase.isEmpty) ? passphrase : nil
        isExporting = true
        onExport(format, effective) { exported in
            isExporting = false
            completion(exported)
        }
    }

    private func saveToFile() {
        let panel = NSSavePanel()
        panel.message = "Save the exported private key"
        panel.nameFieldStringValue = suggestedFileName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        export { exported in
            guard let exported else { return }
            do {
                try Data(exported.utf8).write(to: url, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                dismiss()
            } catch {
                // The sheet stays open; nothing sensitive was written on failure.
            }
        }
    }

    private var suggestedFileName: String {
        switch format {
        case .openssh:
            switch key.keyType {
            case .ed25519: return "id_ed25519"
            case .rsa: return "id_rsa"
            case .ecdsaP256, .ecdsaP384, .ecdsaP521: return "id_ecdsa"
            }
        case .pkcs8, .pkcs1:
            return "private-key.pem"
        }
    }
}

struct EncryptSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onEnable: (String, Bool) -> Void
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var saveToKeychain = true

    var body: some View {
        SheetScaffold(
            title: "Encrypt Keys",
            subtitle: "Encrypts every private key on disk with a passphrase. Optionally save it in the Keychain so you can unlock later with Touch ID. There is no recovery if you forget it.",
            width: 420
        ) {
            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
            SecureField("Confirm passphrase", text: $confirm)
                .textFieldStyle(.roundedBorder)
            Toggle("Save passphrase for Touch ID unlock", isOn: $saveToKeychain)
                .help("Stores the passphrase in your login Keychain. Unlock uses Touch ID instead of retyping.")
        } actions: {
            Spacer()
            Button("Cancel") { dismiss() }
            Button("Encrypt") {
                onEnable(passphrase, saveToKeychain)
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .disabled(passphrase.isEmpty || passphrase != confirm)
        }
    }
}

struct UnlockSheet: View {
    @Environment(\.dismiss) private var dismiss
    let canUseTouchID: Bool
    let onUnlock: (String, Bool) -> Void
    let onTouchID: (@escaping (Bool) -> Void) -> Void
    @State private var passphrase = ""
    @State private var saveToKeychain = true
    @State private var isUnlocking = false

    var body: some View {
        SheetScaffold(
            title: "Unlock Keygate",
            subtitle: canUseTouchID
                ? "Unlock with Touch ID, or enter your passphrase."
                : "Enter your passphrase to unlock signing for this session.",
            width: 400
        ) {
            if canUseTouchID {
                Button {
                    isUnlocking = true
                    onTouchID { success in
                        isUnlocking = false
                        if success { dismiss() }
                    }
                } label: {
                    Label(
                        isUnlocking ? "Waiting for Touch ID…" : "Unlock with Touch ID",
                        systemImage: "touchid"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(isUnlocking)

                Text("or enter passphrase")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
            }

            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .onSubmit { submit() }
                .disabled(isUnlocking)

            Toggle("Save passphrase for Touch ID unlock", isOn: $saveToKeychain)
                .disabled(isUnlocking)
                .help("Stores the passphrase in your login Keychain after a successful unlock.")
        } actions: {
            Spacer()
            Button("Cancel") { dismiss() }
                .disabled(isUnlocking)
            Button("Unlock") { submit() }
                .buttonStyle(.borderedProminent)
                .disabled(passphrase.isEmpty || isUnlocking)
        }
        .onAppear {
            // Prefer Touch ID when a passphrase is already saved.
            if canUseTouchID {
                isUnlocking = true
                onTouchID { success in
                    isUnlocking = false
                    if success { dismiss() }
                }
            }
        }
    }

    private func submit() {
        guard !passphrase.isEmpty else { return }
        onUnlock(passphrase, saveToKeychain)
        dismiss()
    }
}

struct RuleEditorContext: Identifiable {
    let rule: PolicyRule
    let isNew: Bool
    var id: UUID { rule.id }
}

struct RuleEditorSheet: View {
    @Environment(\.dismiss) private var dismiss
    let isNew: Bool
    let keys: [StoredKeyRecord]
    let onSave: (PolicyRule) -> Void

    @State private var name: String
    @State private var action: PolicyAction
    @State private var durationMinutes: Int
    @State private var keyFingerprint: String // empty = any key
    @State private var bundleIdentifier: String
    @State private var executablePath: String
    @State private var teamIdentifier: String

    private let ruleID: UUID
    private let createdAt: Date

    init(rule: PolicyRule, isNew: Bool, keys: [StoredKeyRecord], onSave: @escaping (PolicyRule) -> Void) {
        self.isNew = isNew
        self.keys = keys
        self.onSave = onSave
        ruleID = rule.id
        createdAt = rule.createdAt
        _name = State(initialValue: rule.name)
        _action = State(initialValue: rule.action)
        _durationMinutes = State(initialValue: Int((rule.durationSeconds ?? 3600) / 60))
        _keyFingerprint = State(initialValue: rule.keyFingerprint ?? "")
        _bundleIdentifier = State(initialValue: rule.appBundleIdentifier ?? "")
        _executablePath = State(initialValue: rule.executablePath ?? "")
        _teamIdentifier = State(initialValue: rule.teamIdentifier ?? "")
    }

    var body: some View {
        SheetScaffold(
            title: isNew ? "Add Policy Rule" : "Edit Policy Rule",
            subtitle: "Empty conditions match any request. A request must satisfy every condition for the rule to apply; the first matching rule in the list decides.",
            width: 480
        ) {
            Form {
                TextField("Name", text: $name, prompt: Text("e.g. Allow GitHub from Terminal"))
                Picker("Action", selection: $action) {
                    ForEach(PolicyAction.allCases, id: \.self) { action in
                        Text(Labels.action(action)).tag(action)
                    }
                }
                if action == .allowForDuration {
                    Stepper(value: $durationMinutes, in: 1 ... 24 * 60, step: 5) {
                        Text("Duration: \(durationMinutes) min")
                    }
                }

                Picker("Key", selection: $keyFingerprint) {
                    Text("Any key").tag("")
                    ForEach(keys) { key in
                        Text(key.comment).tag(key.fingerprint)
                    }
                }

                LabeledContent("App") {
                    HStack {
                        TextField("Bundle ID", text: $bundleIdentifier, prompt: Text("e.g. com.apple.Terminal"))
                        Button("Choose…") { chooseApp() }
                    }
                }
                TextField("Executable path", text: $executablePath, prompt: Text("e.g. /usr/bin/ssh"))
                TextField("Team ID", text: $teamIdentifier, prompt: Text("10-character developer team ID"))
            }
            .formStyle(.columns)
        } actions: {
            Spacer()
            Button("Cancel") { dismiss() }
            Button(isNew ? "Add Rule" : "Save") {
                onSave(builtRule)
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    private var builtRule: PolicyRule {
        PolicyRule(
            id: ruleID,
            name: name.trimmingCharacters(in: .whitespaces),
            keyFingerprint: keyFingerprint.isEmpty ? nil : keyFingerprint,
            appBundleIdentifier: normalized(bundleIdentifier),
            executablePath: normalized(executablePath),
            teamIdentifier: normalized(teamIdentifier),
            action: action,
            durationSeconds: action == .allowForDuration ? TimeInterval(durationMinutes * 60) : nil,
            createdAt: createdAt
        )
    }

    private func normalized(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func chooseApp() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.applicationBundle]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.message = "Choose the app this rule applies to"
		guard panel.runModal() == .OK,
		      let url = panel.url,
		      let identity = ProcessResolver.validatedApplicationIdentity(at: url),
		      let validatedBundle = identity.bundleIdentifier,
		      let validatedTeam = identity.teamIdentifier else { return }
		bundleIdentifier = validatedBundle
		teamIdentifier = validatedTeam
        if name.trimmingCharacters(in: .whitespaces).isEmpty {
            let appName = url.deletingPathExtension().lastPathComponent
            name = "Rule for \(appName)"
        }
    }
}
