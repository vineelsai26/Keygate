import KeygateCore
import SwiftUI
import VKit

/// The Policy tab: the ordered rule list with add/edit/delete. Owns the rule
/// editor sheet.
struct PolicySection: View {
    @EnvironmentObject var controller: KeygateController
    @State private var ruleEditor: RuleEditorContext?

    var body: some View {
        Card(title: "Policy", systemImage: "slider.horizontal.3") {
            if controller.rules.isEmpty {
                Text("Unknown apps require Touch ID/password by default. Rules are checked top to bottom; the first match wins.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(controller.rules) { rule in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(rule.name).font(.headline)
                            Text(summary(for: rule))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Menu {
                            Button("Edit…") {
                                ruleEditor = RuleEditorContext(rule: rule, isNew: false)
                            }
                            Divider()
                            Button("Delete", role: .destructive) { controller.deleteRule(rule) }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                        }
                        .menuStyle(.borderlessButton)
                        .fixedSize()
                    }
                    Divider()
                }
            }
            Button {
                ruleEditor = RuleEditorContext(rule: PolicyRule(name: "", action: .alwaysAllow), isNew: true)
            } label: {
                Label("Add Rule…", systemImage: "plus")
            }
        }
        .sheet(item: $ruleEditor) { context in
            RuleEditorSheet(rule: context.rule, isNew: context.isNew, keys: controller.keys) { rule in
                controller.upsertRule(rule)
            }
        }
    }

    /// One-line description of what a rule matches and does, resolving key
    /// fingerprints to their comments where possible.
    private func summary(for rule: PolicyRule) -> String {
        var parts = [Labels.action(rule.action)]
        if rule.action == .allowForDuration, let seconds = rule.durationSeconds {
            parts[0] += " (\(Int(seconds / 60)) min)"
        }
        if let fingerprint = rule.keyFingerprint {
            let name = controller.keys.first { $0.fingerprint == fingerprint }?.comment ?? fingerprint
            parts.append("key: \(name)")
        }
        if let bundle = rule.appBundleIdentifier { parts.append("app: \(bundle)") }
        if let path = rule.executablePath { parts.append("exec: \(path)") }
        if let team = rule.teamIdentifier { parts.append("team: \(team)") }
        if rule.destinationHost != nil || rule.destinationUser != nil || rule.forwardingOnly != nil {
            parts.append("legacy destination constraint (inactive)")
        }
        if parts.count == 1 { parts.append("all requests") }
        return parts.joined(separator: " · ")
    }
}
