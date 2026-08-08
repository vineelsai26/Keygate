import KeygateCore
import SwiftUI
import VKit

/// The Activity tab: the recent signing-request audit trail.
struct ActivitySection: View {
    @EnvironmentObject var controller: KeygateController

    /// How many recent requests to show before the list is expanded.
    private static let collapsedLimit = 5

    @State private var isExpanded = false

    private var visibleEvents: [AuditEvent] {
        if isExpanded {
            return controller.auditEvents
        }
        return Array(controller.auditEvents.prefix(Self.collapsedLimit))
    }

    private var hasMore: Bool {
        controller.auditEvents.count > Self.collapsedLimit
    }

    var body: some View {
        Card(title: "Recent Requests", systemImage: "list.bullet.rectangle") {
            if controller.auditEvents.isEmpty {
                Text("No signing requests recorded yet.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(visibleEvents.enumerated()), id: \.element.id) { index, event in
                    eventRow(event)
                    if index < visibleEvents.count - 1 || hasMore {
                        Divider()
                    }
                }

                if hasMore {
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            isExpanded.toggle()
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Text(isExpanded
                                 ? "Show fewer"
                                 : "Show all \(controller.auditEvents.count) requests")
                            Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                                .font(.caption2.weight(.semibold))
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    @ViewBuilder
    private func eventRow(_ event: AuditEvent) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(Labels.action(event.decision)).font(.headline)
                Spacer()
                Text(event.timestamp, format: .dateTime.hour().minute().second())
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(detail(for: event))
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    /// Human-readable audit row detail: the resolved calling app, the key by its
    /// comment, and the destination when the request carried one. SSH's agent
    /// protocol does not include the target host, so destination is usually absent.
    private func detail(for event: AuditEvent) -> String {
        var parts = ["app: \(ProcessResolver.activityLabel(event.process))"]
        let keyName = controller.keys.first { $0.fingerprint == event.keyFingerprint }?.comment ?? event.keyFingerprint
        parts.append("key: \(keyName)")
        if let host = event.destination.host {
            parts.append("host: \(event.destination.user.map { "\($0)@\(host)" } ?? host)")
        }
        if event.decision == .deny {
            parts.append(event.reason)
        }
        return parts.joined(separator: " · ")
    }
}
