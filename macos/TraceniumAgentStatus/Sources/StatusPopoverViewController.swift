import AppKit

final class StatusPopoverViewController: NSViewController {
    private let rootStack = NSStackView()
    private let headerView = NSView()
    private let badgeLabel = NSTextField(labelWithString: "UNKNOWN")
    private let titleLabel = NSTextField(labelWithString: "Tracenium Agent")
    private let subtitleLabel = NSTextField(labelWithString: "Waiting for local status snapshot...")
    private var valueLabels: [String: NSTextField] = [:]

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 620))
        root.wantsLayer = true
        root.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        rootStack.orientation = .vertical
        rootStack.alignment = .leading
        rootStack.spacing = 12
        rootStack.translatesAutoresizingMaskIntoConstraints = false

        configureHeader()
        rootStack.addArrangedSubview(headerView)

        addSection("Connectivity")
        addRow("Connectivity", key: "connectivity")
        addRow("Snapshot updated", key: "snapshotUpdated")
        addRow("Last heartbeat", key: "lastHeartbeat")
        addRow("Last connected", key: "lastConnected")
        addRow("Last disconnected", key: "lastDisconnected")

        addSection("Identity")
        addRow("Hostname", key: "hostname")
        addRow("Tenant ID", key: "tenantId")
        addRow("Device ID", key: "deviceId")
        addRow("Agent version", key: "agentVersion")
        addRow("Core version", key: "coreVersion")

        addSection("Policy")
        addRow("Policy version", key: "policyVersion")
        addRow("Policy hash", key: "policyHash")
        addRow("Plugins", key: "plugins")
        addRow("Modules", key: "modules")

        addSection("Operations")
        addRow("Last job", key: "lastJob")
        addRow("Update status", key: "updateStatus")
        addRow("Last update check", key: "lastUpdateCheck")
        addRow("Last update complete", key: "lastUpdateComplete")
        addRow("Patch status", key: "patchStatus")
        addRow("Patch last scan", key: "patchLastScan")
        addRow("Patch error", key: "patchError")

        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder

        let documentView = NSView()
        documentView.translatesAutoresizingMaskIntoConstraints = false
        documentView.addSubview(rootStack)
        NSLayoutConstraint.activate([
            rootStack.topAnchor.constraint(equalTo: documentView.topAnchor, constant: 16),
            rootStack.leadingAnchor.constraint(equalTo: documentView.leadingAnchor, constant: 16),
            rootStack.trailingAnchor.constraint(equalTo: documentView.trailingAnchor, constant: -16),
            rootStack.bottomAnchor.constraint(equalTo: documentView.bottomAnchor, constant: -16),
            rootStack.widthAnchor.constraint(equalTo: documentView.widthAnchor, constant: -32)
        ])

        scrollView.documentView = documentView
        root.addSubview(scrollView)
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: root.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: root.bottomAnchor)
        ])

        view = root
    }

    func render(_ status: TrayStatus?) {
        guard let status else {
            applyHeader(online: false, hostname: Host.current().localizedName ?? ProcessInfo.processInfo.hostName, version: nil, updatedAt: nil)
            set("connectivity", "No local status snapshot found")
            set("snapshotUpdated", "—")
            set("lastHeartbeat", "—")
            set("lastConnected", "—")
            set("lastDisconnected", "—")
            set("hostname", Host.current().localizedName ?? ProcessInfo.processInfo.hostName)
            set("tenantId", "—")
            set("deviceId", "—")
            set("agentVersion", "—")
            set("coreVersion", "—")
            set("policyVersion", "—")
            set("policyHash", "—")
            set("plugins", "—")
            set("modules", "—")
            set("lastJob", "—")
            set("updateStatus", "—")
            set("lastUpdateCheck", "—")
            set("lastUpdateComplete", "—")
            set("patchStatus", "—")
            set("patchLastScan", "—")
            set("patchError", "—")
            return
        }

        applyHeader(
            online: status.grpc.connected,
            hostname: resolveHostname(status),
            version: status.agentVersion,
            updatedAt: status.updatedAtUtc
        )

        set("connectivity", status.grpc.connected ? "Online" : "Offline")
        set("snapshotUpdated", format(status.updatedAtUtc))
        set("lastHeartbeat", format(status.grpc.lastHeartbeatAtUtc))
        set("lastConnected", format(status.grpc.lastConnectedAtUtc))
        set("lastDisconnected", format(status.grpc.lastDisconnectedAtUtc))
        set("hostname", resolveHostname(status))
        set("tenantId", status.tenantId.isEmpty ? "—" : status.tenantId)
        set("deviceId", status.deviceId.isEmpty ? "—" : status.deviceId)
        set("agentVersion", status.agentVersion.isEmpty ? "—" : status.agentVersion)
        set("coreVersion", status.coreVersion.isEmpty ? "—" : status.coreVersion)
        set("policyVersion", status.policy.version.isEmpty ? "none" : status.policy.version)
        set("policyHash", (status.policy.hash?.isEmpty == false) ? status.policy.hash! : "—")
        set("plugins", status.policy.plugins.isEmpty ? "—" : status.policy.plugins.joined(separator: ", "))
        set("modules", status.policy.modules.isEmpty ? "—" : status.policy.modules.joined(separator: ", "))
        set("lastJob", formatJob(status.jobs))
        set("updateStatus", formatUpdate(status.update))
        set("lastUpdateCheck", format(status.update.lastCheckedAtUtc))
        set("lastUpdateComplete", format(status.update.lastCompletedAtUtc))
        set("patchStatus", formatPatch(status.patch))
        set("patchLastScan", format(status.patch.lastScanAtUtc))
        set("patchError", (status.patch.lastError?.isEmpty == false) ? status.patch.lastError! : "—")
    }

    private func configureHeader() {
        headerView.translatesAutoresizingMaskIntoConstraints = false
        headerView.wantsLayer = true
        headerView.layer?.backgroundColor = NSColor(calibratedRed: 0.13, green: 0.16, blue: 0.19, alpha: 1.0).cgColor
        headerView.layer?.cornerRadius = 10
        headerView.heightAnchor.constraint(equalToConstant: 88).isActive = true

        let titleStack = NSStackView()
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 4
        titleStack.translatesAutoresizingMaskIntoConstraints = false

        titleLabel.font = NSFont.systemFont(ofSize: 16, weight: .bold)
        titleLabel.textColor = .white

        subtitleLabel.font = NSFont.systemFont(ofSize: 11, weight: .regular)
        subtitleLabel.textColor = NSColor(calibratedWhite: 0.82, alpha: 1.0)
        subtitleLabel.maximumNumberOfLines = 2
        subtitleLabel.lineBreakMode = .byWordWrapping

        titleStack.addArrangedSubview(titleLabel)
        titleStack.addArrangedSubview(subtitleLabel)

        badgeLabel.font = NSFont.systemFont(ofSize: 11, weight: .bold)
        badgeLabel.textColor = .white
        badgeLabel.alignment = .center
        badgeLabel.wantsLayer = true
        badgeLabel.layer?.cornerRadius = 6
        badgeLabel.layer?.masksToBounds = true

        headerView.addSubview(titleStack)
        headerView.addSubview(badgeLabel)

        NSLayoutConstraint.activate([
            titleStack.leadingAnchor.constraint(equalTo: headerView.leadingAnchor, constant: 16),
            titleStack.centerYAnchor.constraint(equalTo: headerView.centerYAnchor),
            titleStack.trailingAnchor.constraint(lessThanOrEqualTo: badgeLabel.leadingAnchor, constant: -12),
            badgeLabel.trailingAnchor.constraint(equalTo: headerView.trailingAnchor, constant: -16),
            badgeLabel.centerYAnchor.constraint(equalTo: headerView.centerYAnchor),
            badgeLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 78),
            badgeLabel.heightAnchor.constraint(equalToConstant: 28)
        ])
    }

    private func applyHeader(online: Bool, hostname: String, version: String?, updatedAt: Date?) {
        badgeLabel.stringValue = online ? "ONLINE" : "OFFLINE"
        badgeLabel.layer?.backgroundColor = online
            ? NSColor.systemGreen.cgColor
            : NSColor.systemRed.cgColor

        let resolvedVersion = (version?.isEmpty == false) ? "v\(version!)" : "unknown version"
        let updated = updatedAt != nil ? "Last refresh \(format(updatedAt))" : "Last refresh unavailable"
        subtitleLabel.stringValue = "\(hostname)  |  \(resolvedVersion)  |  \(updated)"
    }

    private func addSection(_ title: String) {
        let label = NSTextField(labelWithString: title)
        label.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        label.textColor = NSColor.controlAccentColor
        stackSeparatorIfNeeded()
        rootStack.addArrangedSubview(label)
    }

    private func addRow(_ title: String, key: String) {
        let row = NSStackView()
        row.orientation = .vertical
        row.alignment = .leading
        row.spacing = 2

        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        titleLabel.textColor = NSColor.secondaryLabelColor

        let valueLabel = NSTextField(labelWithString: "—")
        valueLabel.font = NSFont.systemFont(ofSize: 12)
        valueLabel.lineBreakMode = .byWordWrapping
        valueLabel.maximumNumberOfLines = 4
        valueLabels[key] = valueLabel

        row.addArrangedSubview(titleLabel)
        row.addArrangedSubview(valueLabel)
        rootStack.addArrangedSubview(row)
    }

    private func stackSeparatorIfNeeded() {
        guard !rootStack.arrangedSubviews.isEmpty else { return }
        let separator = NSBox()
        separator.boxType = .separator
        rootStack.addArrangedSubview(separator)
    }

    private func set(_ key: String, _ value: String) {
        valueLabels[key]?.stringValue = value
    }

    private func resolveHostname(_ status: TrayStatus) -> String {
        status.hostname.isEmpty ? (Host.current().localizedName ?? ProcessInfo.processInfo.hostName) : status.hostname
    }

    private func format(_ date: Date?) -> String {
        guard let date else { return "—" }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        formatter.timeZone = .current
        return formatter.string(from: date)
    }

    private func formatJob(_ jobs: TrayJobStatus) -> String {
        guard let type = jobs.lastJobType, !type.isEmpty else { return "—" }
        let status = jobs.lastJobStatus?.isEmpty == false ? jobs.lastJobStatus! : "unknown"
        return "\(type) · \(status) · \(format(jobs.lastJobAtUtc))"
    }

    private func formatUpdate(_ update: TrayUpdateStatus) -> String {
        guard let status = update.status, !status.isEmpty else { return "—" }
        if let error = update.lastError, !error.isEmpty {
            return "\(status) · \(error)"
        }
        return status
    }

    private func formatPatch(_ patch: TrayPatchStatus) -> String {
        guard let status = patch.status, !status.isEmpty else { return "—" }
        if patch.rebootRequired == true {
            return "\(status) · reboot required"
        }
        return status
    }
}
