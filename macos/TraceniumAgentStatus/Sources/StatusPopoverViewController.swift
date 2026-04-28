import AppKit

/// Popover de status del agente — rewrite limpio con NSGridView.
///
/// Decisiones clave de layout:
///
/// * **Tamaño fijo via popover.contentSize** (en StatusBarController) en
///   vez de preferredContentSize aquí. preferredContentSize se aplica
///   AFTER del primer show del popover, lo que causaba colapso al
///   tamaño intrínseco en el primer render. Setearlo en el popover
///   directamente garantiza el tamaño desde el primer click.
///
/// * **NSGridView para body** en vez de stack-de-stacks. NSGridView
///   maneja automáticamente la alineación de columnas (label/value)
///   sin necesidad de widthAnchor por row. Una sola constraint para
///   las columnas resuelve todo el alineamiento vertical.
///
/// * **NSVisualEffectView material .popover** para el fondo translúcido
///   nativo macOS. Header dark banner se queda encima y da contraste.
///
/// * **Frames + autoresizingMask** para el split header/body en vez de
///   constraints — más simple y directo cuando el padre tiene tamaño
///   fijo conocido.
final class StatusPopoverViewController: NSViewController {
    /// Tamaño del popover. Lee'do desde StatusBarController via
    /// `StatusPopoverViewController.popoverSize`.
    static let popoverSize = NSSize(width: 480, height: 560)
    private static let headerHeight: CGFloat = 72
    private static let bodyPadding: CGFloat = 16

    // Header
    private let headerView = NSView()
    private let titleLabel = NSTextField(labelWithString: "Tracenium Agent")
    private let subtitleLabel = NSTextField(labelWithString: "Waiting for local status snapshot...")
    private let badgeLabel = NSTextField(labelWithString: "UNKNOWN")

    // Body
    private let grid = NSGridView()
    private var valueCells: [String: NSTextField] = [:]

    override func loadView() {
        // Root: NSVisualEffectView para fondo translúcido nativo.
        let root = NSVisualEffectView(frame: NSRect(origin: .zero, size: Self.popoverSize))
        root.material = .popover
        root.blendingMode = .behindWindow
        root.state = .active
        root.autoresizingMask = [.width, .height]
        view = root

        configureHeader()
        configureBody()
    }

    override func viewWillAppear() {
        super.viewWillAppear()
        // Backup: si por alguna razón el popover en StatusBarController
        // no setea contentSize, preferredContentSize aplica acá.
        preferredContentSize = Self.popoverSize
    }

    // MARK: - Header

    private func configureHeader() {
        // Header pinned al top con autoresizing — no auto-layout aquí
        // para mantener el split header/body simple y deterministic.
        headerView.frame = NSRect(
            x: 0,
            y: Self.popoverSize.height - Self.headerHeight,
            width: Self.popoverSize.width,
            height: Self.headerHeight
        )
        headerView.autoresizingMask = [.width, .minYMargin]
        headerView.wantsLayer = true
        // Banner semi-opaco encima del visualEffect — más oscuro que
        // el blur natural pero deja pasar algo del backdrop.
        headerView.layer?.backgroundColor = NSColor(calibratedRed: 0.13, green: 0.16, blue: 0.19, alpha: 0.92).cgColor

        titleLabel.font = NSFont.systemFont(ofSize: 15, weight: .bold)
        titleLabel.textColor = .white
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        subtitleLabel.font = NSFont.systemFont(ofSize: 11, weight: .regular)
        subtitleLabel.textColor = NSColor(calibratedWhite: 0.82, alpha: 1.0)
        subtitleLabel.lineBreakMode = .byTruncatingTail
        subtitleLabel.maximumNumberOfLines = 1
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false

        badgeLabel.font = NSFont.systemFont(ofSize: 11, weight: .bold)
        badgeLabel.textColor = .white
        badgeLabel.alignment = .center
        badgeLabel.wantsLayer = true
        badgeLabel.layer?.cornerRadius = 4
        badgeLabel.layer?.masksToBounds = true
        badgeLabel.translatesAutoresizingMaskIntoConstraints = false

        headerView.addSubview(titleLabel)
        headerView.addSubview(subtitleLabel)
        headerView.addSubview(badgeLabel)

        NSLayoutConstraint.activate([
            // Title arriba-izquierda
            titleLabel.leadingAnchor.constraint(equalTo: headerView.leadingAnchor, constant: 16),
            titleLabel.topAnchor.constraint(equalTo: headerView.topAnchor, constant: 14),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: badgeLabel.leadingAnchor, constant: -12),

            // Subtitle debajo del title
            subtitleLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 2),
            subtitleLabel.trailingAnchor.constraint(lessThanOrEqualTo: badgeLabel.leadingAnchor, constant: -12),

            // Badge centrado vertical, pegado a la derecha
            badgeLabel.trailingAnchor.constraint(equalTo: headerView.trailingAnchor, constant: -16),
            badgeLabel.centerYAnchor.constraint(equalTo: headerView.centerYAnchor),
            badgeLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 70),
            badgeLabel.heightAnchor.constraint(equalToConstant: 22)
        ])

        view.addSubview(headerView)
    }

    // MARK: - Body

    private func configureBody() {
        // Body container: ocupa lo que queda debajo del header.
        let bodyHeight = Self.popoverSize.height - Self.headerHeight
        let bodyContainer = NSView(frame: NSRect(
            x: 0,
            y: 0,
            width: Self.popoverSize.width,
            height: bodyHeight
        ))
        bodyContainer.autoresizingMask = [.width, .height]
        view.addSubview(bodyContainer)

        // ScrollView ocupa todo el body
        let scrollView = NSScrollView(frame: bodyContainer.bounds)
        scrollView.autoresizingMask = [.width, .height]
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.borderType = .noBorder
        bodyContainer.addSubview(scrollView)

        // Grid: 2 columnas (label, value). NSGridView maneja
        // automáticamente el alineamiento de columnas y rows.
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.columnSpacing = 16
        grid.rowSpacing = 6
        grid.rowAlignment = .firstBaseline
        // Columna 0 (labels): trailing align — los valores quedan
        // alineados verticalmente entre rows incluso si los labels
        // varían en ancho. Pero para verse Windows-like dejamos
        // leading.
        if grid.numberOfColumns > 0 {
            grid.column(at: 0).xPlacement = .leading
        }

        // Populate grid
        addSection("Connectivity")
        addRow("Connectivity", key: "connectivity")
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

        // Configurar columnas DESPUÉS de poblar — al momento de crear
        // el grid no había columnas todavía.
        if grid.numberOfColumns >= 1 {
            grid.column(at: 0).xPlacement = .leading
            grid.column(at: 0).width = 140
        }
        if grid.numberOfColumns >= 2 {
            grid.column(at: 1).xPlacement = .leading
        }

        // Document view envuelve el grid con padding
        let documentView = NSView()
        documentView.translatesAutoresizingMaskIntoConstraints = false
        documentView.addSubview(grid)
        NSLayoutConstraint.activate([
            grid.topAnchor.constraint(equalTo: documentView.topAnchor, constant: Self.bodyPadding),
            grid.leadingAnchor.constraint(equalTo: documentView.leadingAnchor, constant: Self.bodyPadding),
            grid.trailingAnchor.constraint(lessThanOrEqualTo: documentView.trailingAnchor, constant: -Self.bodyPadding),
            grid.bottomAnchor.constraint(equalTo: documentView.bottomAnchor, constant: -Self.bodyPadding)
        ])

        scrollView.documentView = documentView
        // Atar el documentView al ancho del clip view del scrollView —
        // sin esto NSScrollView deja que el document tome ancho
        // intrínseco (causa scroll horizontal y colapso visual).
        documentView.widthAnchor.constraint(equalTo: scrollView.contentView.widthAnchor).isActive = true
    }

    private func addSection(_ title: String) {
        let label = NSTextField(labelWithString: title)
        label.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        label.textColor = NSColor.controlAccentColor
        // Section spans both columns
        let row = grid.addRow(with: [label, NSGridCell.emptyContentView])
        row.mergeCells(in: NSRange(location: 0, length: 2))
        row.topPadding = grid.numberOfRows == 1 ? 0 : 8
        row.bottomPadding = 2
    }

    private func addRow(_ title: String, key: String) {
        let labelField = NSTextField(labelWithString: title)
        labelField.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        labelField.textColor = NSColor.secondaryLabelColor

        let valueField = NSTextField(labelWithString: "—")
        valueField.font = NSFont.systemFont(ofSize: 12)
        valueField.textColor = NSColor.labelColor
        valueField.lineBreakMode = .byTruncatingMiddle
        valueField.maximumNumberOfLines = 1
        valueField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        valueCells[key] = valueField

        grid.addRow(with: [labelField, valueField])
    }

    // MARK: - Render

    func render(_ status: TrayStatus?) {
        guard let status else {
            applyHeader(
                online: false,
                hostname: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
                version: nil,
                updatedAt: nil
            )
            set("connectivity", "No local status snapshot found")
            set("lastHeartbeat", "—")
            set("lastConnected", "—")
            set("lastDisconnected", "—")
            set("hostname", Host.current().localizedName ?? ProcessInfo.processInfo.hostName)
            set("tenantId", "—")
            set("deviceId", "—")
            set("agentVersion", "—")
            set("coreVersion", "—")
            set("policyVersion", "—")
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
        set("lastHeartbeat", format(status.grpc.lastHeartbeatAtUtc))
        set("lastConnected", format(status.grpc.lastConnectedAtUtc))
        set("lastDisconnected", format(status.grpc.lastDisconnectedAtUtc))
        set("hostname", resolveHostname(status))
        set("tenantId", status.tenantId.isEmpty ? "—" : status.tenantId)
        set("deviceId", status.deviceId.isEmpty ? "—" : status.deviceId)
        set("agentVersion", status.agentVersion.isEmpty ? "—" : status.agentVersion)
        set("coreVersion", status.coreVersion.isEmpty ? "—" : status.coreVersion)
        set("policyVersion", status.policy.version.isEmpty ? "none" : status.policy.version)
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

    private func applyHeader(online: Bool, hostname: String, version: String?, updatedAt: Date?) {
        badgeLabel.stringValue = online ? "ONLINE" : "OFFLINE"
        badgeLabel.layer?.backgroundColor = online
            ? NSColor.systemGreen.cgColor
            : NSColor.systemRed.cgColor

        let resolvedVersion = (version?.isEmpty == false) ? "v\(version!)" : "unknown version"
        let updated = updatedAt != nil ? "Last refresh \(format(updatedAt))" : "Last refresh unavailable"
        subtitleLabel.stringValue = "\(hostname)  |  \(resolvedVersion)  |  \(updated)"
    }

    private func set(_ key: String, _ value: String) {
        valueCells[key]?.stringValue = value
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
