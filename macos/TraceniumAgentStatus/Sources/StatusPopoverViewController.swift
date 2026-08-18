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
    private static let tabStripHeight: CGFloat = 40
    private static let bodyPadding: CGFloat = 16

    // Header
    private let headerView = NSView()
    private let titleLabel = NSTextField(labelWithString: "Tracenium Agent")
    private let subtitleLabel = NSTextField(labelWithString: "Waiting for local status snapshot...")
    private let badgeLabel = NSTextField(labelWithString: "UNKNOWN")

    // Tab strip — Device Info (support widget) | Agent Info (estado clásico) | Active Job
    private let tabControl = NSSegmentedControl(labels: ["Device Info", "Agent Info", "Active Job"], trackingMode: .selectOne, target: nil, action: nil)
    private let copyButton = NSButton(title: "Copy all", target: nil, action: nil)

    /// Shown only while location is switched on by policy and still ungranted.
    ///
    /// The automatic prompt is unreliable for a menubar app: macOS registers us
    /// as a location client but does not reliably present the alert to a
    /// process that was not already frontmost, and once the client is
    /// registered it may never offer again. A button the person CLICKS sidesteps
    /// that entirely — the app is unambiguously frontmost at that instant,
    /// which is exactly the condition the alert needs.
    private let locationButton = NSButton(title: "Allow location…", target: nil, action: nil)

    /// Set by the controller so the button can reach the provider.
    var onEnableLocation: (() -> Void)?

    // Body — un scrollview por tab; se alterna con isHidden.
    private let agentScroll = NSScrollView()
    private let deviceScroll = NSScrollView()
    private let jobScroll = NSScrollView()
    private let grid = NSGridView()          // Agent Info (grid clásico)
    private let deviceGrid = NSGridView()    // Device Info
    private let jobGrid = NSGridView()       // Active Job
    private var valueCells: [String: NSTextField] = [:]
    private var deviceCells: [String: NSTextField] = [:]
    private var jobCells: [String: NSTextField] = [:]
    // Indeterminate — the agent has no step/percentage signal to report
    // for a running job (see TrayCurrentJob), so this communicates
    // "something is happening" rather than fabricating a completion %.
    private let jobProgress = NSProgressIndicator()

    // Último status renderizado — fuente del Copy all.
    private var lastStatus: TrayStatus?

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
        // Tab strip entre header y body: segmented (izq) + Copy all (der).
        let stripY = Self.popoverSize.height - Self.headerHeight - Self.tabStripHeight
        let strip = NSView(frame: NSRect(
            x: 0,
            y: stripY,
            width: Self.popoverSize.width,
            height: Self.tabStripHeight
        ))
        strip.autoresizingMask = [.width, .minYMargin]

        tabControl.selectedSegment = 0 // Device Info primero — es el caso de soporte
        tabControl.target = self
        tabControl.action = #selector(tabChanged(_:))
        tabControl.translatesAutoresizingMaskIntoConstraints = false

        copyButton.bezelStyle = .rounded
        copyButton.controlSize = .small
        copyButton.font = NSFont.systemFont(ofSize: 11)
        copyButton.target = self
        copyButton.action = #selector(copyAllPressed(_:))
        copyButton.translatesAutoresizingMaskIntoConstraints = false

        locationButton.bezelStyle = .rounded
        locationButton.controlSize = .small
        locationButton.font = NSFont.systemFont(ofSize: 11)
        locationButton.target = self
        locationButton.action = #selector(enableLocationPressed(_:))
        locationButton.translatesAutoresizingMaskIntoConstraints = false
        locationButton.isHidden = true  // only while ungranted — see setLocationPromptVisible

        strip.addSubview(tabControl)
        strip.addSubview(copyButton)
        strip.addSubview(locationButton)
        NSLayoutConstraint.activate([
            tabControl.leadingAnchor.constraint(equalTo: strip.leadingAnchor, constant: Self.bodyPadding),
            tabControl.centerYAnchor.constraint(equalTo: strip.centerYAnchor),
            copyButton.trailingAnchor.constraint(equalTo: strip.trailingAnchor, constant: -Self.bodyPadding),
            copyButton.centerYAnchor.constraint(equalTo: strip.centerYAnchor),
            locationButton.trailingAnchor.constraint(equalTo: copyButton.leadingAnchor, constant: -8),
            locationButton.centerYAnchor.constraint(equalTo: strip.centerYAnchor)
        ])
        view.addSubview(strip)

        // Body container: lo que queda debajo del strip.
        let bodyHeight = Self.popoverSize.height - Self.headerHeight - Self.tabStripHeight
        let bodyContainer = NSView(frame: NSRect(
            x: 0,
            y: 0,
            width: Self.popoverSize.width,
            height: bodyHeight
        ))
        bodyContainer.autoresizingMask = [.width, .height]
        view.addSubview(bodyContainer)

        // Un scrollview por tab, ambos ocupando el body completo;
        // se alterna visibilidad en tabChanged.
        configureScroll(agentScroll, in: bodyContainer, grid: grid)
        configureScroll(deviceScroll, in: bodyContainer, grid: deviceGrid)
        configureScroll(jobScroll, in: bodyContainer, grid: jobGrid)

        // ── Agent Info (grid clásico, intacto) ──
        addSection(grid, "Connectivity")
        addRow(grid, into: &valueCells, "Connectivity", key: "connectivity")
        addRow(grid, into: &valueCells, "Last heartbeat", key: "lastHeartbeat")
        addRow(grid, into: &valueCells, "Last connected", key: "lastConnected")
        addRow(grid, into: &valueCells, "Last disconnected", key: "lastDisconnected")

        addSection(grid, "Identity")
        addRow(grid, into: &valueCells, "Hostname", key: "hostname")
        addRow(grid, into: &valueCells, "Tenant ID", key: "tenantId")
        addRow(grid, into: &valueCells, "Device ID", key: "deviceId")
        addRow(grid, into: &valueCells, "Agent version", key: "agentVersion")
        addRow(grid, into: &valueCells, "Core version", key: "coreVersion")

        addSection(grid, "Policy")
        addRow(grid, into: &valueCells, "Policy version", key: "policyVersion")
        addRow(grid, into: &valueCells, "Plugins", key: "plugins")
        addRow(grid, into: &valueCells, "Modules", key: "modules")

        addSection(grid, "Operations")
        addRow(grid, into: &valueCells, "Last job", key: "lastJob")
        addRow(grid, into: &valueCells, "Update status", key: "updateStatus")
        addRow(grid, into: &valueCells, "Last update check", key: "lastUpdateCheck")
        addRow(grid, into: &valueCells, "Last update complete", key: "lastUpdateComplete")
        addRow(grid, into: &valueCells, "Patch status", key: "patchStatus")
        addRow(grid, into: &valueCells, "Patch last scan", key: "patchLastScan")
        addRow(grid, into: &valueCells, "Patch error", key: "patchError")

        // ── Device Info (widget de soporte) ──
        addSection(deviceGrid, "User & Identity")
        addRow(deviceGrid, into: &deviceCells, "Logged user", key: "devUser")
        addRow(deviceGrid, into: &deviceCells, "Computer name", key: "devComputer")
        addRow(deviceGrid, into: &deviceCells, "Domain", key: "devDomain")

        addSection(deviceGrid, "Network")
        addRow(deviceGrid, into: &deviceCells, "IP address", key: "devIp")
        addRow(deviceGrid, into: &deviceCells, "MAC address", key: "devMac")

        addSection(deviceGrid, "System")
        addRow(deviceGrid, into: &deviceCells, "Operating system", key: "devOs")
        addRow(deviceGrid, into: &deviceCells, "Model", key: "devModel")
        addRow(deviceGrid, into: &deviceCells, "Serial number", key: "devSerial")
        addRow(deviceGrid, into: &deviceCells, "Processor", key: "devCpu")
        addRow(deviceGrid, into: &deviceCells, "Memory", key: "devMemory")
        addRow(deviceGrid, into: &deviceCells, "Screen resolution", key: "devResolution")

        addSection(deviceGrid, "Tracenium")
        addRow(deviceGrid, into: &deviceCells, "Device ID", key: "devDeviceId")

        // ── Active Job ──
        addSection(jobGrid, "Active Job")
        addRow(jobGrid, into: &jobCells, "Status", key: "jobActiveStatus")
        addRow(jobGrid, into: &jobCells, "Job type", key: "jobActiveType")
        addRow(jobGrid, into: &jobCells, "Job ID", key: "jobActiveId")
        addRow(jobGrid, into: &jobCells, "Started at", key: "jobActiveStarted")
        addRow(jobGrid, into: &jobCells, "Elapsed", key: "jobActiveElapsed")

        jobProgress.style = .bar
        jobProgress.isIndeterminate = true
        jobProgress.isDisplayedWhenStopped = false
        jobProgress.translatesAutoresizingMaskIntoConstraints = false
        let progressRow = jobGrid.addRow(with: [jobProgress, NSGridCell.emptyContentView])
        progressRow.mergeCells(in: NSRange(location: 0, length: 2))
        progressRow.topPadding = 4
        jobProgress.widthAnchor.constraint(equalToConstant: 320).isActive = true

        let progressNoteField = NSTextField(labelWithString:
            "The agent doesn't report a completion percentage — this spinner just confirms a job is in flight, and the elapsed time above is live.")
        progressNoteField.font = NSFont.systemFont(ofSize: 10.5)
        progressNoteField.textColor = NSColor.tertiaryLabelColor
        progressNoteField.lineBreakMode = .byWordWrapping
        progressNoteField.maximumNumberOfLines = 3
        progressNoteField.preferredMaxLayoutWidth = 320
        jobCells["jobActiveNote"] = progressNoteField
        let noteRow = jobGrid.addRow(with: [progressNoteField, NSGridCell.emptyContentView])
        noteRow.mergeCells(in: NSRange(location: 0, length: 2))
        noteRow.topPadding = 4

        for g in [grid, deviceGrid, jobGrid] {
            if g.numberOfColumns >= 1 {
                g.column(at: 0).xPlacement = .leading
                g.column(at: 0).width = 140
            }
            if g.numberOfColumns >= 2 {
                g.column(at: 1).xPlacement = .leading
            }
        }

        deviceScroll.isHidden = false
        agentScroll.isHidden = true
        jobScroll.isHidden = true
    }

    /// Monta un scrollview a pantalla completa del body con un grid
    /// adentro (mismo patrón document-view + width-tie del original).
    private func configureScroll(_ scrollView: NSScrollView, in container: NSView, grid: NSGridView) {
        scrollView.frame = container.bounds
        scrollView.autoresizingMask = [.width, .height]
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.borderType = .noBorder
        container.addSubview(scrollView)

        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.columnSpacing = 16
        grid.rowSpacing = 6
        grid.rowAlignment = .firstBaseline

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

    @objc private func tabChanged(_ sender: NSSegmentedControl) {
        deviceScroll.isHidden = sender.selectedSegment != 0
        agentScroll.isHidden = sender.selectedSegment != 1
        jobScroll.isHidden = sender.selectedSegment != 2
    }

    private func addSection(_ targetGrid: NSGridView, _ title: String) {
        let label = NSTextField(labelWithString: title)
        label.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        label.textColor = NSColor.controlAccentColor
        // Section spans both columns
        let row = targetGrid.addRow(with: [label, NSGridCell.emptyContentView])
        row.mergeCells(in: NSRange(location: 0, length: 2))
        row.topPadding = targetGrid.numberOfRows == 1 ? 0 : 8
        row.bottomPadding = 2
    }

    private func addRow(_ targetGrid: NSGridView, into cells: inout [String: NSTextField], _ title: String, key: String) {
        let labelField = NSTextField(labelWithString: title)
        labelField.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        labelField.textColor = NSColor.secondaryLabelColor

        let valueField = NSTextField(labelWithString: "—")
        valueField.font = NSFont.systemFont(ofSize: 12)
        valueField.textColor = NSColor.labelColor
        valueField.lineBreakMode = .byTruncatingMiddle
        valueField.maximumNumberOfLines = 1
        valueField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        // Valores seleccionables: soporte a veces quiere copiar UN campo
        // (ej. solo la serie) en vez del bloque completo.
        valueField.isSelectable = true
        cells[key] = valueField

        targetGrid.addRow(with: [labelField, valueField])
    }

    // MARK: - Render

    /// Show the button only when clicking it would actually achieve something:
    /// policy on, permission not yet granted.
    func setLocationPromptVisible(_ visible: Bool) {
        locationButton.isHidden = !visible
    }

    @objc private func enableLocationPressed(_ sender: Any?) {
        onEnableLocation?()
    }

    func render(_ status: TrayStatus?) {
        lastStatus = status
        renderDeviceInfo(status)
        renderActiveJob(status?.jobs.current)
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

    // MARK: - Device Info tab

    /// Campos que este proceso conoce mejor que el agente-root: usuario
    /// de la sesión y resolución del display principal (en pixels
    /// físicos, no points — soporte espera "3024x1964", no "1512x982").
    private func localLoggedUser() -> String {
        let short = NSUserName()
        let full = NSFullUserName()
        if !full.isEmpty && full != short { return "\(full) (\(short))" }
        return short
    }

    private func localScreenResolution() -> String {
        guard let screen = NSScreen.main else { return "—" }
        let scale = screen.backingScaleFactor
        let w = Int(screen.frame.width * scale)
        let h = Int(screen.frame.height * scale)
        return "\(w) x \(h)"
    }

    private func renderDeviceInfo(_ status: TrayStatus?) {
        let d = status?.device
        setDevice("devUser", localLoggedUser())
        setDevice("devComputer", d?.fqdn ?? d?.hostname ?? resolveLocalHostname(status))
        setDevice("devDomain", d?.domain ?? "—")
        setDevice("devIp", d?.ipv4 ?? d?.ipv6 ?? "—")
        setDevice("devMac", d?.mac ?? "—")
        let osParts = [d?.osName, d?.osVersion].compactMap { $0 }.joined(separator: " ")
        setDevice("devOs", osParts.isEmpty ? "—" : (d?.osBuild.map { "\(osParts) (build \($0))" } ?? osParts))
        let modelParts = [d?.manufacturer, d?.model].compactMap { $0 }.joined(separator: " ")
        setDevice("devModel", modelParts.isEmpty ? "—" : modelParts)
        setDevice("devSerial", d?.serial ?? "—")
        setDevice("devCpu", d?.cpu ?? "—")
        setDevice("devMemory", d?.memoryGb.map { String(format: "%.1f GB", $0) } ?? "—")
        setDevice("devResolution", localScreenResolution())
        setDevice("devDeviceId", (status?.deviceId.isEmpty == false) ? status!.deviceId : "—")
    }

    private func setDevice(_ key: String, _ value: String) {
        deviceCells[key]?.stringValue = value
    }

    // MARK: - Active Job tab

    /// No live progress percentage — see JobElapsedFormatter and the
    /// TrayCurrentJob doc comment for why. Toggles the segmented
    /// control's own label with a bullet so the badge signal is
    /// visible even while the popover is open on a different tab, not
    /// just from the menu-bar icon (see StatusBarController).
    private func renderActiveJob(_ job: TrayCurrentJob?) {
        guard let job else {
            setJob("jobActiveStatus", "Idle — no job currently running")
            setJob("jobActiveType", "—")
            setJob("jobActiveId", "—")
            setJob("jobActiveStarted", "—")
            setJob("jobActiveElapsed", "—")
            jobProgress.stopAnimation(nil)
            jobCells["jobActiveNote"]?.isHidden = true
            tabControl.setLabel("Active Job", forSegment: 2)
            return
        }

        setJob("jobActiveStatus", "Running")
        setJob("jobActiveType", job.jobType.isEmpty ? "—" : job.jobType)
        setJob("jobActiveId", job.jobId.isEmpty ? "—" : job.jobId)
        setJob("jobActiveStarted", format(job.startedAtUtc))
        setJob("jobActiveElapsed", JobElapsedFormatter.format(startedAtUtc: job.startedAtUtc))
        jobProgress.startAnimation(nil)
        jobCells["jobActiveNote"]?.isHidden = false
        tabControl.setLabel("Active Job ●", forSegment: 2)
    }

    private func setJob(_ key: String, _ value: String) {
        jobCells[key]?.stringValue = value
    }

    private func resolveLocalHostname(_ status: TrayStatus?) -> String {
        if let h = status?.hostname, !h.isEmpty { return h }
        return Host.current().localizedName ?? ProcessInfo.processInfo.hostName
    }

    /// Texto plano con todos los campos del Device Info — lo que el
    /// usuario pega en el chat/ticket de soporte.
    private func deviceInfoText() -> String {
        let d = lastStatus?.device
        let osParts = [d?.osName, d?.osVersion].compactMap { $0 }.joined(separator: " ")
        let modelParts = [d?.manufacturer, d?.model].compactMap { $0 }.joined(separator: " ")
        var lines: [String] = []
        lines.append("Logged user: \(localLoggedUser())")
        lines.append("Computer name: \(d?.fqdn ?? d?.hostname ?? resolveLocalHostname(lastStatus))")
        lines.append("Domain: \(d?.domain ?? "-")")
        lines.append("IP address: \(d?.ipv4 ?? d?.ipv6 ?? "-")")
        lines.append("MAC address: \(d?.mac ?? "-")")
        lines.append("Operating system: \(osParts.isEmpty ? "-" : osParts)")
        lines.append("Model: \(modelParts.isEmpty ? "-" : modelParts)")
        lines.append("Serial number: \(d?.serial ?? "-")")
        lines.append("Processor: \(d?.cpu ?? "-")")
        lines.append("Memory: \(d?.memoryGb.map { String(format: "%.1f GB", $0) } ?? "-")")
        lines.append("Screen resolution: \(localScreenResolution())")
        if let id = lastStatus?.deviceId, !id.isEmpty {
            lines.append("Tracenium device ID: \(id)")
        }
        return lines.joined(separator: "\n")
    }

    @objc private func copyAllPressed(_ sender: NSButton) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(deviceInfoText(), forType: .string)
        // Feedback breve en el propio botón — sin popups.
        sender.title = "Copied ✓"
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak sender] in
            sender?.title = "Copy all"
        }
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
