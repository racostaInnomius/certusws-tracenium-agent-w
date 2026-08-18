import AppKit

final class StatusBarController {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let popover = NSPopover()
    private let reader = StatusSnapshotReader()
    private let contentController = StatusPopoverViewController()
    private var timer: Timer?
    /// CoreLocation can only be reached from this process (signed bundle, user
    /// session) — never from the root daemon. See LocationProvider.
    private let locationProvider = LocationProvider()
    private var lastPresenceState: Bool?
    private var lastConnectivityState: Bool?
    private var lastJobBadgeState: Bool?
    private lazy var statusImage: NSImage? = {
        guard let url = Bundle.main.url(forResource: "Tracenium_tryicon", withExtension: "png"),
              let image = NSImage(contentsOf: url) else {
            return nil
        }
        image.size = NSSize(width: 18, height: 18)
        image.isTemplate = false
        return image
    }()
    /// statusImage with a small dot composited onto the bottom-right
    /// corner — shown in place of the plain icon while a job is
    /// running (see TrayCurrentJob). Built once from statusImage
    /// rather than every refresh() tick; NSImage drawing is cheap but
    /// there's no reason to redo it every 5s when the base icon never
    /// changes at runtime.
    private lazy var statusImageWithJobBadge: NSImage? = {
        guard let base = statusImage else { return nil }
        return StatusBarController.badgedImage(base)
    }()

    func start() {
        popover.behavior = .transient
        popover.contentViewController = contentController
        contentController.onEnableLocation = { [weak self] in
            self?.locationProvider.requestConsentFromUser()
        }
        contentController.onInstallRequested = { packageId in
            CatalogInstallSink.write(packageId: packageId)
        }
        // Forzar el tamaño del popover ANTES del primer show. NSPopover
        // por default se reduce al tamaño intrínseco del contentVC view,
        // y `preferredContentSize` se aplica DESPUÉS del primer render
        // — eso causaba que el primer click mostrara el popover
        // colapsado al ancho del row más estrecho. Setearlo en el
        // popover directamente garantiza el tamaño desde el frame 0.
        popover.contentSize = StatusPopoverViewController.popoverSize

        if let button = statusItem.button {
            // Solo icono, sin texto al lado (requirement: el menubar muestra
            // únicamente el icono Tracenium). Si por alguna razón la imagen
            // no carga, dejamos el button vacío en vez de fallback de texto
            // — eso evita ruido visual permanente; el usuario verá un button
            // tiny y al hacer click le sale el popover normal.
            button.image = statusImage
            button.imagePosition = .imageOnly
            button.title = ""
            button.target = self
            button.action = #selector(togglePopover(_:))
        }

        Logger.shared.info("Status bar controller started")

        refresh()

        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        locationProvider.stop()
        Logger.shared.info("Status bar controller stopped")
    }

    @objc
    private func togglePopover(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            contentController.render(reader.read())
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    private func refresh() {
        let status = reader.read()
        contentController.render(status)

        // Driven straight off the snapshot poll: apply() is idempotent, so an
        // unchanged switch costs nothing and a flipped one takes effect within
        // one poll instead of waiting for a restart.
        locationProvider.apply(enabled: status?.policy.features?.locationTracking ?? false)

        // Surface the manual path exactly while it would help: the automatic
        // prompt is unreliable for a menubar app, so the person needs a way to
        // ask for it themselves.
        contentController.setLocationPromptVisible(locationProvider.needsUserConsent)

        let hasSnapshot = status != nil
        if lastPresenceState != hasSnapshot {
            Logger.shared.info(hasSnapshot ? "Snapshot became available" : "Snapshot unavailable")
            lastPresenceState = hasSnapshot
        }

        guard let button = statusItem.button else { return }
        if let status {
            if lastConnectivityState != status.grpc.connected {
                Logger.shared.info(status.grpc.connected ? "Agent connectivity state changed to online" : "Agent connectivity state changed to offline")
                lastConnectivityState = status.grpc.connected
            }
            // Sin texto en el menubar — solo icono. El detalle online/offline
            // se ve en el popover. Mantenemos toolTip (hover) con info útil.
            let jobRunning = status.jobs.current != nil
            var tooltip = "\(status.hostname.isEmpty ? "Tracenium Agent" : status.hostname) · \(status.agentVersion) · \(status.grpc.connected ? "Online" : "Offline")"
            if let job = status.jobs.current {
                tooltip += " · Running \(job.jobType)"
            }
            button.toolTip = tooltip

            if lastJobBadgeState != jobRunning {
                Logger.shared.info(jobRunning ? "Job badge shown (job in progress)" : "Job badge cleared")
                lastJobBadgeState = jobRunning
            }
            button.image = jobRunning ? (statusImageWithJobBadge ?? statusImage) : statusImage
        } else {
            lastConnectivityState = nil
            lastJobBadgeState = nil
            button.toolTip = "Tracenium Agent · No local status snapshot found"
            button.image = statusImage
        }
    }

    /// Composites a small teal dot onto the bottom-right corner of the
    /// base menu-bar icon — the "badge" shown while a job is running.
    /// A plain dot rather than a count: the agent only ever tracks one
    /// active job at a time (see TrayCurrentJob), so there's nothing
    /// to count.
    private static func badgedImage(_ base: NSImage) -> NSImage {
        let size = base.size
        let badged = NSImage(size: size)
        badged.lockFocus()
        base.draw(in: NSRect(origin: .zero, size: size))

        let diameter = max(6, size.width * 0.4)
        let inset: CGFloat = 0.5
        let badgeRect = NSRect(
            x: size.width - diameter - inset,
            y: inset,
            width: diameter,
            height: diameter
        )
        let path = NSBezierPath(ovalIn: badgeRect)
        // White ring so the dot reads clearly against a light or dark
        // menu bar and against the icon's own artwork.
        NSColor.white.setStroke()
        path.lineWidth = 1.2
        NSColor.systemTeal.setFill()
        path.fill()
        path.stroke()

        badged.unlockFocus()
        badged.isTemplate = false
        return badged
    }
}
