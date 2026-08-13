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
    private lazy var statusImage: NSImage? = {
        guard let url = Bundle.main.url(forResource: "Tracenium_tryicon", withExtension: "png"),
              let image = NSImage(contentsOf: url) else {
            return nil
        }
        image.size = NSSize(width: 18, height: 18)
        image.isTemplate = false
        return image
    }()

    func start() {
        popover.behavior = .transient
        popover.contentViewController = contentController
        contentController.onEnableLocation = { [weak self] in
            self?.locationProvider.requestConsentFromUser()
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
            button.toolTip = "\(status.hostname.isEmpty ? "Tracenium Agent" : status.hostname) · \(status.agentVersion) · \(status.grpc.connected ? "Online" : "Offline")"
        } else {
            lastConnectivityState = nil
            button.toolTip = "Tracenium Agent · No local status snapshot found"
        }
    }
}
