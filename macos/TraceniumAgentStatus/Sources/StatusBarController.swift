import AppKit

final class StatusBarController {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let popover = NSPopover()
    private let reader = StatusSnapshotReader()
    private let contentController = StatusPopoverViewController()
    private var timer: Timer?
    /// Indicador de sesión de control remoto (ADR-0012). Vive fuera del
    /// popover a propósito: el popover se cierra al hacer clic fuera, y esto
    /// tiene que verse SIN que la persona vaya a buscarlo.
    private let remoteBanner = RemoteSessionBanner()
    private var snapshotWatcher: SnapshotChangeWatcher?
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
        // ⚠️ TEMPLATE, no la imagen tal cual. El PNG es un glifo BLANCO puro
        // (255,255,255 con la forma en el canal alpha), asi que dibujado literal
        // se ve bien solo sobre barras oscuras. En un Mac con barra clara —o con
        // el resto de iconos en negro— el nuestro quedaba como el unico blanco,
        // practicamente invisible.
        //
        // Con isTemplate el sistema ignora el color y usa SOLO el alpha,
        // pintando el glifo del color que corresponda a la apariencia de la
        // barra en ese momento (negro en clara, blanco en oscura) y ademas
        // resaltandolo bien cuando el item esta pulsado. Es el mecanismo que usa
        // el propio macOS para todos sus iconos de menubar.
        image.isTemplate = true
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

        // Refresco inmediato al escribir el snapshot, solo por el indicador de
        // sesión remota. Ver SnapshotChangeWatcher.
        let watcher = SnapshotChangeWatcher { [weak self] in
            self?.refresh()
        }
        watcher.start(watching: reader.snapshotPath)
        snapshotWatcher = watcher
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        snapshotWatcher?.stop()
        snapshotWatcher = nil
        // Retirar la banda al parar: dejarla encendida sin nadie que la
        // actualice sería una alarma falsa fija en pantalla.
        remoteBanner.render(nil)
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

        // El indicador NO se gatea por policy, al contrario que el widget de
        // device info. Saber que te están viendo la pantalla no es una función
        // que un tenant pueda apagar: si se pudiera, el primero en apagarla
        // sería quien más motivos tiene para mirar sin que se note. El único
        // interruptor es que haya sesión o no la haya.
        remoteBanner.render(status?.remoteSession)

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
        // ⚠️ El badge se dibuja con un HUECO, no con un anillo blanco.
        //
        // La version anterior era un punto teal con borde blanco, y la imagen
        // salia con isTemplate=false para conservar ese color. Eso deja el icono
        // sin adaptarse justo mientras hay un job — o sea, reintroduciendo por
        // rachas el problema del icono blanco en barras claras.
        //
        // Como una imagen template usa SOLO el alpha, el color se pierde por
        // definicion: un punto relleno pegado al glifo se fundiria con el. La
        // solucion es separarlo con transparencia: se borra un disco un poco
        // mayor (.clear) y dentro se rellena el punto. El resultado lee como
        // badge por su SILUETA, que es lo unico que sobrevive al modo template,
        // y funciona igual en barra clara y oscura.
        //
        // Se pierde el teal. Se gana que el icono nunca sea invisible, que es lo
        // que se reporto desde campo.
        let gap: CGFloat = 1.5
        let clearRect = badgeRect.insetBy(dx: -gap, dy: -gap)
        NSGraphicsContext.current?.compositingOperation = .clear
        NSBezierPath(ovalIn: clearRect).fill()
        NSGraphicsContext.current?.compositingOperation = .sourceOver

        NSColor.black.setFill()   // el color da igual: template solo mira el alpha
        NSBezierPath(ovalIn: badgeRect).fill()

        badged.unlockFocus()
        badged.isTemplate = true
        return badged
    }
}
