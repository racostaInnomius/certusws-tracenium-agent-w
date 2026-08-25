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
    /// Eslogan de producto. NO lleva estado: hostname, versión y último
    /// refresco están todos en las pestañas de detalle —Device Info y Agent
    /// Info— así que repetirlos aquí gastaba la única línea de la cabecera en
    /// datos duplicados. El estado vivo que sí importa de un vistazo es la
    /// pastilla ONLINE/OFFLINE, que está a la derecha.
    private let subtitleLabel = NSTextField(labelWithString: "")
    private let badgeLabel = NSTextField(labelWithString: "UNKNOWN")
    /// ⚠️ El fondo y el radio viven AQUI, no en badgeLabel.
    ///
    /// Un NSTextField dibuja su texto arriba cuando el frame es mas alto que la
    /// linea, asi que con una altura fija de 22 y fuente de 11 el texto quedaba
    /// pegado al borde superior de la pastilla. `alignment = .center` solo
    /// centra en horizontal; no existe equivalente vertical en NSTextField.
    /// Con un contenedor, la etiqueta se centra por constraints en los dos ejes.
    private let badgeContainer = NSView()
    /// Logo a color, a la izquierda del titulo. Ver applyHeaderLogo().
    private let logoView = NSImageView()
    private var logoWidthConstraint: NSLayoutConstraint?
    private var titleLeadingConstraint: NSLayoutConstraint?

    // Tab strip — Device Info (support widget) | Agent Info (estado clásico) | Activity (active job + Operations) | Catalog (self-service installs)
    //
    // "Catalog" not "Software Catalog" in the strip itself — four
    // segments plus the Copy button is already tight at 480pt; the
    // section header inside the tab spells the name out in full.
    private let tabControl = NSSegmentedControl(labels: ["Device Info", "Agent Info", "Activity", "Catalog"], trackingMode: .selectOne, target: nil, action: nil)
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

    /// Set by StatusBarController. Fires when the user clicks Install
    /// on a catalog row — writes the request file the daemon polls for
    /// (see CatalogInstallSink).
    var onInstallRequested: ((String) -> Void)?

    // Body — un scrollview por tab; se alterna con isHidden.
    private let agentScroll = NSScrollView()
    private let deviceScroll = NSScrollView()
    private let jobScroll = NSScrollView()
    private let catalogScroll = NSScrollView()
    private let grid = NSGridView()          // Agent Info (grid clásico)
    private let deviceGrid = NSGridView()    // Device Info
    private let jobGrid = NSGridView()       // Active Job
    private let catalogGrid = NSGridView()   // Software Catalog (self-service)
    private var valueCells: [String: NSTextField] = [:]
    private var deviceCells: [String: NSTextField] = [:]
    private var jobCells: [String: NSTextField] = [:]
    // Indeterminate — the agent has no step/percentage signal to report
    // for a running job (see TrayCurrentJob), so this communicates
    // "something is happening" rather than fabricating a completion %.
    private let jobProgress = NSProgressIndicator()

    // Catalog tab state. Rebuilt on every render() — item counts are
    // small (a handful of admin-opted-in packages), so a full
    // clear-and-rebuild of catalogGrid's rows is simpler than diffing
    // and cheap enough at this scale.
    private var lastCatalogItems: [TrayCatalogItem] = []
    // packageId -> the moment its Install button was clicked. Drives an
    // optimistic "Installing…" state until either jobs.current confirms
    // it started or the grace window lapses (covers a SelfInstallAck
    // rejection, which never sets jobs.current at all).
    private var pendingInstallClicks: [String: Date] = [:]
    private static let installRequestGraceSeconds: TimeInterval = 20

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
        subtitleLabel.attributedStringValue = Self.sloganAttributed()
        subtitleLabel.lineBreakMode = .byTruncatingTail
        subtitleLabel.maximumNumberOfLines = 1
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false

        badgeLabel.font = NSFont.systemFont(ofSize: 11, weight: .bold)
        badgeLabel.textColor = .white
        badgeLabel.alignment = .center
        badgeLabel.translatesAutoresizingMaskIntoConstraints = false

        badgeContainer.wantsLayer = true
        badgeContainer.layer?.cornerRadius = 4
        badgeContainer.layer?.masksToBounds = true
        // Neutro de arranque: el color real lo fija el refresh de estado, pero
        // hasta que llega el primer snapshot la pastilla se dibujaba SIN fondo
        // y "UNKNOWN" flotaba suelto sobre la banda. Con esto siempre es una
        // pastilla; lo unico que cambia es su color.
        badgeContainer.layer?.backgroundColor = NSColor(calibratedWhite: 0.45, alpha: 0.55).cgColor
        badgeContainer.translatesAutoresizingMaskIntoConstraints = false
        badgeContainer.addSubview(badgeLabel)

        // Logo a color de marca. El header es una banda oscura, asi que el
        // metalico con cianes contrasta bien sin necesidad de recuadro ni de
        // una version alterna del asset.
        //
        // `.scaleProportionallyUpOrDown` importa: el PNG viene a 256 y sin ella
        // NSImageView lo pintaria a tamaño nativo, desbordando la banda.
        logoView.translatesAutoresizingMaskIntoConstraints = false

        // Se guarda para poder colapsarla: ver applyHeaderLogo(). La altura
        // NO es una constante — se deriva de title+subtitle (ver activate()
        // abajo) para que el logo quede exactamente tan alto como las dos
        // líneas de texto, en vez de un valor fijo que coincidía con ellas
        // solo por casualidad.
        let logoWidth = logoView.widthAnchor.constraint(equalToConstant: 0)
        let titleLeading = titleLabel.leadingAnchor.constraint(equalTo: logoView.trailingAnchor, constant: 0)
        logoWidthConstraint = logoWidth
        titleLeadingConstraint = titleLeading

        headerView.addSubview(logoView)
        headerView.addSubview(titleLabel)
        headerView.addSubview(subtitleLabel)
        headerView.addSubview(badgeContainer)

        NSLayoutConstraint.activate([
            // Logo a la izquierda. Top/bottom pinned al bloque title+subtitle
            // en vez de una altura fija centrada en el header — así el logo
            // mide exactamente lo que miden las dos líneas de texto, sin
            // importar el font metrics exacto de cada una.
            logoView.leadingAnchor.constraint(equalTo: headerView.leadingAnchor, constant: 16),
            logoView.topAnchor.constraint(equalTo: titleLabel.topAnchor),
            logoView.bottomAnchor.constraint(equalTo: subtitleLabel.bottomAnchor),
            logoWidth,

            // Title arriba, a la derecha del logo
            titleLeading,
            titleLabel.topAnchor.constraint(equalTo: headerView.topAnchor, constant: 14),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: badgeContainer.leadingAnchor, constant: -12),

            // Subtitle debajo del title
            subtitleLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 2),
            subtitleLabel.trailingAnchor.constraint(lessThanOrEqualTo: badgeContainer.leadingAnchor, constant: -12),

            // Pastilla centrada vertical, pegada a la derecha. El ancho ya no
            // es un piso fijo de 70 (que sobraba de sobra para "ONLINE") sino
            // uno por debajo de lo que "OFFLINE" necesita, así el padding de
            // la etiqueta es quien realmente decide el ancho de cada estado.
            badgeContainer.trailingAnchor.constraint(equalTo: headerView.trailingAnchor, constant: -16),
            badgeContainer.centerYAnchor.constraint(equalTo: headerView.centerYAnchor),
            badgeContainer.widthAnchor.constraint(greaterThanOrEqualToConstant: 52),
            badgeContainer.heightAnchor.constraint(equalToConstant: 22),

            // Texto centrado en AMBOS ejes dentro de la pastilla
            badgeLabel.centerXAnchor.constraint(equalTo: badgeContainer.centerXAnchor),
            badgeLabel.centerYAnchor.constraint(equalTo: badgeContainer.centerYAnchor),
            badgeLabel.leadingAnchor.constraint(greaterThanOrEqualTo: badgeContainer.leadingAnchor, constant: 6),
            badgeLabel.trailingAnchor.constraint(lessThanOrEqualTo: badgeContainer.trailingAnchor, constant: -6)
        ])

        view.addSubview(headerView)

        applyHeaderLogo(Bundle.main.url(forResource: "tracenium_logo_color", withExtension: "png")
            .flatMap { NSImage(contentsOf: $0) })
    }

    /// Coloca —o retira— el logo del header ajustando su hueco.
    ///
    /// Sin imagen el ancho colapsa a 0 y el titulo se pega al borde, en vez de
    /// dejar 34pt vacios. Un asset que no se copia al bundle es un fallo de
    /// empaquetado SILENCIOSO —no revienta en runtime— y asi el header se ve
    /// intencionado en lugar de roto.
    ///
    /// Es `internal` a proposito: el snapshot de tests corre fuera de la .app,
    /// donde `Bundle.main` es el runner y no lleva recursos, asi que necesita
    /// poder inyectarlo para que la imagen refleje lo que vera el usuario.
    func applyHeaderLogo(_ image: NSImage?) {
        logoView.image = image
        logoView.imageScaling = .scaleProportionallyUpOrDown
        // Height is no longer set here — it's derived from the
        // titleLabel.top/subtitleLabel.bottom pin (see configureHeader),
        // so it always matches the two text lines exactly.
        logoWidthConstraint?.constant = image == nil ? 0 : 34
        titleLeadingConstraint?.constant = image == nil ? 0 : 10
        headerView.needsLayout = true
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

        // .mini, not .small — .small's rounded bezel still carries enough
        // padding to read as noticeably bigger than the Windows tray's
        // native "Copy all" button (a plain AutoSize WinForms Button).
        // .mini is the closest native macOS equivalent to that compact
        // footprint; the font size is Apple's own HIG-prescribed size for
        // that control size rather than a guessed constant.
        copyButton.bezelStyle = .rounded
        copyButton.controlSize = .mini
        copyButton.font = NSFont.systemFont(ofSize: NSFont.systemFontSize(for: .mini))
        copyButton.target = self
        copyButton.action = #selector(copyAllPressed(_:))
        copyButton.translatesAutoresizingMaskIntoConstraints = false

        // Same size as copyButton — they share the tab strip, so a
        // mismatched size between the two would look worse than either
        // alone.
        locationButton.bezelStyle = .rounded
        locationButton.controlSize = .mini
        locationButton.font = NSFont.systemFont(ofSize: NSFont.systemFontSize(for: .mini))
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
        configureScroll(catalogScroll, in: bodyContainer, grid: catalogGrid)

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

        // ── Activity: current job + Operations (last job, update/patch
        // status — moved here from Agent Info so everything about "what
        // the agent is doing" lives in one place; mirrors the Windows
        // tray's Activity tab) ──
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

        addSection(jobGrid, "Operations")
        addRow(jobGrid, into: &jobCells, "Last job", key: "lastJob")
        addRow(jobGrid, into: &jobCells, "Update status", key: "updateStatus")
        addRow(jobGrid, into: &jobCells, "Last update check", key: "lastUpdateCheck")
        addRow(jobGrid, into: &jobCells, "Last update complete", key: "lastUpdateComplete")
        addRow(jobGrid, into: &jobCells, "Patch status", key: "patchStatus")
        addRow(jobGrid, into: &jobCells, "Patch last scan", key: "patchLastScan")
        addRow(jobGrid, into: &jobCells, "Patch error", key: "patchError")

        // ── Software Catalog (self-service) ──
        // Static intro row; the actual package rows are rebuilt on
        // every render() in renderCatalog() since the list is dynamic.
        addSection(catalogGrid, "Software Catalog")
        let catalogIntro = NSTextField(labelWithString:
            "Software your admin has made available to install yourself, no ticket needed.")
        catalogIntro.font = NSFont.systemFont(ofSize: 10.5)
        catalogIntro.textColor = NSColor.tertiaryLabelColor
        catalogIntro.lineBreakMode = .byWordWrapping
        catalogIntro.maximumNumberOfLines = 2
        catalogIntro.preferredMaxLayoutWidth = 400
        let catalogIntroRow = catalogGrid.addRow(with: [catalogIntro, NSGridCell.emptyContentView])
        catalogIntroRow.mergeCells(in: NSRange(location: 0, length: 2))
        catalogIntroRow.bottomPadding = 4

        for g in [grid, deviceGrid, jobGrid] {
            if g.numberOfColumns >= 1 {
                g.column(at: 0).xPlacement = .leading
                g.column(at: 0).width = 140
            }
            if g.numberOfColumns >= 2 {
                g.column(at: 1).xPlacement = .leading
            }
        }

        // catalogGrid's columns hold item text + an Install button, not
        // the label/value pairing the loop above assumes — sized on its
        // own instead.
        if catalogGrid.numberOfColumns >= 1 {
            catalogGrid.column(at: 0).xPlacement = .leading
        }
        if catalogGrid.numberOfColumns >= 2 {
            catalogGrid.column(at: 1).xPlacement = .trailing
            catalogGrid.column(at: 1).width = 90
        }

        deviceScroll.isHidden = false
        agentScroll.isHidden = true
        jobScroll.isHidden = true
        catalogScroll.isHidden = true
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
        catalogScroll.isHidden = sender.selectedSegment != 3
    }

    /// Teal de marca para los titulos de seccion, adaptado a la apariencia.
    ///
    /// Antes era `NSColor.controlAccentColor`, que no solo es el azul de Apple:
    /// **cambia si el usuario elige otro color de acento** en Ajustes. Los
    /// titulos de una ventana de marca no deberian depender de eso.
    ///
    /// Es dinamico porque NINGUN teal unico sirve en las dos apariencias. Ratios
    /// de contraste medidos contra los fondos nominales del material .popover:
    ///
    ///     color      claro   oscuro
    ///     #5A9F9F     2.82    4.71   <- el de marca: flojo sobre claro
    ///     #3C7C7C     4.45    2.98   <- bueno sobre claro, flojo sobre oscuro
    ///
    /// Asi que cada apariencia usa el que le toca: el de marca en oscuro, y una
    /// version oscurecida —mismo tono— en claro. Los dos quedan por encima de
    /// 3.0, el umbral de WCAG para texto grande en negrita, y el de claro llega
    /// a 4.5, el de texto normal.
    ///
    /// Nota: `.popover` es translucido, asi que el fondo real depende de lo que
    /// haya detras. Los numeros son sobre el fondo nominal — sirven para elegir,
    /// no como garantia de cumplimiento.
    static let brandSectionColor = NSColor(name: "TraceniumBrandSection") { appearance in
        let dark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        return dark
            ? NSColor(calibratedRed: 90/255.0,  green: 159/255.0, blue: 159/255.0, alpha: 1.0)
            : NSColor(calibratedRed: 60/255.0,  green: 124/255.0, blue: 124/255.0, alpha: 1.0)
    }

    private func addSection(_ targetGrid: NSGridView, _ title: String) {
        let label = NSTextField(labelWithString: title)
        label.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        label.textColor = Self.brandSectionColor
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
        renderCatalog(status)
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
            setJob("lastJob", "—")
            setJob("updateStatus", "—")
            setJob("lastUpdateCheck", "—")
            setJob("lastUpdateComplete", "—")
            setJob("patchStatus", "—")
            setJob("patchLastScan", "—")
            setJob("patchError", "—")
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
        setJob("lastJob", formatJob(status.jobs))
        setJob("updateStatus", formatUpdate(status.update))
        setJob("lastUpdateCheck", format(status.update.lastCheckedAtUtc))
        setJob("lastUpdateComplete", format(status.update.lastCompletedAtUtc))
        setJob("patchStatus", formatPatch(status.patch))
        setJob("patchLastScan", format(status.patch.lastScanAtUtc))
        setJob("patchError", (status.patch.lastError?.isEmpty == false) ? status.patch.lastError! : "—")
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
            tabControl.setLabel("Activity", forSegment: 2)
            return
        }

        setJob("jobActiveStatus", "Running")
        setJob("jobActiveType", job.jobType.isEmpty ? "—" : job.jobType)
        setJob("jobActiveId", job.jobId.isEmpty ? "—" : job.jobId)
        setJob("jobActiveStarted", format(job.startedAtUtc))
        setJob("jobActiveElapsed", JobElapsedFormatter.format(startedAtUtc: job.startedAtUtc))
        jobProgress.startAnimation(nil)
        jobCells["jobActiveNote"]?.isHidden = false
        tabControl.setLabel("Activity ●", forSegment: 2)
    }

    private func setJob(_ key: String, _ value: String) {
        jobCells[key]?.stringValue = value
    }

    // MARK: - Software Catalog tab (self-service)

    /// Rebuilds the catalog rows from scratch on every render() — the
    /// list only ever holds a handful of admin-opted-in packages, so a
    /// full clear beats hand-diffing NSGridView rows.
    private func renderCatalog(_ status: TrayStatus?) {
        let items = status?.catalog?.items ?? []
        lastCatalogItems = items

        // render() fires every 5s from StatusBarController.start(), starting
        // BEFORE the user ever opens the popover for the first time — AppKit
        // doesn't call loadView()/configureBody() until the view is actually
        // needed. Every other tab tolerates that because it only writes into
        // a dictionary of already-instantiated fields (a no-op miss while
        // the dictionary is still empty). This tab is the one that mutates
        // catalogGrid's row STRUCTURE directly, so running it pre-load would
        // build up rows with no floor to trim back to — then configureBody()
        // appends the real title/intro rows AFTER that pile once the view
        // finally loads, corrupting the tab for the rest of the process's
        // life. Skip the grid mutation entirely until there's a grid to
        // mutate; installButtonPressed can't fire before then anyway since
        // there's no button yet to click.
        guard isViewLoaded else { return }

        // Drop any optimistic "Installing…" state whose grace window
        // has lapsed — covers a SelfInstallRequest that got rejected
        // (no RunJob ever follows, so jobs.current would otherwise
        // never clear it) as well as one that silently never arrived.
        let now = Date()
        pendingInstallClicks = pendingInstallClicks.filter {
            now.timeIntervalSince($0.value) < Self.installRequestGraceSeconds
        }

        while catalogGrid.numberOfRows > 2 {
            // Rows 0-1 are the static section title + intro line added
            // in configureBody — leave those, clear everything rebuilt
            // per-render below them.
            catalogGrid.removeRow(at: 2)
        }

        if items.isEmpty {
            // Deliberately NOT merged — NSGridView refuses to removeRow(at:)
            // a row containing a merged cell (NSGridView.m:865: "contains a
            // merged cell and cannot be removed"), which crashed the app on
            // the very next 5s render tick after this row appeared. Column 1
            // just stays blank instead; visually near-identical since it's
            // only 90pt wide anyway.
            let emptyField = NSTextField(labelWithString: "Nothing available right now.")
            emptyField.font = NSFont.systemFont(ofSize: 12)
            emptyField.textColor = NSColor.secondaryLabelColor
            let row = catalogGrid.addRow(with: [emptyField, NSGridCell.emptyContentView])
            row.topPadding = 6
            return
        }

        // Any job running — self-install or otherwise — blocks new
        // Installs. PrivSvc runs one privileged operation at a time, so
        // a second click before the first finishes could only fail;
        // better to make that visible than let the user click into it.
        let jobRunning = status?.jobs.current != nil

        for (index, item) in items.enumerated() {
            // A thin separator between packages (not before the first
            // one) — NSGridView has no per-row background API to fake a
            // "card" with, so a divider is what actually groups one
            // package's rows visually apart from the next's within the
            // existing flat, non-merged-cell structure (see the isEmpty
            // branch above for why cells here stay unmerged).
            if index > 0 {
                // NOT merged — same constraint as everywhere else in this
                // loop (a merged cell can't be removeRow(at:)'d on the
                // next render tick without crashing). Column 1 stays
                // blank, so the line spans column 0's width rather than
                // the full row; a shorter divider beats a crash.
                let divider = NSBox()
                divider.boxType = .separator
                let dividerRow = catalogGrid.addRow(with: [divider, NSGridCell.emptyContentView])
                dividerRow.topPadding = 10
                dividerRow.bottomPadding = 10
            }

            // Version only when it's a real value — the catalog sometimes
            // ships the literal string "unknown" for packages with no
            // version metadata, which used to render right in the bold
            // title line ("Winzip unknown").
            let hasRealVersion = !item.version.isEmpty && item.version.caseInsensitiveCompare("unknown") != .orderedSame
            let vendorSuffix = (item.vendor?.isEmpty == false) ? "  ·  \(item.vendor!)" : ""
            let versionSuffix = hasRealVersion ? " \(item.version)" : ""
            let nameField = NSTextField(labelWithString: "\(item.name)\(versionSuffix)\(vendorSuffix)")
            nameField.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
            nameField.lineBreakMode = .byTruncatingTail
            nameField.maximumNumberOfLines = 1

            let button = NSButton(title: "Install", target: self, action: #selector(installButtonPressed(_:)))
            button.tag = index
            button.bezelStyle = .rounded
            button.controlSize = .small

            let isPending = pendingInstallClicks[item.packageId] != nil
            button.title = isPending ? "Installing…" : "Install"
            button.isEnabled = !isPending && !jobRunning

            let nameRow = catalogGrid.addRow(with: [nameField, button])
            nameRow.topPadding = index == 0 ? 6 : 0

            if let description = item.description, !description.isEmpty {
                let detailField = NSTextField(labelWithString: description)
                detailField.font = NSFont.systemFont(ofSize: 10.5)
                detailField.textColor = NSColor.secondaryLabelColor
                detailField.lineBreakMode = .byWordWrapping
                detailField.maximumNumberOfLines = 2
                // Narrower than before (320) since this cell no longer spans
                // column 1's ~90pt — deliberately NOT merged, see the
                // isEmpty branch above for why (removeRow(at:) crashes on a
                // merged row; this row gets rebuilt on every 5s tick).
                detailField.preferredMaxLayoutWidth = 300
                catalogGrid.addRow(with: [detailField, NSGridCell.emptyContentView])
            }

            // Its own line, not buried in the description — a restart
            // requirement is important enough to read at a glance, not
            // parse out of a joined "·"-separated string.
            if item.requiresReboot == true {
                let restartField = NSTextField(labelWithString: "Requires a restart")
                restartField.font = NSFont.systemFont(ofSize: 10.5, weight: .semibold)
                restartField.textColor = Self.catalogWarningText
                let restartRow = catalogGrid.addRow(with: [restartField, NSGridCell.emptyContentView])
                restartRow.topPadding = 2
            }
        }
    }

    /// "Requires a restart" text color — same amber family as the
    /// Windows tray's warning chip, adapted per appearance the same way
    /// brandSectionColor is.
    static let catalogWarningText = NSColor(name: "TraceniumCatalogWarning") { appearance in
        let dark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        return dark
            ? NSColor(calibratedRed: 255/255.0, green: 197/255.0, blue: 92/255.0, alpha: 1.0)
            : NSColor(calibratedRed: 139/255.0, green: 100/255.0, blue: 4/255.0, alpha: 1.0)
    }

    @objc private func installButtonPressed(_ sender: NSButton) {
        guard sender.tag >= 0, sender.tag < lastCatalogItems.count else { return }
        let item = lastCatalogItems[sender.tag]
        pendingInstallClicks[item.packageId] = Date()
        onInstallRequested?(item.packageId)
        // Optimistic — reflect "Installing…" immediately rather than
        // waiting for the next poll tick to re-render.
        renderCatalog(lastStatus)
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
        badgeContainer.layer?.backgroundColor = online
            ? NSColor.systemGreen.cgColor
            : NSColor.systemRed.cgColor

        // El subtitulo ya no se toca aqui: es el eslogan, fijo. hostname,
        // version y ultimo refresco siguen estando —y con mas detalle— en las
        // pestañas Device Info y Agent Info.
        _ = (hostname, version, updatedAt)
    }

    /// El eslogan con el "&" en el cian de marca.
    ///
    /// Se arma como NSAttributedString y no como dos etiquetas para que el
    /// truncado por ancho siga funcionando como en una sola linea: con dos
    /// campos, un popover estrecho partiria la frase por un sitio arbitrario.
    static func sloganAttributed() -> NSAttributedString {
        let font = NSFont.systemFont(ofSize: 11, weight: .regular)
        let base = NSColor(calibratedWhite: 0.86, alpha: 1.0)
        // #8FFDFF — el cian de la paleta, el mismo acento del logo del header.
        let accent = NSColor(calibratedRed: 143/255.0, green: 253/255.0, blue: 255/255.0, alpha: 1.0)

        let s = NSMutableAttributedString()
        s.append(NSAttributedString(string: "Endpoint Intelligence ",
                                    attributes: [.font: font, .foregroundColor: base]))
        s.append(NSAttributedString(string: "&",
                                    attributes: [.font: NSFont.systemFont(ofSize: 11, weight: .semibold),
                                                 .foregroundColor: accent]))
        s.append(NSAttributedString(string: " Compliance Platform",
                                    attributes: [.font: font, .foregroundColor: base]))
        return s
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
