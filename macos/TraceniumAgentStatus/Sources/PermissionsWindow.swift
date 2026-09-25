import AppKit
import CoreLocation

/// Los dos permisos que Tracenium no puede darse a sí mismo, pedidos cuando la
/// persona está delante.
///
/// ── Por qué existe esta ventana ─────────────────────────────────────
///
/// Hasta ahora los dos permisos de macOS se pedían **en el peor momento
/// posible**: la primera vez que alguien los necesitaba. Un operador abría una
/// sesión de pantalla para resolver una incidencia y la sesión moría con
/// `screen_recording_permission_pending` mientras, en el Mac, aparecía un
/// diálogo del sistema sin contexto delante de una persona que no había pedido
/// nada. Lo normal ante eso es decir que no.
///
/// Aquí se piden al terminar la instalación, que es cuando la persona SÍ está
/// esperando pasos de configuración, con una explicación de para qué sirve
/// cada uno y sin que nada dependa de que diga que sí.
///
/// ── Las tres reglas que condicionan el diseño ───────────────────────
///
/// 1. **TCC va por BINARIO, no por producto.** El permiso de Grabación de
///    Pantalla lo tiene que pedir el ejecutable que captura — el helper
///    `Tracenium Screen Helper.app` —, no esta app. Si lo pidiera la bandeja,
///    la persona concedería el permiso de OTRA cosa y la captura seguiría sin
///    poder. Por eso el botón lanza el helper con `--tcc-request` en vez de
///    llamar a `CGRequestScreenCaptureAccess()` aquí.
///
/// 2. **Consultar no registra; pedir sí.** `CGPreflightScreenCaptureAccess`
///    solo mira. Mientras el helper únicamente consultara, su entrada no
///    existía en Ajustes y el permiso era inalcanzable incluso a mano, porque
///    el selector del panel busca aplicaciones. De ahí que el estado se lea
///    con `--tcc-status` (sin efectos) y la concesión vaya por
///    `--tcc-request`.
///
/// 3. **Apple NO deja conceder la Grabación de Pantalla por MDM.** No hay
///    atajo para una flota: alguien tiene que decir que sí en cada Mac. La
///    ubicación sí se puede preautorizar por perfil; esta ventana la detecta
///    ya concedida y no molesta.
///
/// Nada de lo que se pide aquí es obligatorio: el agente inventaría, parchea y
/// cumple sin ninguno de los dos. Se dice en la ventana, porque un permiso
/// arrancado con la impresión de que si no el equipo no funciona no es un
/// permiso, es un peaje.
final class PermissionsWindow: NSObject {

    /// Estado de un permiso, tal y como se pinta.
    enum State { case granted, missing, unknown }

    private let window: NSWindow
    private var pollTimer: Timer?

    private let locationChip = NSTextField(labelWithString: "")
    private let screenChip = NSTextField(labelWithString: "")
    private let locationButton = NSButton()
    private let screenButton = NSButton()
    private let doneButton = NSButton()

    /// Lo llama el botón de ubicación. Lo pone quien monta la ventana, porque
    /// el permiso de ubicación lo pide el `LocationProvider` de la app — que
    /// es, por la regla 1, el binario correcto para ESE permiso.
    var onRequestLocation: (() -> Void)?
    /// Estado actual de la ubicación, consultado sin efectos secundarios.
    var locationState: (() -> State)?

    private static let width: CGFloat = 520

    /// Alto de la banda de marca.
    ///
    /// No es una decisión estética: los botones de la ventana viven en los
    /// ~28 pt superiores (`titlebarHeight`) y, con `fullSizeContentView`, se
    /// pintan sobre nuestro contenido. La banda tiene que ser lo bastante alta
    /// para que el logo y los textos quepan POR DEBAJO de ellos.
    static let headerHeight: CGFloat = 74
    /// Franja de arriba reservada al sistema. Nada nuestro entra aquí.
    static let titlebarReserved: CGFloat = 28
    private static let chrome = NSColor(srgbRed: 0x22/255.0, green: 0x28/255.0, blue: 0x31/255.0, alpha: 1)
    private static let cyan = NSColor(srgbRed: 0x8F/255.0, green: 0xFD/255.0, blue: 0xFF/255.0, alpha: 1)
    private static let teal = NSColor(srgbRed: 0x3C/255.0, green: 0x7C/255.0, blue: 0x7C/255.0, alpha: 1)
    private static let ink = NSColor(srgbRed: 0x1C/255.0, green: 0x20/255.0, blue: 0x27/255.0, alpha: 1)
    private static let inkSoft = NSColor(srgbRed: 0x5C/255.0, green: 0x64/255.0, blue: 0x6E/255.0, alpha: 1)
    private static let good = NSColor(srgbRed: 0x1F/255.0, green: 0x7A/255.0, blue: 0x4D/255.0, alpha: 1)

    override init() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 100),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        super.init()
        build()
    }

    /// Enseña la ventana. No es modal a propósito: la instalación ya terminó y
    /// bloquear el Mac por unos permisos opcionales sería cobrarlos por la
    /// fuerza.
    func present() {
        refresh()
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)

        // El estado cambia FUERA de esta app: la persona puede concederlo en
        // Ajustes, en otra ventana. Sin mirar cada poco, la ventana enseñaría
        // "no concedido" para siempre sobre un permiso que acaban de dar.
        //
        // ⚠️ El sondeo va a 3 s, no a 1,5: cada uno lanza un proceso por
        // LaunchServices, y encadenarlos más rápido de lo que tardan en
        // contestar solo apila helpers.
        Self.probeScreenRecording(request: false) { [weak self] _ in self?.refresh() }
        let t = Timer(timeInterval: 3.0, repeats: true) { [weak self] _ in
            Self.probeScreenRecording(request: false) { _ in self?.refresh() }
        }
        RunLoop.main.add(t, forMode: .common)
        pollTimer = t
    }

    func close() {
        pollTimer?.invalidate()
        pollTimer = nil
        window.orderOut(nil)
    }

    /// Para renderizarla en un test sin abrirla.
    var contentViewForTests: NSView? { window.contentView }

    // MARK: - Estado

    /// Último estado conocido de la Grabación de Pantalla DEL HELPER.
    ///
    /// Se cachea porque averiguarlo ya no es instantáneo: hay que lanzar el
    /// helper por LaunchServices y esperar su respuesta en un fichero. Ver
    /// `probeScreenRecording`.
    private static var lastKnownScreenState: State = .unknown

    static func screenRecordingState() -> State { lastKnownScreenState }

    /// Pregunta —o pide— el permiso, con la atribución correcta.
    ///
    /// ── 🔴 Por qué no se puede lanzar el helper y leer su stdout ────────
    ///
    /// TCC no atribuye el permiso al binario que corre, sino a su
    /// **responsible process**. Un helper lanzado con `Process()` desde esta
    /// app tiene a esta app como responsable, así que:
    ///
    ///   * `--tcc-request` registraba **Tracenium Agent Status** en Ajustes ›
    ///     Grabación de pantalla, no «Tracenium Screen Helper». Visto en un Mac
    ///     real el 25-sep-2026, con las DOS entradas en la lista.
    ///   * `--tcc-status` devolvía el permiso de la app de estado, así que un
    ///     helper que YA tenía el permiso concedido se pintaba «Not granted» —
    ///     y pulsar «Allow…» pedía el permiso equivocado, otra vez.
    ///
    /// Lanzarlo por LaunchServices (`NSWorkspace.openApplication`) lo deja como
    /// su propio responsable, que es como lo lanza el PrivSvc en el camino de
    /// captura de verdad (`launchctl asuser`) — de ahí que la entrada correcta
    /// sí existiera. El precio es que se pierde stdout, y por eso el helper
    /// aprendió `--out`.
    static func probeScreenRecording(request: Bool,
                                     completion: @escaping (State) -> Void) {
        guard let app = helperAppURL() else {
            lastKnownScreenState = .unknown
            completion(.unknown)
            return
        }
        let out = NSTemporaryDirectory() + "tracenium-tcc-\(UUID().uuidString).json"
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.arguments = [request ? "--tcc-request" : "--tcc-status", "--out", out]
        cfg.activates = request          // el diálogo del sistema necesita foco
        cfg.createsNewApplicationInstance = true   // el helper es de un solo uso
        cfg.hides = !request

        NSWorkspace.shared.openApplication(at: app, configuration: cfg) { _, error in
            if let error {
                Logger.shared.warn("No se pudo lanzar el helper de pantalla: \(error)")
                DispatchQueue.main.async { completion(Self.lastKnownScreenState) }
                return
            }
            // El helper es one-shot y escribe al salir. Se sondea un rato
            // corto; si no aparece, se conserva lo último que se supo en vez de
            // pintar «no concedido» sobre un permiso que quizá esté.
            DispatchQueue.global(qos: .utility).async {
                var state: State? = nil
                for _ in 0..<30 {   // ~3 s
                    if let data = FileManager.default.contents(atPath: out),
                       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let granted = json["screenRecording"] as? Bool {
                        state = granted ? .granted : .missing
                        break
                    }
                    Thread.sleep(forTimeInterval: 0.1)
                }
                try? FileManager.default.removeItem(atPath: out)
                DispatchQueue.main.async {
                    if let state { Self.lastKnownScreenState = state }
                    completion(Self.lastKnownScreenState)
                }
            }
        }
    }

    /// El BUNDLE del helper, que es lo que LaunchServices sabe abrir.
    static func helperAppURL() -> URL? {
        guard let exe = helperURL() else { return nil }
        // …/Tracenium Screen Helper.app/Contents/MacOS/tracenium-screencap
        let app = exe.deletingLastPathComponent()   // MacOS
            .deletingLastPathComponent()            // Contents
            .deletingLastPathComponent()            // .app
        return app.pathExtension == "app" ? app : nil
    }

    /// Dónde vive el helper de captura.
    ///
    /// ⚠️ El paquete lo instala bajo `PrivSvc/macos/`, no bajo `PrivSvc/`:
    /// `build-macos-pkg.sh` lo monta en `$BUILD_DIR/PrivSvc/macos/Tracenium
    /// Screen Helper.app` y el PrivSvc lo resuelve como hermano de su propio
    /// `dist/`, que vive en esa misma carpeta. La primera versión de esta
    /// ventana escribió la ruta un nivel más arriba, así que en un Mac
    /// instalado el fichero no existía, el estado caía a `.unknown` y el botón
    /// "Allow…" salía DESACTIVADO: el permiso quedaba inalcanzable justo desde
    /// la ventana que existe para concederlo.
    ///
    /// Por eso los candidatos van en una lista y no en un literal: la ruta
    /// vieja se queda como reserva para un Mac que aún tenga el paquete
    /// anterior, igual que hace `privsvc/macos/src/screen-capture.ts`.
    static let helperCandidates = [
        "/Library/Application Support/Tracenium/PrivSvc/macos/"
            + "Tracenium Screen Helper.app/Contents/MacOS/tracenium-screencap",
        "/Library/Application Support/Tracenium/PrivSvc/"
            + "Tracenium Screen Helper.app/Contents/MacOS/tracenium-screencap",
    ]

    /// `nil` cuando el .app se ejecuta suelto (desarrollo).
    private static func helperURL() -> URL? {
        if let override = ProcessInfo.processInfo.environment["TRACENIUM_SCREENCAP_HELPER"],
           !override.trimmingCharacters(in: .whitespaces).isEmpty {
            return URL(fileURLWithPath: override.trimmingCharacters(in: .whitespaces))
        }
        for path in helperCandidates where FileManager.default.isExecutableFile(atPath: path) {
            return URL(fileURLWithPath: path)
        }
        return nil
    }

    // ⚠️ Aquí había un `run()` que lanzaba el helper con `Process()` y leía su
    // stdout. Se ha ido, y no debe volver: un helper lanzado así tiene a esta
    // app como responsible process, y TCC le cuelga a ELLA el permiso de
    // pantalla. Fue exactamente el fallo del 25-sep. Todo lo que hable con el
    // helper para asuntos de permisos pasa por `probeScreenRecording`.

    private func refresh() {
        let loc = locationState?() ?? .unknown
        let screen = Self.screenRecordingState()

        apply(loc, to: locationChip, button: locationButton)
        apply(screen, to: screenChip, button: screenButton)

        doneButton.title = (loc == .granted && screen == .granted) ? "Done" : "Not now"
    }

    private func apply(_ state: State, to chip: NSTextField, button: NSButton) {
        switch state {
        case .granted:
            chip.stringValue = "Granted"
            chip.textColor = Self.good
            button.isEnabled = false
            button.title = "Granted"
        case .missing:
            chip.stringValue = "Not granted"
            chip.textColor = Self.inkSoft
            button.isEnabled = true
            button.title = "Allow…"
        case .unknown:
            // ⚠️ "No lo sé" NO se pinta como "no concedido". Pasa cuando el
            // helper no está instalado (desarrollo), y decir que falta un
            // permiso que quizá esté mandaría a la persona a buscar algo que
            // no tiene que arreglar.
            chip.stringValue = "Unknown"
            chip.textColor = Self.inkSoft
            button.isEnabled = false
            button.title = "Allow…"
        }
    }

    // MARK: - Acciones

    @objc private func locationTapped() {
        onRequestLocation?()
        // El diálogo de CoreLocation puede no salir si el sistema ya decidió
        // antes; el panel de Ajustes es la salida que siempre funciona.
        openSettings("com.apple.preference.security?Privacy_LocationServices")
    }

    @objc private func screenTapped() {
        // Pedir DE VERDAD: es lo único que registra la entrada en Ajustes. Y
        // por LaunchServices, para que la entrada que se registre sea la del
        // HELPER y no la de esta app (ver probeScreenRecording).
        Self.probeScreenRecording(request: true) { [weak self] _ in self?.refresh() }
        openSettings("com.apple.preference.security?Privacy_ScreenCapture")
    }

    private func openSettings(_ anchor: String) {
        if let url = URL(string: "x-apple.systempreferences:\(anchor)") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc private func doneTapped() { close() }

    // MARK: - Construcción

    private func build() {
        window.title = "Tracenium"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.backgroundColor = .white

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 0
        root.translatesAutoresizingMaskIntoConstraints = false

        root.addArrangedSubview(header())
        root.addArrangedSubview(intro())
        root.addArrangedSubview(row(
            title: "Location",
            why: "Puts this Mac on the map if it is ever lost or stolen. Nothing is tracked while it sits on your desk.",
            chip: locationChip, button: locationButton, action: #selector(locationTapped)
        ))
        root.addArrangedSubview(row(
            title: "Screen sharing",
            why: "Lets IT see this screen when you ask for help. You are asked every single time, and a banner stays on screen while anyone is looking.",
            chip: screenChip, button: screenButton, action: #selector(screenTapped)
        ))
        root.addArrangedSubview(footer())

        let content = NSView()
        content.wantsLayer = true
        content.layer?.backgroundColor = NSColor.white.cgColor
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            content.widthAnchor.constraint(equalToConstant: Self.width),
        ])
        window.contentView = content
        // Pintar el estado ya al montar: una ventana que aparece con los
        // indicadores en blanco y se rellena medio segundo después parece
        // rota justo en el momento en que se está pidiendo confianza.
        refresh()
        window.layoutIfNeeded()
        window.setContentSize(content.fittingSize)
    }

    private func header() -> NSView {
        let bar = NSView()
        bar.wantsLayer = true
        bar.layer?.backgroundColor = Self.chrome.cgColor
        bar.translatesAutoresizingMaskIntoConstraints = false

        let logo = NSImageView()
        logo.imageScaling = .scaleProportionallyUpOrDown
        logo.image = Bundle.main.url(forResource: "tracenium_logo_color", withExtension: "png")
            .flatMap { NSImage(contentsOf: $0) }
        logo.translatesAutoresizingMaskIntoConstraints = false

        let name = NSTextField(labelWithString: "Tracenium")
        name.font = .systemFont(ofSize: 13, weight: .bold)
        name.textColor = NSColor(srgbRed: 0xF2/255.0, green: 0xF4/255.0, blue: 0xF7/255.0, alpha: 1)
        name.translatesAutoresizingMaskIntoConstraints = false

        let slogan = NSTextField(labelWithString: "")
        slogan.attributedStringValue = ConsentWindow.sloganAttributed()
        slogan.translatesAutoresizingMaskIntoConstraints = false

        bar.addSubview(logo); bar.addSubview(name); bar.addSubview(slogan)
        NSLayoutConstraint.activate([
            bar.heightAnchor.constraint(equalToConstant: Self.headerHeight),
            logo.leadingAnchor.constraint(equalTo: bar.leadingAnchor, constant: 18),
            // ⚠️ Anclado ABAJO, no al centro. Esta ventana es `.titled` y
            // `.fullSizeContentView`, así que los tres botones del sistema se
            // dibujan ENCIMA de la banda, en los ~28 pt de arriba. Con la barra
            // de 46 pt y el contenido centrado, el logo caía justo debajo del
            // botón rojo: parecía decoración y era el botón de cerrar. Bajando
            // el bloque por debajo de esa franja, el logo vuelve a ser logo.
            logo.bottomAnchor.constraint(equalTo: bar.bottomAnchor, constant: -13),
            logo.widthAnchor.constraint(equalToConstant: 22),
            logo.heightAnchor.constraint(equalToConstant: 22),
            name.leadingAnchor.constraint(equalTo: logo.trailingAnchor, constant: 10),
            name.centerYAnchor.constraint(equalTo: logo.centerYAnchor),
            slogan.trailingAnchor.constraint(equalTo: bar.trailingAnchor, constant: -18),
            slogan.centerYAnchor.constraint(equalTo: logo.centerYAnchor),
        ])
        return bar
    }

    private func intro() -> NSView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.edgeInsets = NSEdgeInsets(top: 22, left: 24, bottom: 8, right: 24)

        let title = NSTextField(wrappingLabelWithString: "Two permissions macOS only you can grant")
        title.font = .systemFont(ofSize: 17, weight: .bold)
        title.textColor = Self.ink
        title.preferredMaxLayoutWidth = Self.width - 48

        let sub = NSTextField(wrappingLabelWithString:
            "Tracenium already keeps this Mac inventoried, patched and compliant without them. "
            + "These two add what macOS will not let any software switch on by itself — not even your IT team, "
            + "and not through device management. You can change them whenever you want in System Settings.")
        sub.font = .systemFont(ofSize: 12)
        sub.textColor = Self.inkSoft
        sub.preferredMaxLayoutWidth = Self.width - 48

        stack.addArrangedSubview(title)
        stack.addArrangedSubview(sub)
        NSLayoutConstraint.activate([stack.widthAnchor.constraint(equalToConstant: Self.width)])
        return stack
    }

    private func row(title: String, why: String, chip: NSTextField,
                     button: NSButton, action: Selector) -> NSView {
        let box = NSView()
        box.wantsLayer = true
        box.layer?.backgroundColor = NSColor(srgbRed: 0xF5/255.0, green: 0xF7/255.0, blue: 0xF8/255.0, alpha: 1).cgColor
        box.layer?.cornerRadius = 10
        box.layer?.borderWidth = 1
        box.layer?.borderColor = NSColor(srgbRed: 0xE1/255.0, green: 0xE4/255.0, blue: 0xE6/255.0, alpha: 1).cgColor
        box.translatesAutoresizingMaskIntoConstraints = false

        let name = NSTextField(labelWithString: title)
        name.font = .systemFont(ofSize: 14, weight: .semibold)
        name.textColor = Self.ink
        name.translatesAutoresizingMaskIntoConstraints = false

        chip.font = .systemFont(ofSize: 11, weight: .semibold)
        chip.translatesAutoresizingMaskIntoConstraints = false

        let detail = NSTextField(wrappingLabelWithString: why)
        detail.font = .systemFont(ofSize: 12)
        detail.textColor = Self.inkSoft
        detail.preferredMaxLayoutWidth = Self.width - 48 - 24 - 110
        detail.translatesAutoresizingMaskIntoConstraints = false

        button.title = "Allow…"
        button.target = self
        button.action = action
        button.isBordered = false
        button.wantsLayer = true
        button.layer?.backgroundColor = NSColor(srgbRed: 0xEB/255.0, green: 0xF4/255.0, blue: 0xF4/255.0, alpha: 1).cgColor
        button.layer?.cornerRadius = 8
        button.layer?.borderWidth = 1
        button.layer?.borderColor = Self.teal.cgColor
        button.attributedTitle = NSAttributedString(string: "Allow…", attributes: [
            .font: NSFont.systemFont(ofSize: 12, weight: .semibold),
            .foregroundColor: NSColor(srgbRed: 0x2F/255.0, green: 0x60/255.0, blue: 0x60/255.0, alpha: 1),
        ])
        button.translatesAutoresizingMaskIntoConstraints = false

        box.addSubview(name); box.addSubview(chip); box.addSubview(detail); box.addSubview(button)
        NSLayoutConstraint.activate([
            name.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 14),
            name.topAnchor.constraint(equalTo: box.topAnchor, constant: 12),
            chip.leadingAnchor.constraint(equalTo: name.trailingAnchor, constant: 10),
            chip.centerYAnchor.constraint(equalTo: name.centerYAnchor),
            detail.leadingAnchor.constraint(equalTo: name.leadingAnchor),
            detail.topAnchor.constraint(equalTo: name.bottomAnchor, constant: 4),
            detail.trailingAnchor.constraint(lessThanOrEqualTo: button.leadingAnchor, constant: -12),
            detail.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -12),
            button.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -14),
            button.centerYAnchor.constraint(equalTo: box.centerYAnchor),
            button.heightAnchor.constraint(equalToConstant: 30),
            button.widthAnchor.constraint(greaterThanOrEqualToConstant: 92),
        ])

        let wrap = NSStackView()
        wrap.orientation = .vertical
        wrap.alignment = .leading
        wrap.edgeInsets = NSEdgeInsets(top: 6, left: 24, bottom: 6, right: 24)
        wrap.addArrangedSubview(box)
        NSLayoutConstraint.activate([
            wrap.widthAnchor.constraint(equalToConstant: Self.width),
            box.widthAnchor.constraint(equalToConstant: Self.width - 48),
        ])
        return wrap
    }

    private func footer() -> NSView {
        let bar = NSStackView()
        bar.orientation = .horizontal
        bar.alignment = .centerY
        bar.spacing = 10
        bar.edgeInsets = NSEdgeInsets(top: 12, left: 24, bottom: 20, right: 24)

        let note = NSTextField(labelWithString: "Granting these is optional.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = Self.inkSoft

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        doneButton.title = "Not now"
        doneButton.target = self
        doneButton.action = #selector(doneTapped)
        doneButton.isBordered = false
        doneButton.wantsLayer = true
        doneButton.layer?.backgroundColor = NSColor.white.cgColor
        doneButton.layer?.cornerRadius = 8
        doneButton.layer?.borderWidth = 2
        doneButton.layer?.borderColor = Self.ink.cgColor
        doneButton.attributedTitle = NSAttributedString(string: "Not now", attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: Self.ink,
        ])
        doneButton.translatesAutoresizingMaskIntoConstraints = false

        bar.addArrangedSubview(note)
        bar.addArrangedSubview(spacer)
        bar.addArrangedSubview(doneButton)
        NSLayoutConstraint.activate([
            bar.widthAnchor.constraint(equalToConstant: Self.width),
            doneButton.heightAnchor.constraint(equalToConstant: 34),
            doneButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96),
        ])
        return bar
    }
}
