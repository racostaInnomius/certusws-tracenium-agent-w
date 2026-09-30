import AppKit

/// Recordarle a la persona que instale una actualización de macOS antes de una
/// fecha: el presentador de la acción para el usuario `os.update` (ADR-0036
/// D1; nació como job `os_update_nudge`, 29-sep).
///
/// ── Por qué existe ──────────────────────────────────────────────────
///
/// En Apple silicon el agente NO puede instalar una actualización del sistema:
/// `softwareupdate --install` pide la contraseña de un propietario del volumen
/// aunque corra como root (job e4689371, 28-sep: una hora colgado esperándola).
/// Sin MDM la única forma es que la persona la instale desde Ajustes, así que
/// esto se lo pide — y se lo vuelve a pedir, cada vez más a menudo, hasta que
/// lo haga. El agente retira la acción cuando el escaneo ya no la lista.
///
/// ── El ritmo: el de TODAS las acciones para el usuario ─────────────
///
///   más de 3 días para la fecha  → una vez al día
///   últimos 3 días               → cada 4 horas
///   vencida                      → cada hora
///   sin fecha                    → una vez al día
///
/// El servidor sólo fija la fecha, nunca el intervalo: ningún operador puede
/// convertir la bandeja en una alarma. La hora del último aviso vive en
/// UserDefaults de ESTA sesión: es lo que vio esta persona, no algo que el
/// agente pueda saber. Un reinicio de la bandeja no la vuelve a enseñar al
/// instante.
///
/// No es modal ni se puede silenciar para siempre: «Remind me later» sólo la
/// cierra hasta el siguiente turno.
enum UserActionCadence {
    static let day: TimeInterval = 24 * 3600

    static func interval(deadline: Date?, now: Date) -> TimeInterval {
        guard let deadline else { return day }
        let remaining = deadline.timeIntervalSince(now)
        if remaining <= 0 { return 3600 }
        if remaining <= 3 * day { return 4 * 3600 }
        return day
    }

    static func isDue(lastShown: Date?, deadline: Date?, now: Date) -> Bool {
        guard let lastShown else { return true }
        return now.timeIntervalSince(lastShown) >= interval(deadline: deadline, now: now)
    }
}

/// El texto que ve la persona. Aparte para poder probarlo sin ventana.
enum OsUpdateReminderText {
    static func title(_ request: TrayOsUpdateRequest, now: Date) -> String {
        let when = dayString(request.deadlineUtc)
        return request.deadlineUtc <= now
            ? "\(request.title) was due on \(when)"
            : "Please install \(request.title) by \(when)"
    }

    static func body(_ request: TrayOsUpdateRequest, now: Date) -> String {
        var lines = [
            "Your IT team needs this Mac updated. The update asks for your password, so only you can install it.",
            "Open Software Update, choose Update Now and follow the steps. Save your work first: the Mac restarts to finish.",
        ]
        if request.deadlineUtc <= now {
            lines.insert("The deadline has passed. Please install it as soon as you can.", at: 0)
        }
        if request.pendingCount > 1 {
            lines.append("There are \(request.pendingCount) updates waiting; Software Update lists them all.")
        }
        return lines.joined(separator: "\n\n")
    }

    static func dayString(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = .current
        f.setLocalizedDateFormatFromTemplate("EEE MMM d, j:mm")
        return f.string(from: date)
    }
}

final class OsUpdateReminder: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private var shownLabel: String?
    /// Interno (no privado) para que los tests puedan simular una ventana
    /// enseñada sin crear un NSWindow.
    var shownActionIds: [String] = []
    private let defaults: UserDefaults
    private let sink: (_ actionIds: [String], _ event: UserActionEventSink.Event) -> Void
    private let clock: () -> Date

    init(defaults: UserDefaults = .standard,
         sink: @escaping (_ actionIds: [String], _ event: UserActionEventSink.Event) -> Void = UserActionEventSink.record,
         clock: @escaping () -> Date = Date.init) {
        self.defaults = defaults
        self.sink = sink
        self.clock = clock
        super.init()
    }

    /// Cerrar con la X cuenta como «más tarde» (y se informa como `dismissed`).
    /// Sin esto `window` seguiría puesta y el recordatorio no volvería a salir
    /// nunca. Los cierres programáticos quitan antes el delegado: no pasan por aquí.
    func windowWillClose(_ notification: Notification) {
        sink(shownActionIds, .dismissed)
        restartCadence()
        window = nil
        shownLabel = nil
        shownActionIds = []
    }

    /// El siguiente aviso cuenta desde que la persona RESPONDIÓ, no desde que
    /// se le enseñó. Medido 30-sep en JPR-MacBookPro: la ventana de las 06:43
    /// se quedó abierta hasta las 12:42 (persona fuera); «Remind me later» a
    /// las 12:42:23 y a los 3 s volvió a salir, porque desde las 06:43 ya
    /// habían pasado más de las 4 h del intervalo. «Más tarde» tiene que ser
    /// más tarde.
    private func restartCadence() {
        guard let lead = shownActionIds.first else { return }
        defaults.set(clock(), forKey: Self.key(lead))
    }

    /// La marca del último aviso va por la acción más urgente: una petición
    /// nueva (otra fecha, otro actionId) empieza su propio ritmo.
    private static func key(_ actionId: String) -> String { "userAction.lastShown.\(actionId)" }

    /// Idempotente: se llama en cada refresco de la bandeja con TODAS las
    /// acciones; esta ventana se ocupa de las `os.update`.
    func handle(_ actions: [TrayUserAction], now: Date = Date()) {
        guard let request = TrayOsUpdateRequest.from(actions, now: now), let lead = request.actionIds.first else {
            // Instalada, cancelada o caducada: si la ventana sigue abierta ya no tiene razón de ser.
            close()
            return
        }
        if window != nil { return }
        let last = defaults.object(forKey: Self.key(lead)) as? Date
        guard UserActionCadence.isDue(lastShown: last, deadline: request.deadlineUtc, now: now) else { return }
        defaults.set(now, forKey: Self.key(lead))
        Logger.shared.info("Showing macOS update reminder for \(request.label) (deadline \(request.deadlineUtc), \(request.pendingCount) pending)")
        shownActionIds = request.actionIds
        sink(request.actionIds, .shown)
        show(request, now: now)
    }

    private func close() {
        let w = window
        window = nil
        shownLabel = nil
        shownActionIds = []
        w?.delegate = nil
        w?.orderOut(nil)
    }

    // MARK: - Ventana

    private static let width: CGFloat = 440
    private static let chrome = NSColor(srgbRed: 0x22/255.0, green: 0x28/255.0, blue: 0x31/255.0, alpha: 1)
    private static let amber = NSColor(srgbRed: 0xF4/255.0, green: 0xD3/255.0, blue: 0x7D/255.0, alpha: 1)
    private static let teal = NSColor(srgbRed: 0x3C/255.0, green: 0x7C/255.0, blue: 0x7C/255.0, alpha: 1)
    private static let ink = NSColor(srgbRed: 0x1C/255.0, green: 0x20/255.0, blue: 0x27/255.0, alpha: 1)
    private static let inkSoft = NSColor(srgbRed: 0x5C/255.0, green: 0x64/255.0, blue: 0x6E/255.0, alpha: 1)
    private static let hairline = NSColor(srgbRed: 0xD0/255.0, green: 0xD5/255.0, blue: 0xDC/255.0, alpha: 1)
    /// Alto de la banda de marca. La ventana dibuja su contenido bajo la barra
    /// de título (`fullSizeContentView`), así que el botón de cerrar cae
    /// ENCIMA de la banda: con 42 pt tapaba «Tracenium» (prueba en el Mac del
    /// piloto, 29-sep). Con 64 la marca va en la mitad baja, libre.
    static let headerHeight: CGFloat = 64

    private func show(_ request: TrayOsUpdateRequest, now: Date) {
        let w = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 100),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        w.titleVisibility = .hidden
        w.titlebarAppearsTransparent = true
        w.isMovableByWindowBackground = true
        w.standardWindowButton(.miniaturizeButton)?.isHidden = true
        w.standardWindowButton(.zoomButton)?.isHidden = true
        w.appearance = NSAppearance(named: .aqua)
        w.backgroundColor = .white
        // Encima de las ventanas normales, por debajo de los diálogos del sistema.
        w.level = .floating
        w.isReleasedWhenClosed = false
        w.delegate = self
        w.contentView = Self.content(request, now: now, target: self)
        w.layoutIfNeeded()
        if let content = w.contentView { w.setContentSize(content.fittingSize) }
        w.center()
        window = w
        shownLabel = request.label
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
    }

    /// El contenido, aparte para poder renderizarlo en un test.
    static func content(_ request: TrayOsUpdateRequest, now: Date, target: AnyObject?) -> NSView {
        let overdue = request.deadlineUtc <= now

        let header = NSView()
        header.wantsLayer = true
        header.layer?.backgroundColor = chrome.cgColor
        header.translatesAutoresizingMaskIntoConstraints = false
        // El logo de marca delante del nombre, como en el aviso de consentimiento.
        let logo = NSImageView()
        logo.imageScaling = .scaleProportionallyUpOrDown
        logo.image = Bundle.main.url(forResource: "tracenium_logo_color", withExtension: "png")
            .flatMap { NSImage(contentsOf: $0) }
        logo.setAccessibilityIdentifier("os-update-brand-logo")
        logo.translatesAutoresizingMaskIntoConstraints = false
        let brand = NSTextField(labelWithString: "Tracenium")
        brand.font = .systemFont(ofSize: 13, weight: .bold)
        brand.textColor = NSColor(srgbRed: 0xF2/255.0, green: 0xF4/255.0, blue: 0xF7/255.0, alpha: 1)
        brand.translatesAutoresizingMaskIntoConstraints = false
        let slogan = NSTextField(labelWithString: "")
        slogan.attributedStringValue = ConsentWindow.sloganAttributed()
        slogan.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(logo)
        header.addSubview(brand)
        header.addSubview(slogan)
        var headerConstraints = [
            header.heightAnchor.constraint(equalToConstant: headerHeight),
            logo.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 18),
            logo.centerYAnchor.constraint(equalTo: brand.centerYAnchor),
            logo.widthAnchor.constraint(equalToConstant: 22),
            logo.heightAnchor.constraint(equalToConstant: 22),
            brand.leadingAnchor.constraint(equalTo: logo.trailingAnchor, constant: 10),
            brand.bottomAnchor.constraint(equalTo: header.bottomAnchor, constant: -14),
            slogan.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -18),
            slogan.firstBaselineAnchor.constraint(equalTo: brand.firstBaselineAnchor),
        ]
        if overdue {
            let rule = NSView()
            rule.wantsLayer = true
            rule.layer?.backgroundColor = amber.cgColor
            rule.translatesAutoresizingMaskIntoConstraints = false
            header.addSubview(rule)
            headerConstraints += [
                rule.leadingAnchor.constraint(equalTo: header.leadingAnchor),
                rule.trailingAnchor.constraint(equalTo: header.trailingAnchor),
                rule.bottomAnchor.constraint(equalTo: header.bottomAnchor),
                rule.heightAnchor.constraint(equalToConstant: 2),
            ]
        }
        NSLayoutConstraint.activate(headerConstraints)

        let title = NSTextField(wrappingLabelWithString: OsUpdateReminderText.title(request, now: now))
        title.font = .systemFont(ofSize: 15, weight: .bold)
        title.textColor = ink
        title.setAccessibilityIdentifier("osUpdateReminder.title")
        let body = NSTextField(wrappingLabelWithString: OsUpdateReminderText.body(request, now: now))
        body.font = .systemFont(ofSize: 12)
        body.textColor = inkSoft
        body.setAccessibilityIdentifier("osUpdateReminder.body")

        // Con la forma de la marca, no el azul del sistema: el botón por
        // defecto de macOS toma el color de acento del usuario y rompía el
        // aspecto de Tracenium. Mismo patrón que ConsentWindow.pill.
        let open = pill("Open Software Update", fill: teal, text: .white, border: teal,
                        target: target, action: #selector(OsUpdateReminder.openTapped))
        open.keyEquivalent = "\r"
        let later = pill("Remind me later", fill: .white, text: ink, border: hairline,
                         target: target, action: #selector(OsUpdateReminder.laterTapped))
        later.keyEquivalent = "\u{1b}"
        let buttons = NSStackView(views: [NSView(), later, open])
        buttons.orientation = .horizontal
        buttons.spacing = 8

        let inner = NSStackView(views: [title, body, buttons])
        inner.orientation = .vertical
        inner.alignment = .leading
        inner.spacing = 12
        // Aire entre el texto y los botones: pegados parecían parte del párrafo.
        inner.setCustomSpacing(24, after: body)
        inner.edgeInsets = NSEdgeInsets(top: 18, left: 20, bottom: 20, right: 20)
        inner.translatesAutoresizingMaskIntoConstraints = false

        let root = NSView()
        root.wantsLayer = true
        root.layer?.backgroundColor = NSColor.white.cgColor
        root.addSubview(header)
        root.addSubview(inner)
        NSLayoutConstraint.activate([
            root.widthAnchor.constraint(equalToConstant: width),
            header.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            header.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            header.topAnchor.constraint(equalTo: root.topAnchor),
            inner.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            inner.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            inner.topAnchor.constraint(equalTo: header.bottomAnchor),
            inner.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            buttons.widthAnchor.constraint(equalTo: inner.widthAnchor, constant: -40),
            title.widthAnchor.constraint(equalTo: inner.widthAnchor, constant: -40),
            body.widthAnchor.constraint(equalTo: inner.widthAnchor, constant: -40),
        ])
        return root
    }

    /// Un botón con la forma de la marca: píldora, sin bezel de sistema.
    static func pill(_ title: String, fill: NSColor, text: NSColor, border: NSColor,
                     target: AnyObject?, action: Selector) -> NSButton {
        let b = NSButton(title: title, target: target, action: action)
        b.isBordered = false
        b.wantsLayer = true
        b.layer?.backgroundColor = fill.cgColor
        b.layer?.cornerRadius = 8
        b.layer?.borderWidth = 1
        b.layer?.borderColor = border.cgColor
        b.attributedTitle = NSAttributedString(string: title, attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: text,
        ])
        b.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            b.heightAnchor.constraint(equalToConstant: 32),
            b.widthAnchor.constraint(equalToConstant: ceil(b.attributedTitle.size().width) + 32),
        ])
        return b
    }

    /// Ajustes → General → Actualización de software. El ancla cambió en
    /// Ventura: antes era un panel de Preferencias del Sistema.
    static var softwareUpdateURL: URL? {
        if #available(macOS 13, *) {
            return URL(string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")
        }
        return URL(string: "x-apple.systempreferences:com.apple.preferences.softwareupdate")
    }

    @objc func openTapped() {
        if let url = Self.softwareUpdateURL { NSWorkspace.shared.open(url) }
        Logger.shared.info("macOS update reminder: user opened Software Update (\(shownLabel ?? "?"))")
        // Telemetría: abrir Ajustes no instala nada; el agente cierra la acción
        // cuando el escaneo deja de listarla.
        sink(shownActionIds, .opened)
        restartCadence()
        close()
    }

    @objc func laterTapped() {
        Logger.shared.info("macOS update reminder: user chose later (\(shownLabel ?? "?"))")
        sink(shownActionIds, .snoozed)
        restartCadence()
        close()
    }
}
