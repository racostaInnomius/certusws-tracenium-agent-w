import AppKit

/// El diálogo de consentimiento de ADR-0012, con la cara de Tracenium.
///
/// ── Por qué NO es un `NSAlert` ──────────────────────────────────────
///
/// Lo era. Un `NSAlert` es la ventana que macOS ya sabe colocar bien en
/// cualquier DPI y cualquier tema, y por eso se eligió: sale por encima de
/// todo sin depender de que la bandeja tenga el foco.
///
/// Lo que se perdía a cambio es lo que este diálogo necesita más que ningún
/// otro: **que se reconozca de un vistazo quién lo muestra**. Un aviso que
/// aparece de la nada diciendo que alguien quiere ver tu pantalla, con el
/// aspecto exacto de cualquier otro cuadro del sistema, es indistinguible de
/// un intento de estafa — y la reacción sana ante eso es pulsar lo que sea
/// para que desaparezca. Nombrar el producto en el texto ayuda; enseñarlo
/// con su cromo y su logo, más.
///
/// Todo lo que el `NSAlert` hacía bien se conserva aquí a propósito:
///
///  * **Denegar es el botón por defecto** (Return) y Escape también deniega.
///    En un diálogo que concede acceso a la pantalla de alguien, la opción de
///    reposo no puede ser la que concede.
///  * **Modal de verdad** (`NSApp.runModal`), no una ventana que se pueda
///    dejar de lado y olvidar.
///  * **El icono del bundle firmado**: el texto lo copia cualquiera, el icono
///    que macOS asocia al bundle no. Es la parte que la persona puede comparar
///    con lo que ve en su barra de menús.
///
/// Y se añade lo que no había: la cuenta atrás. El plazo existía —vencerlo
/// cuenta como negativa— pero no se veía, así que la persona no sabía que
/// estaba decidiendo contra reloj.
final class ConsentWindow {

    private let request: ConsentRequest
    private let control: Bool
    private let window: NSWindow
    private let expiryLabel = NSTextField(labelWithString: "")
    private var timer: Timer?
    private var approved = false

    // Marca. Los mismos valores que la franja y que el header del popover.
    private static let chrome = NSColor(srgbRed: 0x22/255.0, green: 0x28/255.0, blue: 0x31/255.0, alpha: 1)
    private static let chromeControl = NSColor(srgbRed: 0x2A/255.0, green: 0x26/255.0, blue: 0x20/255.0, alpha: 1)
    private static let cyan = NSColor(srgbRed: 0x8F/255.0, green: 0xFD/255.0, blue: 0xFF/255.0, alpha: 1)
    private static let amber = NSColor(srgbRed: 0xF4/255.0, green: 0xD3/255.0, blue: 0x7D/255.0, alpha: 1)
    private static let teal = NSColor(srgbRed: 0x3C/255.0, green: 0x7C/255.0, blue: 0x7C/255.0, alpha: 1)
    private static let ink = NSColor(srgbRed: 0x1C/255.0, green: 0x20/255.0, blue: 0x27/255.0, alpha: 1)
    private static let inkSoft = NSColor(srgbRed: 0x5C/255.0, green: 0x64/255.0, blue: 0x6E/255.0, alpha: 1)

    private static let width: CGFloat = 480

    init(request: ConsentRequest, control: Bool) {
        self.request = request
        self.control = control
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 100),
            styleMask: [.titled, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        build()
    }

    /// Bloquea hasta que la persona decide. `true` = concedió.
    func runModal() -> Bool {
        window.center()
        window.makeKeyAndOrderFront(nil)
        startCountdown()
        NSApp.runModal(for: window)
        timer?.invalidate()
        window.orderOut(nil)
        return approved
    }

    /// El contenido montado, para poder renderizarlo en un test sin abrir la
    /// ventana modal (que en un test colgaría el `runModal`).
    var contentViewForTests: NSView? { window.contentView }

    // MARK: - Construcción

    private func build() {
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.standardWindowButton(.closeButton)?.isHidden = true
        window.standardWindowButton(.miniaturizeButton)?.isHidden = true
        window.standardWindowButton(.zoomButton)?.isHidden = true
        window.backgroundColor = .white
        window.level = .modalPanel

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 0
        root.translatesAutoresizingMaskIntoConstraints = false

        root.addArrangedSubview(header())
        root.addArrangedSubview(body())
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
        window.layoutIfNeeded()
        window.setContentSize(content.fittingSize)
    }

    /// Banda oscura con el logo y el eslogan. Lo PRIMERO que se ve es de
    /// quién viene el aviso.
    private func header() -> NSView {
        let bar = NSView()
        bar.wantsLayer = true
        bar.layer?.backgroundColor = (control ? Self.chromeControl : Self.chrome).cgColor
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
        slogan.attributedStringValue = Self.sloganAttributed()
        slogan.translatesAutoresizingMaskIntoConstraints = false

        bar.addSubview(logo)
        bar.addSubview(name)
        bar.addSubview(slogan)
        NSLayoutConstraint.activate([
            bar.heightAnchor.constraint(equalToConstant: 46),
            logo.leadingAnchor.constraint(equalTo: bar.leadingAnchor, constant: 18),
            logo.centerYAnchor.constraint(equalTo: bar.centerYAnchor),
            logo.widthAnchor.constraint(equalToConstant: 22),
            logo.heightAnchor.constraint(equalToConstant: 22),
            name.leadingAnchor.constraint(equalTo: logo.trailingAnchor, constant: 10),
            name.centerYAnchor.constraint(equalTo: bar.centerYAnchor),
            slogan.trailingAnchor.constraint(equalTo: bar.trailingAnchor, constant: -18),
            slogan.centerYAnchor.constraint(equalTo: bar.centerYAnchor),
            slogan.leadingAnchor.constraint(greaterThanOrEqualTo: name.trailingAnchor, constant: 12),
        ])
        if control {
            let rule = NSView()
            rule.wantsLayer = true
            rule.layer?.backgroundColor = Self.amber.cgColor
            rule.translatesAutoresizingMaskIntoConstraints = false
            bar.addSubview(rule)
            NSLayoutConstraint.activate([
                rule.leadingAnchor.constraint(equalTo: bar.leadingAnchor),
                rule.trailingAnchor.constraint(equalTo: bar.trailingAnchor),
                rule.bottomAnchor.constraint(equalTo: bar.bottomAnchor),
                rule.heightAnchor.constraint(equalToConstant: 2),
            ])
        }
        return bar
    }

    /// El eslogan de producto, con el "&" en el cian de marca.
    ///
    /// Mismo texto y mismo acento que el header del popover de estado: el
    /// diálogo tiene que parecerse a la ventana que la persona ya ha visto en
    /// su barra de menús, porque parecerse a ella ES la prueba.
    static func sloganAttributed() -> NSAttributedString {
        let font = NSFont.systemFont(ofSize: 11, weight: .regular)
        let base = NSColor(calibratedWhite: 0.68, alpha: 1.0)
        let s = NSMutableAttributedString()
        s.append(NSAttributedString(string: "Endpoint Intelligence ",
                                    attributes: [.font: font, .foregroundColor: base]))
        s.append(NSAttributedString(string: "&",
                                    attributes: [.font: NSFont.systemFont(ofSize: 11, weight: .semibold),
                                                 .foregroundColor: cyan]))
        s.append(NSAttributedString(string: " Compliance Platform",
                                    attributes: [.font: font, .foregroundColor: base]))
        return s
    }

    private func body() -> NSView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.edgeInsets = NSEdgeInsets(top: 22, left: 24, bottom: 6, right: 24)
        stack.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(wrappingLabelWithString: request.title)
        title.font = .systemFont(ofSize: 17, weight: .bold)
        title.textColor = Self.ink
        title.preferredMaxLayoutWidth = Self.width - 48
        stack.addArrangedSubview(title)

        // Las líneas vienen YA PARTIDAS del agente (`consent-text.ts`), que es
        // donde vive la redacción para las tres plataformas. Aquí se
        // presentan, no se reescriben: una copia distinta por sistema es una
        // copia que se desincroniza.
        for line in request.lines where !line.isEmpty {
            stack.addArrangedSubview(bullet(line))
        }

        NSLayoutConstraint.activate([
            stack.widthAnchor.constraint(equalToConstant: Self.width),
        ])
        return stack
    }

    private func bullet(_ text: String) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 10

        let dot = NSTextField(labelWithString: "•")
        dot.font = .systemFont(ofSize: 13, weight: .bold)
        dot.textColor = control ? Self.amber : Self.teal

        let label = NSTextField(wrappingLabelWithString: text)
        label.font = .systemFont(ofSize: 13)
        label.textColor = Self.ink
        label.preferredMaxLayoutWidth = Self.width - 72

        row.addArrangedSubview(dot)
        row.addArrangedSubview(label)
        return row
    }

    private func footer() -> NSView {
        let bar = NSStackView()
        bar.orientation = .horizontal
        bar.alignment = .centerY
        bar.spacing = 10
        bar.edgeInsets = NSEdgeInsets(top: 16, left: 24, bottom: 20, right: 24)
        bar.translatesAutoresizingMaskIntoConstraints = false

        expiryLabel.font = .systemFont(ofSize: 11)
        expiryLabel.textColor = Self.inkSoft

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        // Píldoras propias y no el bezel del sistema. Dos razones, y la
        // segunda no es estética: el bezel de macOS pinta el botón gris de
        // siempre, que devuelve el diálogo al aspecto anónimo del que se le
        // quiere sacar; y un control con bezel del sistema no aparece en
        // `cacheDisplay`, así que la captura de revisión salía sin botones —
        // o sea, la pieza que decide el consentimiento era justo la que no se
        // podía revisar.
        let deny = pill(request.denyLabel,
                        fill: .white,
                        text: Self.ink,
                        border: Self.ink,
                        borderWidth: 2,
                        action: #selector(denyTapped))
        deny.keyEquivalent = "\r"   // Return ⇒ DENEGAR. Ver la cabecera.
        // El anillo hace VISIBLE cuál es el de reposo. Sin él, "denegar es el
        // botón por defecto" es una verdad que sólo conoce el código.
        deny.layer?.shadowColor = Self.ink.cgColor
        deny.layer?.shadowOpacity = 0.18
        deny.layer?.shadowRadius = 0
        deny.layer?.shadowOffset = .zero
        deny.layer?.masksToBounds = false

        let allow = pill(request.allowLabel,
                         fill: control ? Self.amber : NSColor(srgbRed: 0xEB/255.0, green: 0xF4/255.0, blue: 0xF4/255.0, alpha: 1),
                         text: control ? NSColor(srgbRed: 0x3A/255.0, green: 0x2D/255.0, blue: 0x07/255.0, alpha: 1) : NSColor(srgbRed: 0x2F/255.0, green: 0x60/255.0, blue: 0x60/255.0, alpha: 1),
                         border: control ? NSColor(srgbRed: 0xB9/255.0, green: 0x8F/255.0, blue: 0x17/255.0, alpha: 1) : Self.teal,
                         borderWidth: 1,
                         action: #selector(allowTapped))

        // Escape también deniega. Un botón no puede llevar dos atajos, así que
        // el de Escape es uno invisible: el gesto universal de "sácame de
        // aquí" no puede acabar concediendo acceso a la pantalla.
        let escapeHatch = NSButton(title: "", target: self, action: #selector(denyTapped))
        escapeHatch.keyEquivalent = "\u{1b}"
        escapeHatch.isHidden = true
        bar.addSubview(escapeHatch)

        bar.addArrangedSubview(expiryLabel)
        bar.addArrangedSubview(spacer)
        bar.addArrangedSubview(allow)
        bar.addArrangedSubview(deny)

        NSLayoutConstraint.activate([bar.widthAnchor.constraint(equalToConstant: Self.width)])
        return bar
    }

    /// Un botón con la forma de la marca: píldora, sin bezel de sistema.
    private func pill(_ title: String,
                      fill: NSColor,
                      text: NSColor,
                      border: NSColor,
                      borderWidth: CGFloat,
                      action: Selector) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.isBordered = false
        b.wantsLayer = true
        b.layer?.backgroundColor = fill.cgColor
        b.layer?.cornerRadius = 8
        b.layer?.borderWidth = borderWidth
        b.layer?.borderColor = border.cgColor
        b.attributedTitle = NSAttributedString(string: title, attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: text,
        ])
        b.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            b.heightAnchor.constraint(equalToConstant: 34),
            b.widthAnchor.constraint(greaterThanOrEqualToConstant: 96),
        ])
        return b
    }

    // MARK: - Cuenta atrás

    private func startCountdown() {
        tick()
        guard request.expiresAtUtc != nil else { return }
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(t, forMode: .modalPanel)
        timer = t
    }

    private func tick() {
        guard let expiry = request.expiresAtUtc else {
            expiryLabel.stringValue = ""
            return
        }
        let left = Int(expiry.timeIntervalSinceNow.rounded())
        if left <= 0 {
            // El plazo venció. No se concede nada: el agente ya lo cuenta como
            // negativa, y dejar la ventana abierta invitaría a contestar a algo
            // que ya no escucha nadie.
            expiryLabel.stringValue = "Expired"
            approved = false
            NSApp.stopModal()
            return
        }
        expiryLabel.stringValue = "Expires in \(left) s"
    }

    // MARK: - Decisión

    @objc private func denyTapped() {
        approved = false
        NSApp.stopModal()
    }

    @objc private func allowTapped() {
        approved = true
        NSApp.stopModal()
    }
}
