import AppKit

/// Indicador PERMANENTE de sesión de control remoto (ADR-0012, paso 1).
///
/// Franja bajo la barra de menús, siempre encima, mientras alguien está viendo
/// esta pantalla. No es una notificación: una notificación se descarta y a los
/// diez segundos la persona ya no recuerda que la están mirando. Lo que
/// protege es la presencia continua — y el botón de cortar que lleva al lado.
///
/// Decisiones de macOS que NO son intercambiables:
///
///  * **`NSPanel` con `.nonactivatingPanel`**, no `NSWindow`. Una ventana
///    normal activaría esta app al pulsar el botón, sacando del foco a la
///    persona en mitad de la incidencia que motivó la sesión de soporte. El
///    panel no-activante acepta el clic sin robar el foco, que es justo el
///    comportamiento que hace falta.
///
///  * **`collectionBehavior` con `.canJoinAllSpaces` y `.fullScreenAuxiliary`.**
///    Sin lo segundo, la banda desaparece en cuanto la persona pone cualquier
///    app en pantalla completa — y una app a pantalla completa es exactamente
///    donde alguien tiene abierto el documento que no querría que le vieran.
///    Un indicador que se esconde cuando más importa no es un indicador.
///
///  * **`.statusBar` como nivel**, por encima de ventanas normales. No usamos
///    un nivel más alto: por encima de `.statusBar` están los diálogos del
///    sistema, y taparle a alguien una alerta de macOS con nuestra banda sería
///    empeorar su situación, no mejorarla.
///
///  * **`.stationary`**, para que no se arrastre en la animación de Mission
///    Control como si fuera una ventana de la persona.
///
/// ── Presentación (rediseño 25-sep-2026, igual en las tres plataformas) ──
///
/// Cromo oscuro de marca en vez de la banda ámbar del sistema: se lee como una
/// pieza de Tracenium y no como un aviso genérico del SO, que es lo que la
/// hace creíble. Y el ámbar deja de ser el fondo para ser **el acento del
/// estado**:
///
///   viendo        → cian  (#8FFDFF)
///   controlando   → ámbar (#F4D37D)
///
/// Los dos acentos se distinguen también por CLARIDAD, no solo por tono, así
/// que el cambio se ve aunque no se distingan los colores. El alto y la
/// posición no cambian al escalar: la franja no salta de sitio, porque una
/// franja que salta se lee como una ventana nueva y no como la misma que ya
/// estaba avisando.
final class RemoteSessionBanner {
    private var panel: NSPanel?
    private var sessionId = ""

    // MARK: Vistas

    private let logoView = NSImageView()
    private let dotView = NSView()
    private let label = NSTextField(labelWithString: "")
    private let recBadge = NSView()
    private let recDot = NSView()
    private let recLabel = NSTextField(labelWithString: "REC")
    private let divider = NSView()
    private let stopButton = NSButton(title: "Stop sharing", target: nil, action: nil)
    private let accentBar = NSView()

    /// Alto de la franja. Uno solo: ver la nota de la cabecera.
    private static let bannerHeight: CGFloat = 52
    private static let bannerWidth: CGFloat = 760
    private static let cornerRadius: CGFloat = 14

    // MARK: Colores de marca
    //
    // Fijos y no adaptativos al modo claro/oscuro: la franja es cromo oscuro
    // SIEMPRE. En modo claro una banda oscura destaca más, que es lo que se
    // busca, y así el indicador se ve igual en las capturas de un incidente
    // independientemente de cómo tuviera el Mac la persona.

    private static let chromeViewing = NSColor(srgbRed: 0x22/255.0, green: 0x28/255.0, blue: 0x31/255.0, alpha: 1)
    private static let chromeControlling = NSColor(srgbRed: 0x2A/255.0, green: 0x26/255.0, blue: 0x20/255.0, alpha: 1)
    private static let accentViewing = NSColor(srgbRed: 0x8F/255.0, green: 0xFD/255.0, blue: 0xFF/255.0, alpha: 1)
    private static let accentControlling = NSColor(srgbRed: 0xF4/255.0, green: 0xD3/255.0, blue: 0x7D/255.0, alpha: 1)
    private static let textViewing = NSColor(srgbRed: 0xF2/255.0, green: 0xF4/255.0, blue: 0xF7/255.0, alpha: 1)
    private static let textControlling = NSColor(srgbRed: 0xFB/255.0, green: 0xEF/255.0, blue: 0xD2/255.0, alpha: 1)

    /// Refleja el estado de la sesión. `nil` o inactiva ⇒ se esconde.
    ///
    /// Que se esconda importa tanto como que aparezca: una franja encendida sin
    /// sesión enseña una alarma falsa y entrena a la gente a ignorar la
    /// siguiente, que sí será real.
    func render(_ session: TrayRemoteSession?) {
        guard let session, session.active, !session.sessionId.isEmpty else {
            hide()
            return
        }

        sessionId = session.sessionId
        let panel = self.panel ?? makePanel()
        self.panel = panel

        let controlling = session.controlling
        let accent = controlling ? Self.accentControlling : Self.accentViewing
        let text = controlling ? Self.textControlling : Self.textViewing

        panel.backgroundColor = .clear
        panel.contentView?.layer?.backgroundColor = (controlling ? Self.chromeControlling : Self.chromeViewing).cgColor
        accentBar.layer?.backgroundColor = accent.cgColor
        dotView.layer?.backgroundColor = accent.cgColor

        // Sin nombre decimos "An operator". Inventar uno sería peor que
        // admitir que no lo sabemos: la identidad es justo lo que hace creíble
        // al indicador.
        let who = (session.operator?.isEmpty == false) ? session.operator! : "An operator"
        label.attributedStringValue = Self.bannerText(
            who: who, controlling: controlling, color: text
        )

        // La grabación sale como insignia y no dentro de la frase: es un hecho
        // distinto del de quién mira, y en la frase se perdía al final de una
        // línea larga que se trunca por la derecha justo ahí.
        recBadge.isHidden = !session.recording

        stopButton.attributedTitle = Self.buttonTitle(
            controlling ? "Stop session" : "Stop sharing",
            color: controlling ? NSColor(srgbRed: 0x3A/255.0, green: 0x2D/255.0, blue: 0x07/255.0, alpha: 1) : text
        )
        stopButton.layer?.backgroundColor = controlling ? accent.cgColor : NSColor.clear.cgColor
        stopButton.layer?.borderColor = controlling ? accent.cgColor : text.withAlphaComponent(0.55).cgColor
        stopButton.isEnabled = true

        reposition(panel)
        // orderFrontRegardless: mostrar SIN activar la app. Ordenar al frente
        // de la forma normal desde una app .accessory puede no hacer nada si
        // no somos la app activa, que es siempre.
        panel.orderFrontRegardless()
    }

    /// El texto, con la palabra que importa en negrita.
    ///
    /// "controlando" va destacado porque es la diferencia entre las dos cosas
    /// que la franja puede estar diciendo, y la que cambia lo que la persona
    /// haría al respecto.
    private static func bannerText(who: String, controlling: Bool, color: NSColor) -> NSAttributedString {
        let regular = NSFont.systemFont(ofSize: 13, weight: .semibold)
        let strong = NSFont.systemFont(ofSize: 13, weight: .heavy)
        let s = NSMutableAttributedString()
        if controlling {
            s.append(NSAttributedString(string: "\(who) is viewing and ",
                                        attributes: [.font: regular, .foregroundColor: color]))
            s.append(NSAttributedString(string: "controlling",
                                        attributes: [.font: strong, .foregroundColor: color]))
            s.append(NSAttributedString(string: " this Mac",
                                        attributes: [.font: regular, .foregroundColor: color]))
        } else {
            s.append(NSAttributedString(string: "\(who) is viewing this screen",
                                        attributes: [.font: regular, .foregroundColor: color]))
        }
        return s
    }

    private static func buttonTitle(_ title: String, color: NSColor) -> NSAttributedString {
        NSAttributedString(string: title, attributes: [
            .font: NSFont.systemFont(ofSize: 12, weight: .semibold),
            .foregroundColor: color,
        ])
    }

    private func hide() {
        sessionId = ""
        panel?.orderOut(nil)
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: Self.bannerWidth, height: Self.bannerHeight),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.isFloatingPanel = true
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        panel.hidesOnDeactivate = false
        panel.isMovable = false
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true

        let content = NSView(frame: NSRect(x: 0, y: 0, width: Self.bannerWidth, height: Self.bannerHeight))
        content.wantsLayer = true
        content.layer?.cornerRadius = Self.cornerRadius
        // Solo las esquinas de ABAJO: la franja está pegada al borde superior,
        // así que redondear arriba dibujaría un hueco contra la barra de menús.
        // minY es abajo en las coordenadas de AppKit.
        content.layer?.maskedCorners = [.layerMinXMinYCorner, .layerMaxXMinYCorner]
        content.layer?.masksToBounds = true

        logoView.imageScaling = .scaleProportionallyUpOrDown
        logoView.image = Bundle.main.url(forResource: "tracenium_logo_color", withExtension: "png")
            .flatMap { NSImage(contentsOf: $0) }
        logoView.translatesAutoresizingMaskIntoConstraints = false

        dotView.wantsLayer = true
        dotView.layer?.cornerRadius = 4.5
        dotView.translatesAutoresizingMaskIntoConstraints = false

        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        // Insignia REC: punto + palabra, en ámbar sobre su propio relleno.
        recBadge.wantsLayer = true
        recBadge.layer?.cornerRadius = 10
        recBadge.layer?.backgroundColor = NSColor(srgbRed: 0xF4/255.0, green: 0xD3/255.0, blue: 0x7D/255.0, alpha: 0.16).cgColor
        recBadge.layer?.borderWidth = 1
        recBadge.layer?.borderColor = NSColor(srgbRed: 0xF4/255.0, green: 0xD3/255.0, blue: 0x7D/255.0, alpha: 0.45).cgColor
        recBadge.translatesAutoresizingMaskIntoConstraints = false

        recDot.wantsLayer = true
        recDot.layer?.cornerRadius = 3.5
        recDot.layer?.backgroundColor = Self.accentControlling.cgColor
        recDot.translatesAutoresizingMaskIntoConstraints = false

        recLabel.attributedStringValue = NSAttributedString(string: "REC", attributes: [
            .font: NSFont.systemFont(ofSize: 10, weight: .bold),
            .foregroundColor: NSColor(srgbRed: 0xF7/255.0, green: 0xDF/255.0, blue: 0x9E/255.0, alpha: 1),
            .kern: 0.6,
        ])
        recLabel.translatesAutoresizingMaskIntoConstraints = false

        divider.wantsLayer = true
        divider.layer?.backgroundColor = NSColor(white: 1, alpha: 0.20).cgColor
        divider.translatesAutoresizingMaskIntoConstraints = false

        // isBordered = false + capa propia: el bezel de macOS pinta un botón
        // gris de sistema que rompería el cromo. La píldora se dibuja aquí.
        stopButton.isBordered = false
        stopButton.wantsLayer = true
        stopButton.layer?.cornerRadius = 17
        stopButton.layer?.borderWidth = 1
        stopButton.target = self
        stopButton.action = #selector(stopTapped)
        stopButton.translatesAutoresizingMaskIntoConstraints = false

        accentBar.wantsLayer = true
        accentBar.translatesAutoresizingMaskIntoConstraints = false

        recBadge.addSubview(recDot)
        recBadge.addSubview(recLabel)
        for v in [logoView, dotView, label, recBadge, divider, stopButton, accentBar] {
            content.addSubview(v)
        }
        panel.contentView = content

        NSLayoutConstraint.activate([
            logoView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 14),
            logoView.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            logoView.widthAnchor.constraint(equalToConstant: 24),
            logoView.heightAnchor.constraint(equalToConstant: 24),

            dotView.leadingAnchor.constraint(equalTo: logoView.trailingAnchor, constant: 12),
            dotView.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            dotView.widthAnchor.constraint(equalToConstant: 9),
            dotView.heightAnchor.constraint(equalToConstant: 9),

            label.leadingAnchor.constraint(equalTo: dotView.trailingAnchor, constant: 10),
            label.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            label.trailingAnchor.constraint(lessThanOrEqualTo: recBadge.leadingAnchor, constant: -10),

            recBadge.trailingAnchor.constraint(equalTo: divider.leadingAnchor, constant: -10),
            recBadge.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            recBadge.heightAnchor.constraint(equalToConstant: 20),

            recDot.leadingAnchor.constraint(equalTo: recBadge.leadingAnchor, constant: 8),
            recDot.centerYAnchor.constraint(equalTo: recBadge.centerYAnchor),
            recDot.widthAnchor.constraint(equalToConstant: 7),
            recDot.heightAnchor.constraint(equalToConstant: 7),

            recLabel.leadingAnchor.constraint(equalTo: recDot.trailingAnchor, constant: 5),
            recLabel.trailingAnchor.constraint(equalTo: recBadge.trailingAnchor, constant: -8),
            recLabel.centerYAnchor.constraint(equalTo: recBadge.centerYAnchor),

            divider.trailingAnchor.constraint(equalTo: stopButton.leadingAnchor, constant: -10),
            divider.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            divider.widthAnchor.constraint(equalToConstant: 1),
            divider.heightAnchor.constraint(equalToConstant: 22),

            stopButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -8),
            stopButton.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            stopButton.heightAnchor.constraint(equalToConstant: 34),
            stopButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 116),

            accentBar.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            accentBar.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            accentBar.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            accentBar.heightAnchor.constraint(equalToConstant: 2),
        ])

        return panel
    }

    /// El contenido montado, para poder renderizarlo en un test.
    ///
    /// Sólo lectura: el test mira lo que la persona vería, no toca el estado.
    /// Es lo mismo que hace `applyHeaderLogo` en el popover — un asa para que
    /// una pantalla que sólo se veía instalando el .app se pueda revisar.
    var contentViewForTests: NSView? { panel?.contentView }

    @objc private func stopTapped() {
        guard !sessionId.isEmpty else { return }
        // Desactivar en el acto: la persona ya lo pidió y volver a pulsar no
        // acelera nada. El texto cambia para que se vea que se está actuando —
        // el corte tarda hasta medio segundo en llegar al agente.
        stopButton.isEnabled = false
        stopButton.attributedTitle = Self.buttonTitle("Stopping…", color: Self.textViewing)
        RemoteSessionRevokeSink.write(sessionId: sessionId)
    }

    private func reposition(_ panel: NSPanel) {
        // visibleFrame excluye la barra de menús y el Dock, así que la banda
        // queda JUSTO debajo del menú sin taparlo.
        guard let screen = NSScreen.main else { return }
        let area = screen.visibleFrame
        let width = min(area.width - 40, Self.bannerWidth)
        let height = Self.bannerHeight
        panel.setFrame(
            NSRect(x: area.midX - width / 2, y: area.maxY - height, width: width, height: height),
            display: true
        )
    }
}
