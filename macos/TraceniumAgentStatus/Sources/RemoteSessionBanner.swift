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
final class RemoteSessionBanner {
    private var panel: NSPanel?
    private let label = NSTextField(labelWithString: "")
    private let stopButton = NSButton(title: "Stop sharing", target: nil, action: nil)
    private var sessionId = ""

    /// Ámbar de aviso, con su variante para modo oscuro. Ámbar y no rojo: el
    /// rojo dice "error" y esto no lo es — es una sesión legítima que la
    /// persona debe poder ver. El rojo se reserva para cuando algo va mal.
    private static let bannerBackground = NSColor(name: "TraceniumRemoteBannerBg") { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            ? NSColor(calibratedRed: 88/255.0, green: 62/255.0, blue: 4/255.0, alpha: 1.0)
            : NSColor(calibratedRed: 255/255.0, green: 244/255.0, blue: 214/255.0, alpha: 1.0)
    }

    private static let bannerText = NSColor(name: "TraceniumRemoteBannerText") { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            ? NSColor(calibratedRed: 255/255.0, green: 197/255.0, blue: 92/255.0, alpha: 1.0)
            : NSColor(calibratedRed: 139/255.0, green: 100/255.0, blue: 4/255.0, alpha: 1.0)
    }

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

        // Sin nombre decimos "An operator". Inventar uno sería peor que
        // admitir que no lo sabemos: la identidad es justo lo que hace creíble
        // al indicador.
        let who = (session.operator?.isEmpty == false) ? session.operator! : "An operator"
        var text = session.controlling
            ? "\(who) is viewing and controlling this Mac"
            : "\(who) is viewing this screen"
        if session.recording {
            // El derecho a saber que te graban no se agota al aceptar: dura lo
            // que dure la grabación.
            text += " · this session is being recorded"
        }

        label.stringValue = text
        stopButton.title = session.controlling ? "Stop session" : "Stop sharing"
        stopButton.isEnabled = true

        show()
    }

    private func show() {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        reposition(panel)
        // orderFrontRegardless: mostrar SIN activar la app. Ordenar al frente
        // de la forma normal desde una app .accessory puede no hacer nada si
        // no somos la app activa, que es siempre.
        panel.orderFrontRegardless()
    }

    private func hide() {
        sessionId = ""
        panel?.orderOut(nil)
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 34),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.isFloatingPanel = true
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        panel.hidesOnDeactivate = false
        panel.isMovable = false
        panel.backgroundColor = Self.bannerBackground
        panel.hasShadow = true

        let content = NSView(frame: panel.contentView?.bounds ?? .zero)
        content.wantsLayer = true

        label.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        label.textColor = Self.bannerText
        label.alignment = .center
        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false

        stopButton.bezelStyle = .rounded
        stopButton.target = self
        stopButton.action = #selector(stopTapped)
        stopButton.translatesAutoresizingMaskIntoConstraints = false

        content.addSubview(label)
        content.addSubview(stopButton)
        panel.contentView = content

        NSLayoutConstraint.activate([
            stopButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -10),
            stopButton.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            label.trailingAnchor.constraint(equalTo: stopButton.leadingAnchor, constant: -12),
            label.centerYAnchor.constraint(equalTo: content.centerYAnchor),
        ])

        return panel
    }

    @objc private func stopTapped() {
        guard !sessionId.isEmpty else { return }
        // Desactivar en el acto: la persona ya lo pidió y volver a pulsar no
        // acelera nada. El texto cambia para que se vea que se está actuando —
        // el corte tarda hasta medio segundo en llegar al agente.
        stopButton.isEnabled = false
        stopButton.title = "Stopping…"
        RemoteSessionRevokeSink.write(sessionId: sessionId)
    }

    private func reposition(_ panel: NSPanel) {
        // visibleFrame excluye la barra de menús y el Dock, así que la banda
        // queda JUSTO debajo del menú sin taparlo.
        guard let screen = NSScreen.main else { return }
        let area = screen.visibleFrame
        let width = min(area.width - 40, 720)
        let height: CGFloat = 34
        panel.setFrame(
            NSRect(x: area.midX - width / 2, y: area.maxY - height, width: width, height: height),
            display: true
        )
    }
}
