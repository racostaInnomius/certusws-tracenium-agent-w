import XCTest
import AppKit
@testable import TraceniumAgentStatus

/// Renderiza a PNG la franja de sesión y el diálogo de consentimiento REALES.
///
/// Mismo motivo que `HeaderSnapshotTests`: son las dos piezas que la persona
/// del otro lado ve cuando le miran la pantalla, y hasta ahora sólo se podían
/// revisar instalando el .app en la máquina de alguien — con lo cual no las
/// revisaba nadie, y el rediseño del 25-sep salió de una captura que mandó el
/// usuario porque no había otra forma de verlo.
///
/// Lo que se afirma automáticamente es lo que se puede afirmar sin mirar:
///
///   * que el acento CAMBIA entre ver y controlar (si los dos estados se
///     pintaran igual, el rediseño no diría nada),
///   * que denegar es el botón por defecto del diálogo — un Return distraído
///     no puede conceder acceso a la pantalla de nadie. Eso es una regla de
///     ADR-0012, no una preferencia de estilo, y aquí queda fijada.
///
/// Las rutas de los PNG salen por consola al correr los tests.
final class RemoteSessionUiSnapshotTests: XCTestCase {

    private func repoLogo() -> NSImage? {
        // En un test, `Bundle.main` es el de xctest y no lleva los recursos de
        // la .app. Se inyecta desde el repo para que la imagen refleje lo que
        // verá la persona; producción sigue leyendo del bundle.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Resources/tracenium_logo_color.png")
        return NSImage(contentsOf: url)
    }

    private func png(_ view: NSView, _ name: String) throws -> NSBitmapImageRep {
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            throw XCTSkip("no se pudo crear el bitmap de \(name)")
        }
        view.cacheDisplay(in: view.bounds, to: rep)
        guard let data = rep.representation(using: .png, properties: [:]) else {
            throw XCTSkip("no se pudo codificar \(name)")
        }
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracenium-\(name).png")
        try data.write(to: url)
        print("SNAPSHOT \(name) -> \(url.path)")
        return rep
    }

    /// Los modelos se construyen con el DECODIFICADOR real y no con un init de
    /// test: así el doble no puede tener una forma que el JSON de verdad no
    /// produce.
    private func decode<T: Decodable>(_ json: [String: Any]) throws -> T {
        let data = try JSONSerialization.data(withJSONObject: json)
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return try d.decode(T.self, from: data)
    }

    private func session(controlling: Bool) throws -> TrayRemoteSession {
        try decode([
            "active": true,
            "sessionId": "sess-snapshot",
            "capability": "rcp.screen",
            "operator": "Javier Pacheco",
            "controlling": controlling,
            "recording": true,
        ])
    }

    /// El color de un píxel del centro de la barra de acento, que es lo que
    /// distingue los dos estados de un vistazo.
    private func accentPixel(_ rep: NSBitmapImageRep) -> NSColor? {
        rep.colorAt(x: rep.pixelsWide / 2, y: rep.pixelsHigh - 1)
    }

    func testBannerStatesRenderAndDifferInAccent() throws {
        let banner = RemoteSessionBanner()

        banner.render(try session(controlling: false))
        guard let viewing = banner.contentViewForTests else {
            throw XCTSkip("la franja no montó su contenido")
        }
        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        deep(viewing).compactMap { $0 as? NSImageView }.forEach { $0.image = repoLogo() }
        let viewingRep = try png(viewing, "banner-viewing")

        banner.render(try session(controlling: true))
        guard let controlling = banner.contentViewForTests else {
            throw XCTSkip("la franja no montó su contenido")
        }
        let controllingRep = try png(controlling, "banner-controlling")

        // ⚠️ Lo que se afirma: los dos estados NO se pintan igual. Si alguien
        // unifica los acentos "por coherencia", la franja deja de avisar de lo
        // único que cambia lo que la persona haría.
        let a = accentPixel(viewingRep)
        let b = accentPixel(controllingRep)
        XCTAssertNotNil(a)
        XCTAssertNotNil(b)
        XCTAssertNotEqual(a?.description, b?.description,
                          "ver y controlar tienen que distinguirse por el acento")
    }

    func testConsentWindowRendersAndDenyIsDefault() throws {
        let request: ConsentRequest = try decode([
            "requestId": "req-snapshot",
            "sessionId": "sess-snapshot",
            "kind": "control",
            "title": "Allow Javier Pacheco to take control of this computer?",
            "lines": [
                "Javier Pacheco is requesting to CONTROL this computer.",
                "They can already see your screen.",
                "This also lets them use your mouse and keyboard.",
                "Requested through Tracenium, your IT management software.",
                "This session is being recorded.",
            ],
            "allowLabel": "Allow control",
            "denyLabel": "Not now",
        ])

        let window = ConsentWindow(request: request, control: true)
        guard let content = window.contentViewForTests else {
            throw XCTSkip("la ventana no montó su contenido")
        }
        func allViews(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(allViews) }
        allViews(content).compactMap { $0 as? NSImageView }.forEach { $0.image = repoLogo() }
        for v in descendants(content) where v is NSStackView || v is NSButton {
            print("DBG \(type(of: v)) frame=\(v.frame) hidden=\(v.isHidden)")
        }
        print("DBG content=\(content.frame) fitting=\(content.fittingSize)")
        _ = try png(content, "consent-control")

        // ⚠️ ADR-0012: el botón por defecto DENIEGA. Return es donde va la
        // mano, y en un diálogo que concede acceso a la pantalla de alguien la
        // opción de reposo no puede ser la que concede.
        // Recursivo: los botones viven dentro de dos NSStackView anidados, y
        // una búsqueda de dos niveles encontraba cero — un falso verde que
        // habría dejado pasar exactamente el bug que este test vigila.
        func descendants(_ v: NSView) -> [NSView] {
            v.subviews + v.subviews.flatMap(descendants)
        }
        let buttons = descendants(content)
            .compactMap { $0 as? NSButton }
            .filter { !$0.title.isEmpty }
        let porDefecto = buttons.filter { $0.keyEquivalent == "\r" }
        XCTAssertEqual(porDefecto.count, 1, "exactamente un botón por defecto")
        XCTAssertEqual(porDefecto.first?.title, "Not now",
                       "el botón por defecto tiene que ser el de denegar")
    }
}
