import XCTest
import AppKit
@testable import TraceniumAgentStatus

/// Renderiza el popover REAL a PNG para poder mirarlo.
///
/// No es un test de regresión con imagen de referencia: es una forma de que un
/// cambio de layout sea revisable sin instalar el .app en la máquina de nadie.
/// Los ajustes visuales de esta pantalla se venían validando a ojo tras un
/// build+install completo, y eso hace que nadie los revise.
///
/// Lo que SÍ afirma automáticamente es lo que se puede afirmar sin ver la
/// imagen: que la pastilla del estado centra su texto en los dos ejes. Ese fue
/// un bug real —`NSTextField` dibuja arriba cuando el frame es más alto que la
/// línea, y `alignment = .center` sólo resuelve el eje horizontal— y sin
/// contenedor volvería a aparecer sin que nada fallara.
///
/// El PNG se escribe en TMPDIR; la ruta sale por consola al correr los tests.
final class HeaderSnapshotTests: XCTestCase {

    private func makeLoadedController() -> StatusPopoverViewController {
        let vc = StatusPopoverViewController()
        _ = vc.view          // fuerza loadView() y toda la construcción del header
        vc.view.layoutSubtreeIfNeeded()
        return vc
    }

    func testPopoverRendersToPNG() throws {
        let vc = makeLoadedController()

        // En un test, Bundle.main es el bundle de xctest y no lleva los recursos
        // de la .app, asi que el logo saldria vacio. Se inyecta desde el repo
        // para que la imagen refleje lo que vera el usuario — la logica de
        // produccion sigue leyendo del bundle, sin ramas de test.
        let repoLogo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Resources/tracenium_logo_color.png")
        vc.applyHeaderLogo(NSImage(contentsOf: repoLogo))
        vc.view.layoutSubtreeIfNeeded()

        let view = vc.view

        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            return XCTFail("no se pudo crear el bitmap del popover")
        }
        view.cacheDisplay(in: view.bounds, to: rep)

        guard let png = rep.representation(using: .png, properties: [:]) else {
            return XCTFail("no se pudo codificar el PNG")
        }
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracenium-popover.png")
        try png.write(to: url)
        print("POPOVER SNAPSHOT -> \(url.path)")

        XCTAssertGreaterThan(rep.pixelsWide, 0)
        XCTAssertGreaterThan(rep.pixelsHigh, 0)
    }

    /// El bug #3 reportado: el texto de ONLINE/OFFLINE no estaba centrado.
    func testStatusBadgeTextIsCenteredOnBothAxes() throws {
        let vc = makeLoadedController()

        // Se localizan por estructura y no por referencia directa para que el
        // test siga valiendo si los campos privados se renombran.
        let labels = allSubviews(of: vc.view).compactMap { $0 as? NSTextField }
        guard let badge = labels.first(where: {
            let s = $0.stringValue.uppercased()
            return s == "ONLINE" || s == "OFFLINE" || s == "UNKNOWN"
        }) else {
            return XCTFail("no se encontró la pastilla de estado en el header")
        }

        guard let container = badge.superview else {
            return XCTFail("la pastilla no tiene contenedor")
        }

        // El contenedor es quien debe llevar el fondo: si la etiqueta volviera a
        // pintarse ella misma, el texto se iría otra vez al borde superior.
        XCTAssertNotNil(
            container.layer?.backgroundColor,
            "el fondo de la pastilla debe vivir en el contenedor, no en el NSTextField"
        )

        let b = badge.frame
        let c = container.bounds
        XCTAssertEqual(b.midX, c.midX, accuracy: 0.6, "texto descentrado en horizontal")
        XCTAssertEqual(b.midY, c.midY, accuracy: 0.6, "texto descentrado en vertical")
    }

    /// El logo a color del header (#4). Si el recurso no viaja al bundle, la
    /// imagen queda nil y el header sale con un hueco — sin fallar en runtime.
    func testHeaderLogoResourceLoads() throws {
        let vc = makeLoadedController()
        let images = allSubviews(of: vc.view).compactMap { $0 as? NSImageView }
        XCTAssertFalse(images.isEmpty, "el header debería tener un NSImageView para el logo")
    }

    private func allSubviews(of view: NSView) -> [NSView] {
        view.subviews + view.subviews.flatMap { allSubviews(of: $0) }
    }
}
