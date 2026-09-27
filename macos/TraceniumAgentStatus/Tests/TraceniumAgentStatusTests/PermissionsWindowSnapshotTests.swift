import XCTest
import AppKit
@testable import TraceniumAgentStatus

/// La ventana de permisos, renderizada a PNG para poder revisarla.
///
/// Es la primera pantalla que ve quien acaba de instalar Tracenium en su Mac, y
/// hasta ahora ese momento no existía: los dos permisos se pedían la primera
/// vez que hacían falta, con un diálogo del sistema sin contexto en mitad de
/// una incidencia. Una pantalla que decide si alguien confía en el producto
/// tiene que poder mirarse sin instalar el .app.
final class PermissionsWindowSnapshotTests: XCTestCase {

    func testRendersToPNG() throws {
        let w = PermissionsWindow()
        // Estados fijos para que la imagen no dependa de cómo tenga los
        // permisos el Mac que corre los tests.
        w.locationState = { .granted }

        guard let content = w.contentViewForTests else {
            throw XCTSkip("la ventana no montó su contenido")
        }
        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        let repoLogo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Resources/tracenium_logo_color.png")
        deep(content).compactMap { $0 as? NSImageView }.forEach { $0.image = NSImage(contentsOf: repoLogo) }

        content.layoutSubtreeIfNeeded()
        guard let rep = content.bitmapImageRepForCachingDisplay(in: content.bounds) else {
            throw XCTSkip("sin bitmap")
        }
        content.cacheDisplay(in: content.bounds, to: rep)
        guard let data = rep.representation(using: .png, properties: [:]) else {
            throw XCTSkip("sin png")
        }
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracenium-permissions.png")
        try data.write(to: url)
        print("SNAPSHOT permissions -> \(url.path)")
        XCTAssertGreaterThan(rep.pixelsHigh, 0)
    }

    /// ⚠️ "No lo sé" no se puede pintar como "no concedido".
    ///
    /// Pasa cuando el helper no está instalado. Decir que falta un permiso que
    /// quizá esté mandaría a la persona a arreglar algo que no está roto.
    func testUnknownIsNotRenderedAsMissing() throws {
        let w = PermissionsWindow()
        w.locationState = { .unknown }
        guard let content = w.contentViewForTests else { throw XCTSkip("sin contenido") }
        w.present()
        defer { w.close() }
        content.layoutSubtreeIfNeeded()

        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        let chips = deep(content).compactMap { $0 as? NSTextField }
            .map { $0.stringValue }
        XCTAssertTrue(chips.contains("Unknown"), "el estado desconocido se dice, no se disfraza")
        XCTAssertFalse(chips.contains("Granted"), "y desde luego no se pinta como concedido")
    }

    /// 🔴 Los botones de la ventana tapaban el logo.
    ///
    /// Captura del usuario, 25-sep-2026: con `fullSizeContentView` el sistema
    /// pinta cerrar/minimizar/zoom SOBRE nuestra banda, y con la banda de 46 pt
    /// y el contenido centrado el logo caía justo bajo el botón rojo. Quien
    /// fuera a tocar el logo cerraba la ventana — es decir, el sitio más obvio
    /// para pulsar era el que hacía desaparecer la pantalla que pide el
    /// permiso.
    ///
    /// La invariante no es «la barra mide X»: es que **nada nuestro entra en la
    /// franja del sistema**. Así aguanta aunque cambien las alturas.
    func testNothingOfOursSitsUnderTheWindowButtons() throws {
        let w = PermissionsWindow()
        w.locationState = { .granted }
        guard let content = w.contentViewForTests else { throw XCTSkip("sin contenido") }
        content.layoutSubtreeIfNeeded()

        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        // La banda es la única vista con el cromo oscuro de marca.
        let reserved = PermissionsWindow.titlebarReserved

        // Coordenadas de la ventana: y=0 abajo. La franja del sistema es la
        // cinta de `reserved` puntos pegada ARRIBA del contenido.
        let topEdge = content.bounds.maxY
        var offenders: [String] = []
        for v in deep(content) where (v is NSImageView) || (v is NSTextField) {
            let f = v.convert(v.bounds, to: content)
            if f.maxY > topEdge - reserved {
                let kind = (v as? NSTextField)?.stringValue ?? "logo"
                offenders.append("\(kind) llega a y=\(Int(topEdge - f.maxY)) pt del borde")
            }
        }
        XCTAssertTrue(offenders.isEmpty,
                      "esto queda debajo de los botones del sistema: \(offenders.joined(separator: ", "))")
    }

    /// 🔴 En modo oscuro los botones salían VACÍOS.
    ///
    /// Captura del usuario (25-sep-2026): «Granted» y «Done» sin texto. El
    /// texto estaba, pintado de blanco sobre nuestra tarjeta blanca.
    ///
    /// La causa no es el tema: es que `refresh()` y `apply()` asignaban
    /// `.title`, y ESO DESCARTA el `attributedTitle` —y con él el color que le
    /// habíamos puesto—. El botón pasa a pintarse con el color de etiqueta del
    /// sistema, que en claro es oscuro (colaba por accidente) y en oscuro es
    /// blanco.
    ///
    /// Se comprueba la propiedad que importa —que cada botón lleve SU color— y
    /// no que la ventana «se vea bien», que no es medible.
    func testEveryButtonKeepsItsOwnColour() throws {
        let w = PermissionsWindow()
        w.locationState = { .granted }
        guard let content = w.contentViewForTests else { throw XCTSkip("sin contenido") }
        w.present()
        defer { w.close() }
        content.layoutSubtreeIfNeeded()

        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        let buttons = deep(content).compactMap { $0 as? NSButton }
        XCTAssertFalse(buttons.isEmpty, "no se encontró ningún botón")

        // ⚠️ La aserción NO puede ser «tiene attributedTitle»: AppKit lo
        // SINTETIZA a partir de `.title`, así que siempre hay uno y con color.
        // La primera versión de esta prueba comprobaba eso y pasaba aunque se
        // devolviera el bug. Lo que distingue un caso del otro es CUÁL es el
        // color: los nuestros son literales de marca; el sintetizado es el
        // color de etiqueta del sistema, que sigue el tema del equipo.
        let brand: [NSColor] = [
            NSColor(srgbRed: 0x1C/255.0, green: 0x20/255.0, blue: 0x27/255.0, alpha: 1), // ink
            NSColor(srgbRed: 0x5C/255.0, green: 0x64/255.0, blue: 0x6E/255.0, alpha: 1), // inkSoft
            NSColor(srgbRed: 0x3C/255.0, green: 0x7C/255.0, blue: 0x7C/255.0, alpha: 1), // teal
            NSColor(srgbRed: 0x2F/255.0, green: 0x60/255.0, blue: 0x60/255.0, alpha: 1)  // teal oscuro
        ]
        func isBrand(_ c: NSColor?) -> Bool {
            guard let c = c?.usingColorSpace(.sRGB) else { return false }
            return brand.contains { b in
                let b = b.usingColorSpace(.sRGB)!
                return abs(b.redComponent - c.redComponent) < 0.01
                    && abs(b.greenComponent - c.greenComponent) < 0.01
                    && abs(b.blueComponent - c.blueComponent) < 0.01
            }
        }

        for b in buttons {
            let attr = b.attributedTitle
            XCTAssertGreaterThan(attr.length, 0, "botón sin texto")
            var range = NSRange(location: 0, length: 0)
            let colour = attr.attribute(.foregroundColor, at: 0, effectiveRange: &range) as? NSColor
            XCTAssertTrue(
                isBrand(colour),
                "«\(attr.string)» no lleva un color de marca sino "
                + "\(String(describing: colour)): alguien asignó `.title` y AppKit "
                + "lo repintó con el color de etiqueta del sistema — en modo oscuro "
                + "eso es blanco sobre nuestra tarjeta blanca"
            )
        }
    }

    /// Y la otra mitad: la apariencia se fija, para que lo que dibuja el
    /// SISTEMA encima (botones de ventana, atenuado de un control desactivado)
    /// no siga el tema del equipo sobre una paleta escrita para tarjeta clara.
    func testTheWindowPinsTheLightAppearance() throws {
        let w = PermissionsWindow()
        w.locationState = { .granted }
        w.present()
        defer { w.close() }
        XCTAssertEqual(w.contentViewForTests?.window?.appearance?.name, .aqua,
                       "sin fijar la apariencia, la mitad de los Macs pintan "
                       + "los controles del sistema en claro sobre nuestro blanco")
    }
}
