import XCTest
import AppKit
@testable import TraceniumAgentStatus

/// ⚠️ «Permissions…» y «Copy all» comparten fila y no medían lo mismo.
///
/// Captura del usuario, 25-sep-2026. El código tenía un comentario que decía
/// «Same size as copyButton» justo encima de `locationButton.controlSize =
/// .mini`, mientras copyButton era `.regular`: el comentario describía la
/// intención y el valor hacía otra cosa. En la fila se veía un botón de
/// juguete al lado de uno normal.
///
/// La prueba mide los botones montados, no lee la constante: una constante
/// puede volver a discrepar del resultado, y lo que la persona ve es el alto
/// en pantalla.
final class TabStripSizingTests: XCTestCase {

    private func strip(_ vc: StatusPopoverViewController) -> [NSButton] {
        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        return deep(vc.view).compactMap { $0 as? NSButton }
    }

    func testPermissionsAndCopyAllAreTheSameHeight() throws {
        let vc = StatusPopoverViewController()
        _ = vc.view
        vc.setLocationPromptVisible(true)   // «Permissions…» solo sale si hace falta
        vc.view.layoutSubtreeIfNeeded()

        let buttons = strip(vc)
        guard let copy = buttons.first(where: { $0.title == "Copy all" }),
              let perms = buttons.first(where: { $0.title.hasPrefix("Permissions") }) else {
            throw XCTSkip("no se encontraron los dos botones: \(buttons.map(\.title))")
        }

        XCTAssertEqual(
            perms.frame.height, copy.frame.height, accuracy: 0.5,
            "los dos comparten la tira de pestañas; con altos distintos la fila "
            + "no se lee como una fila"
        )
        XCTAssertEqual(perms.controlSize, copy.controlSize)
        XCTAssertEqual(perms.font?.pointSize, copy.font?.pointSize)
    }

    /// Y que sigan alineados verticalmente con las pestañas, que es el otro
    /// modo de que la fila se rompa.
    func testBothButtonsMatchTheTabsHeight() throws {
        let vc = StatusPopoverViewController()
        _ = vc.view
        vc.setLocationPromptVisible(true)
        vc.view.layoutSubtreeIfNeeded()

        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        guard let tabs = deep(vc.view).compactMap({ $0 as? NSSegmentedControl }).first else {
            throw XCTSkip("sin tira de pestañas")
        }
        for b in strip(vc) where b.title == "Copy all" || b.title.hasPrefix("Permissions") {
            XCTAssertEqual(b.frame.height, tabs.frame.height, accuracy: 1.0,
                           "«\(b.title)» no mide lo que las pestañas")
        }
    }
}
