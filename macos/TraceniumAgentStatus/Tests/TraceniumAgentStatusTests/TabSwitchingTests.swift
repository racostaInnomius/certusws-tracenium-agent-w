import XCTest
import AppKit
@testable import TraceniumAgentStatus

/// ⚠️ Dos pestañas dibujadas una encima de otra.
///
/// De dónde viene (captura del usuario, 25-sep-2026): tras entrar en Catalog y
/// volver a otra pestaña, el popover enseñaba las filas de Device Info y las de
/// Agent Info SUPERPUESTAS — «Logged user» y «Last heartbeat» pisándose, los
/// títulos de sección de las dos a alturas distintas. Ilegible.
///
/// El cambio de pestaña es un `isHidden` sobre cuatro scrollviews y la rama
/// parecía exhaustiva, así que en vez de razonar sobre el código se reproduce:
/// se monta el controlador de verdad, se recorren las pestañas como lo haría
/// una persona y se comprueba la invariante que la pantalla necesita —
/// **exactamente una visible** —, además de dejar un PNG para mirarlo.
final class TabSwitchingTests: XCTestCase {

    private func loaded() -> StatusPopoverViewController {
        let vc = StatusPopoverViewController()
        _ = vc.view
        vc.view.layoutSubtreeIfNeeded()
        return vc
    }

    /// Los cuatro scrollviews del cuerpo, en orden de pestaña.
    private func bodyScrolls(_ vc: StatusPopoverViewController) -> [NSScrollView] {
        func deep(_ v: NSView) -> [NSView] { v.subviews + v.subviews.flatMap(deep) }
        return deep(vc.view).compactMap { $0 as? NSScrollView }
    }

    private func visibleCount(_ vc: StatusPopoverViewController) -> Int {
        bodyScrolls(vc).filter { !$0.isHidden }.count
    }

    /// Un estado con catálogo, como el que llega cada 5 s.
    private func status(catalogItems: Int) throws -> TrayStatus {
        let items = (0..<catalogItems).map { i in
            """
            {"id":"pkg-\(i)","name":"Paquete \(i)","version":"1.0.\(i)","vendor":"ACME"}
            """
        }.joined(separator: ",")
        let json = """
        {
          "updatedAtUtc": "2026-09-25T10:00:00Z",
          "agentVersion": "1.1.80",
          "coreVersion": "1.1.80",
          "deviceId": "7149a30a-1181-41ed-86a7-08c7a62f20b4",
          "tenantId": "1",
          "hostname": "JPR-MacBookPro",
          "grpc": { "connected": true },
          "policy": { "version": "1789743940824", "plugins": ["amp","rcp"], "modules": [] },
          "jobs": {},
          "update": {},
          "patch": {},
          "catalog": { "items": [\(items)] }
        }
        """
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return try d.decode(TrayStatus.self, from: Data(json.utf8))
    }

    /// ⚠️ El caso REAL: el tic de 5 s corre mientras la persona navega.
    ///
    /// `render()` es lo único que mutaba la estructura de filas (el catálogo),
    /// así que si el solapamiento sale de ahí, sólo aparece cuando los dos se
    /// entrelazan — que es exactamente lo que pasa en el equipo y no en una
    /// prueba que sólo pulsa pestañas.
    func testTabsStaySeparateWhileTheFiveSecondTickRuns() throws {
        let vc = loaded()
        vc.render(try status(catalogItems: 3))
        XCTAssertEqual(visibleCount(vc), 1)

        for hop in [3, 1, 3, 0, 2, 3, 1, 0] {
            vc.selectTabForTests(hop)
            vc.render(try status(catalogItems: hop % 2 == 0 ? 3 : 0))
            vc.view.layoutSubtreeIfNeeded()
            XCTAssertEqual(visibleCount(vc), 1,
                           "pestaña \(hop) + render: tiene que quedar UNA visible")
        }
    }

    /// Deja el popover en el estado de la captura y lo escribe a PNG para
    /// poder mirarlo en vez de deducirlo.
    func testSnapshotAfterCatalogRoundTrip() throws {
        let vc = loaded()
        let repoLogo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Resources/tracenium_logo_color.png")
        vc.applyHeaderLogo(NSImage(contentsOf: repoLogo))

        vc.render(try status(catalogItems: 0))
        vc.selectTabForTests(3)               // Catalog
        vc.render(try status(catalogItems: 0))
        vc.selectTabForTests(1)               // vuelta a Agent Info
        vc.render(try status(catalogItems: 0))
        vc.view.layoutSubtreeIfNeeded()

        let view = vc.view
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            throw XCTSkip("sin bitmap")
        }
        view.cacheDisplay(in: view.bounds, to: rep)
        guard let data = rep.representation(using: .png, properties: [:]) else {
            throw XCTSkip("sin png")
        }
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracenium-tabs-after-catalog.png")
        try data.write(to: url)
        print("SNAPSHOT tabs -> \(url.path)")
    }

    func testExactlyOneTabIsVisibleAfterEveryHop() throws {
        let vc = loaded()
        XCTAssertEqual(bodyScrolls(vc).count, 4, "cuatro pestañas, cuatro scrollviews")
        XCTAssertEqual(visibleCount(vc), 1, "al abrir, sólo Device Info")

        // El recorrido de la captura: ida a Catalog y vuelta.
        for hop in [3, 1, 3, 0, 2, 3, 1] {
            vc.selectTabForTests(hop)
            XCTAssertEqual(visibleCount(vc), 1,
                           "tras ir a la pestaña \(hop) tiene que quedar UNA visible")
        }
    }

    /// Y la prueba de que el detector mira algo: si se fuerzan dos visibles, se
    /// tiene que ver.
    func testTheCheckWouldCatchAnOverlap() throws {
        let vc = loaded()
        let scrolls = bodyScrolls(vc)
        scrolls[0].isHidden = false
        scrolls[1].isHidden = false
        XCTAssertGreaterThan(visibleCount(vc), 1)
    }
}
