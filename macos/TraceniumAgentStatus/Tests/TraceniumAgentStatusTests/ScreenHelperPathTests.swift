import XCTest
@testable import TraceniumAgentStatus

/// 🔴 El botón «Allow…» de Screen sharing salía DESACTIVADO en un Mac
/// instalado (captura del usuario, 25-sep-2026: el estado decía «Unknown»).
///
/// La causa no estaba en la lógica del botón sino en una ruta escrita a mano:
/// la ventana buscaba el helper en `PrivSvc/Tracenium Screen Helper.app` y el
/// paquete lo instala en `PrivSvc/**macos**/Tracenium Screen Helper.app`. Sin
/// fichero, `screenRecordingState()` devuelve `.unknown`, y `.unknown` apaga el
/// botón a propósito (no decimos «no concedido» de algo que no sabemos). El
/// resultado es el peor posible: la única ventana que existe para conceder el
/// permiso era la única que no podía concederlo.
///
/// Una prueba que comparase la ruta con otra constante mía habría pasado con
/// las dos rutas mal. Así que la verdad se saca de **`build-macos-pkg.sh`**,
/// que es quien decide dónde aterriza el fichero: si alguien mueve el helper
/// en el script, esta prueba se pone roja aunque nadie se acuerde de esta
/// ventana.
final class ScreenHelperPathTests: XCTestCase {

    /// Raíz del repo, subiendo desde este fichero.
    private func repoRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // …/TraceniumAgentStatusTests
            .deletingLastPathComponent()   // …/Tests
            .deletingLastPathComponent()   // …/TraceniumAgentStatus
            .deletingLastPathComponent()   // …/macos
            .deletingLastPathComponent()   // raíz del repo
    }

    /// Dónde dice el script de empaquetado que vive el helper, una vez
    /// instalado. Se derivan las dos mitades:
    ///
    ///   `local app_dir="$BUILD_DIR/PrivSvc/macos/Tracenium Screen Helper.app"`
    ///   `rsync … "$BUILD_DIR/PrivSvc/" "$PKG_ROOT/Library/…/Tracenium/PrivSvc/"`
    private func installedHelperPathFromBuildScript() throws -> String {
        let script = repoRoot().appendingPathComponent("scripts/build-macos-pkg.sh")
        let text = try String(contentsOf: script, encoding: .utf8)

        // 1. El app bundle, relativo a $BUILD_DIR.
        guard let appLine = text.split(separator: "\n").first(where: {
            $0.contains("app_dir=") && $0.contains("Screen Helper.app")
        }) else {
            XCTFail("build-macos-pkg.sh ya no declara el app_dir del helper")
            throw XCTSkip("sin app_dir")
        }
        guard let start = appLine.range(of: "$BUILD_DIR/"),
              let end = appLine.range(of: ".app", range: start.upperBound..<appLine.endIndex) else {
            XCTFail("no se pudo leer la ruta del helper en: \(appLine)")
            throw XCTSkip("sin ruta")
        }
        let relative = String(appLine[start.upperBound..<end.upperBound])  // PrivSvc/macos/….app

        // 2. Dónde acaba $BUILD_DIR/PrivSvc/ en el disco del equipo.
        guard let rsync = text.split(separator: "\n").first(where: {
            $0.contains("rsync") && $0.contains("$BUILD_DIR/PrivSvc/")
        }) else {
            XCTFail("build-macos-pkg.sh ya no copia PrivSvc al pkg root")
            throw XCTSkip("sin rsync")
        }
        guard let dstStart = rsync.range(of: "$PKG_ROOT"),
              let dstEnd = rsync.range(of: "/PrivSvc/", range: dstStart.upperBound..<rsync.endIndex) else {
            XCTFail("no se pudo leer el destino de PrivSvc en: \(rsync)")
            throw XCTSkip("sin destino")
        }
        // "$PKG_ROOT/Library/Application Support/Tracenium" → sin $PKG_ROOT
        let installRoot = String(rsync[dstStart.upperBound..<dstEnd.lowerBound])

        // relative empieza por "PrivSvc/", que ya va en installRoot + "/"
        return installRoot + "/" + relative + "/Contents/MacOS/tracenium-screencap"
    }

    /// La invariante: lo que la ventana busca PRIMERO es lo que el paquete
    /// instala. No «una de las rutas vale», sino la primera — las demás son
    /// reserva para paquetes viejos y no deben tapar un error en la buena.
    func testFirstCandidateIsWhereThePackageInstallsIt() throws {
        let expected = try installedHelperPathFromBuildScript()
        XCTAssertEqual(
            PermissionsWindow.helperCandidates.first, expected,
            "La ventana busca el helper donde el paquete NO lo instala; "
            + "el botón «Allow…» saldrá desactivado en toda la flota de Macs."
        )
    }

    /// Y que la ruta vieja siga presente como reserva: un Mac con el paquete
    /// anterior todavía tiene el helper ahí, y quitarla lo dejaría sin poder
    /// conceder el permiso hasta reinstalar.
    func testLegacyPathSurvivesAsFallback() {
        XCTAssertTrue(
            PermissionsWindow.helperCandidates.contains {
                $0 == "/Library/Application Support/Tracenium/PrivSvc/"
                    + "Tracenium Screen Helper.app/Contents/MacOS/tracenium-screencap"
            },
            "sin la ruta anterior, los Macs sin reinstalar pierden el permiso"
        )
    }

    /// El orden importa: primero la actual.
    func testCandidatesAreOrderedNewestFirst() throws {
        XCTAssertEqual(PermissionsWindow.helperCandidates.count, 2)
        XCTAssertTrue(PermissionsWindow.helperCandidates[0].contains("/PrivSvc/macos/"))
        XCTAssertFalse(PermissionsWindow.helperCandidates[1].contains("/PrivSvc/macos/"))
    }

    /// 🔴 TCC le colgó el permiso de pantalla a la app equivocada.
    ///
    /// Captura del usuario, 25-sep-2026: en Ajustes › Grabación de pantalla
    /// aparecían **las dos** entradas, «Tracenium Agent Status» y «Tracenium
    /// Screen Helper», y la ventana pintaba «Not granted» sobre un helper que
    /// YA tenía el permiso concedido.
    ///
    /// Esta app no pide ese permiso en ninguna parte: lo pide el helper. Pero
    /// TCC no atribuye al binario que corre, sino a su **responsible process**,
    /// y un helper lanzado con `Process()` tiene por responsable a quien lo
    /// lanzó. Resultado: se registraba —y se consultaba— el permiso de la app
    /// de estado. Pedirlo mal y además leerlo mal, que es lo que hacía que
    /// pulsar «Allow…» no arreglara nada.
    ///
    /// La única salida es LaunchServices, que deja al helper como su propio
    /// responsable. Es la forma en que ya lo lanza el PrivSvc para capturar de
    /// verdad (`launchctl asuser`), y por eso la entrada buena existía.
    ///
    /// Un tipo no puede sujetar esto: `Process()` compila igual de bien. Lo
    /// sujeta el texto del fichero.
    func testTheStatusAppNeverSpawnsTheHelperAsItsOwnChild() throws {
        let source = repoRoot()
            .appendingPathComponent("macos/TraceniumAgentStatus/Sources/PermissionsWindow.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        let code = text
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")

        XCTAssertFalse(
            code.contains("Process()"),
            "lanzar el helper como hijo hace que TCC registre y consulte el "
            + "permiso de ESTA app: el botón «Allow…» pide el permiso de quien "
            + "no captura, y el estado del helper se lee como el de la bandeja"
        )
        XCTAssertTrue(
            code.contains("NSWorkspace.shared.openApplication"),
            "la petición tiene que ir por LaunchServices para que el helper sea "
            + "su propio responsible process"
        )
    }

    /// Y que se lance el BUNDLE, no el ejecutable de dentro: LaunchServices
    /// solo sabe abrir apps, y la identidad que TCC ancla es la del bundle.
    func testTheAppBundleIsWhatGetsLaunched() throws {
        let exe = PermissionsWindow.helperCandidates[0]
        let app = URL(fileURLWithPath: exe)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        XCTAssertEqual(app.pathExtension, "app",
                       "la ruta candidata ya no cuelga de un .app: \(app.path)")
        XCTAssertEqual(app.lastPathComponent, "Tracenium Screen Helper.app")
    }

    /// El helper tiene que saber escribir su respuesta a fichero: por
    /// LaunchServices se pierde stdout, así que sin `--out` no hay forma de
    /// leer el estado con la atribución correcta.
    func testTheHelperCanReportThroughAFile() throws {
        let helper = repoRoot()
            .appendingPathComponent("privsvc/macos/helpers/screencap/main.swift")
        let text = try String(contentsOf: helper, encoding: .utf8)
        XCTAssertTrue(text.contains("\"--out\""),
                      "sin --out, el estado solo viaja por stdout y stdout se "
                      + "pierde al lanzar por LaunchServices")
    }
}
