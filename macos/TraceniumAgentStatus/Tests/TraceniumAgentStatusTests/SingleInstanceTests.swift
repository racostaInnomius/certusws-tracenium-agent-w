import XCTest
import AppKit
@testable import TraceniumAgentStatus

/// 🔴 Dos iconos de Tracenium en la barra de menús (captura del usuario,
/// 25-sep-2026), y en el log dos arranques separados por 7 ms.
///
/// El `postinstall` lanza la bandeja dos veces sin querer: `launchctl kickstart`
/// para el LaunchAgent y `open --args --setup` para la ventana de permisos.
/// Cada proceso creaba su `NSStatusItem`.
///
/// Lo que se prueba aquí es que el arbitraje **no depende del tiempo**. Una
/// comprobación con `NSRunningApplication` habría pasado esta prueba y fallado
/// en el equipo, porque con 7 ms de diferencia ninguna de las dos instancias
/// está todavía registrada en LaunchServices. Un `flock` no tiene ese hueco: se
/// resuelve en el descriptor, no en un registro que llega cuando llega.
final class SingleInstanceTests: XCTestCase {

    /// ⚠️ Cerrojo propio por prueba.
    ///
    /// La primera versión usaba el de verdad, el del home. Falló en cuanto
    /// quedó viva una bandeja en este Mac: `claimPrimary()` devolvía `false`
    /// porque el producto estaba funcionando. Una prueba que se pone roja
    /// cuando la app corre no mide la invariante, mide el entorno.
    override func setUp() {
        super.setUp()
        SingleInstance.releaseForTests()
        SingleInstance.lockPathForTests = NSTemporaryDirectory()
            + "tracenium-test-\(UUID().uuidString).lock"
    }

    override func tearDown() {
        SingleInstance.releaseForTests()
        if let p = SingleInstance.lockPathForTests {
            try? FileManager.default.removeItem(atPath: p)
        }
        SingleInstance.lockPathForTests = nil
        super.tearDown()
    }

    /// `flock` va por descriptor abierto, así que un segundo `open()` del mismo
    /// proceso compite igual que lo haría otro proceso. Eso permite probar la
    /// exclusión de verdad y no una versión de juguete.
    private func secondClaimerFails() -> Bool {
        let fd = open(SingleInstance.lockPath, O_CREAT | O_RDWR, 0o644)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        return flock(fd, LOCK_EX | LOCK_NB) != 0
    }

    func testFirstClaimWinsAndSecondIsRefused() {
        XCTAssertTrue(SingleInstance.claimPrimary(),
                      "la primera instancia se queda")
        XCTAssertTrue(secondClaimerFails(),
                      "la segunda tiene que encontrarse el cerrojo cogido; "
                      + "si no, vuelven los dos iconos en la barra")
    }

    /// Y que el cerrojo siga cogido después: si `claimPrimary` cerrara el
    /// descriptor al volver, el cerrojo se soltaría y una instancia posterior
    /// —el `KeepAlive` del LaunchAgent reiniciando, por ejemplo— se colaría.
    func testTheLockIsHeldForTheLifeOfTheProcess() {
        _ = SingleInstance.claimPrimary()
        XCTAssertTrue(secondClaimerFails(), "el cerrojo se soltó al volver de claimPrimary")
        XCTAssertTrue(secondClaimerFails(), "y sigue cogido en la siguiente comprobación")
    }

    /// El cerrojo vive en el home del usuario, no en el directorio de estado:
    /// ese es de root (`drwxr-xr-x root:wheel`) y la bandeja corre como la
    /// persona, así que allí no podría ni crear el fichero.
    func testTheLockLivesWhereTheTrayCanWrite() throws {
        // Sin override: la ruta REAL, que es la que importa.
        SingleInstance.lockPathForTests = nil
        let path = SingleInstance.lockPath
        XCTAssertTrue(path.hasPrefix(NSHomeDirectory()),
                      "el cerrojo tiene que vivir en el home: el directorio de "
                      + "estado es de root y la bandeja corre como la persona")
        XCTAssertTrue(path.hasSuffix("/agentstatus.lock"))
        XCTAssertTrue(FileManager.default.isWritableFile(
            atPath: (path as NSString).deletingLastPathComponent))
    }

    /// El nombre del aviso entre procesos es parte del contrato: si cambia en
    /// un lado y no en el otro, el `--setup` se pierde en silencio y la ventana
    /// de permisos no sale nunca en una instalación sobre un equipo que ya
    /// tenía la bandeja viva.
    func testHandOffNameIsTheAgreedOne() {
        XCTAssertEqual(SingleInstance.showPermissions.rawValue,
                       "com.certusws.tracenium.agentstatus.showPermissions")
    }
}
