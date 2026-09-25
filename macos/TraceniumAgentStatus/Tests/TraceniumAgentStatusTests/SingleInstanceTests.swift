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

    /// `flock` va por descriptor abierto, así que un segundo `open()` del mismo
    /// proceso compite igual que lo haría otro proceso. Eso permite probar la
    /// exclusión de verdad y no una versión de juguete.
    private func secondClaimerFails() -> Bool {
        let base = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/Tracenium")
        let path = (base as NSString).appendingPathComponent("agentstatus.lock")
        let fd = open(path, O_CREAT | O_RDWR, 0o644)
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
        _ = SingleInstance.claimPrimary()
        let path = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/Tracenium/agentstatus.lock")
        XCTAssertTrue(FileManager.default.fileExists(atPath: path),
                      "el cerrojo no se creó en \(path)")
        XCTAssertTrue(FileManager.default.isWritableFile(atPath: path))
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
