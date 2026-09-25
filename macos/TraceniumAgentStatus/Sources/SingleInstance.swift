import AppKit

/// Una sola bandeja por sesión de escritorio.
///
/// ── Qué pasó ────────────────────────────────────────────────────────
///
/// El 25-sep-2026, tras instalar, quedaron DOS iconos de Tracenium en la barra
/// de menús. En el log de la app, dos arranques con **7 ms de diferencia**:
///
///   [16:40:17.715] Agent status app launched
///   [16:40:17.722] Agent status app launched
///
/// Son los dos lanzadores del `postinstall` pisándose: `launchctl kickstart`
/// arranca el LaunchAgent y, acto seguido, `open -a … --args --setup` pide otra
/// para enseñar la ventana de permisos. Cada proceso crea su `NSStatusItem`,
/// así que salen dos iconos idénticos — y como el LaunchAgent lleva
/// `KeepAlive`, el duplicado se queda hasta cerrar sesión.
///
/// ── Por qué un cerrojo de fichero y no `NSRunningApplication` ───────
///
/// Lo natural sería preguntar a LaunchServices si ya hay otra instancia. Pero
/// con 7 ms de diferencia el registro de la primera puede no haber ocurrido
/// todavía: las dos preguntarían, las dos oirían «no hay nadie» y las dos se
/// quedarían. `flock` no depende de que nadie se haya registrado: la primera
/// que llega al fichero gana, y el resultado es el mismo con 7 ms o con 7
/// minutos de diferencia.
///
/// ── Y el `--setup` no se pierde ─────────────────────────────────────
///
/// La instancia que sobra no se limita a morirse: si traía `--setup`, avisa a
/// la que se queda para que abra la ventana de permisos. Lo hace con reintentos
/// porque la superviviente puede llevar milisegundos de vida y no tener aún
/// puesto el observador — el mismo margen que causó el problema.
enum SingleInstance {

    /// Aviso entre procesos: «abre la ventana de permisos».
    static let showPermissions = Notification.Name("com.certusws.tracenium.agentstatus.showPermissions")

    /// Descriptor del cerrojo. Se guarda para toda la vida del proceso: al
    /// soltarlo se liberaría el cerrojo y otra instancia podría colarse.
    private static var lockFD: Int32 = -1

    private static var lockPath: String {
        let base = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/Tracenium")
        try? FileManager.default.createDirectory(
            atPath: base, withIntermediateDirectories: true)
        return (base as NSString).appendingPathComponent("agentstatus.lock")
    }

    /// ¿Es esta la instancia que se queda?
    ///
    /// `false` ⇒ el llamante tiene que salir SIN crear icono de barra.
    static func claimPrimary() -> Bool {
        let fd = open(lockPath, O_CREAT | O_RDWR, 0o644)
        guard fd >= 0 else {
            // Sin poder abrir el fichero no se puede arbitrar. Se sigue
            // adelante: un icono duplicado es molesto, ninguno es una bandeja
            // que no existe.
            Logger.shared.warn("No se pudo abrir el cerrojo de instancia; sigo sin arbitrar")
            return true
        }
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            close(fd)
            return false
        }
        lockFD = fd
        return true
    }

    /// Le pide a la instancia viva que abra la ventana de permisos.
    ///
    /// Reintenta porque la superviviente puede estar todavía arrancando. Si
    /// nadie contesta en ese plazo se acabó igual: es preferible que no salga
    /// la ventana a dejar un segundo icono para siempre.
    static func handOffSetup(attempts: Int = 10, every: TimeInterval = 0.5) {
        var left = attempts
        func post() {
            DistributedNotificationCenter.default().postNotificationName(
                showPermissions, object: nil, userInfo: nil, deliverImmediately: true)
            left -= 1
            if left > 0 {
                DispatchQueue.main.asyncAfter(deadline: .now() + every, execute: post)
            } else {
                Logger.shared.info("Instancia duplicada: --setup entregado, saliendo")
                NSApp.terminate(nil)
            }
        }
        post()
    }
}
