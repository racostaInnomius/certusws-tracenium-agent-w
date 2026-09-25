import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let wantsSetup = CommandLine.arguments.contains("--setup")

        // ⚠️ ANTES de crear nada visible. El `StatusBarController` monta su
        // `NSStatusItem` en cuanto existe, así que un segundo proceso que
        // llegue hasta aquí ya ha puesto un icono duplicado en la barra
        // aunque después decida morirse. Ver SingleInstance.
        guard SingleInstance.claimPrimary() else {
            Logger.shared.info("Ya hay una bandeja viva; esta instancia no pinta icono")
            if wantsSetup {
                SingleInstance.handOffSetup()
            } else {
                NSApp.terminate(nil)
            }
            return
        }

        Logger.shared.info("Agent status app launched")
        statusBarController = StatusBarController()
        statusBarController?.start()

        // La ventana de permisos puede pedirla otro proceso: el `--setup` que
        // lanza el postinstall llega como una instancia aparte, que se apaga
        // en cuanto delega el encargo.
        DistributedNotificationCenter.default().addObserver(
            forName: SingleInstance.showPermissions, object: nil, queue: .main
        ) { [weak self] _ in
            self?.statusBarController?.showPermissions()
        }

        // `--setup` lo pasa el postinstall justo después de instalar, que es
        // cuando la persona está esperando pasos de configuración. Pedir los
        // permisos en ese momento —y no la primera vez que hacen falta, en
        // mitad de una incidencia— es toda la diferencia entre una pregunta
        // razonable y un diálogo del sistema que aparece sin contexto.
        if wantsSetup {
            statusBarController?.showPermissions()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        Logger.shared.info("Agent status app terminating")
        statusBarController?.stop()
    }
}
