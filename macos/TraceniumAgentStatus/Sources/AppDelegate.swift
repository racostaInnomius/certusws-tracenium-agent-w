import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Logger.shared.info("Agent status app launched")
        statusBarController = StatusBarController()
        statusBarController?.start()

        // `--setup` lo pasa el postinstall justo después de instalar, que es
        // cuando la persona está esperando pasos de configuración. Pedir los
        // permisos en ese momento —y no la primera vez que hacen falta, en
        // mitad de una incidencia— es toda la diferencia entre una pregunta
        // razonable y un diálogo del sistema que aparece sin contexto.
        if CommandLine.arguments.contains("--setup") {
            statusBarController?.showPermissions()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        Logger.shared.info("Agent status app terminating")
        statusBarController?.stop()
    }
}
