import Foundation

/// Despierta un refresco en cuanto cambia el fichero de estado.
///
/// POR QUÉ EXISTE, SI YA HAY UN TIMER DE 5 SEGUNDOS
///
///   Los 5 s valen para todo lo demás que enseña esta app: que un recuento de
///   parches o una versión tarden unos segundos no le importa a nadie. El
///   indicador de "te están viendo la pantalla" (ADR-0012) es otra cosa —
///   serían hasta 5 segundos de alguien mirando ANTES de que se encienda el
///   aviso, que es exactamente el hueco que el ADR viene a cerrar.
///
///   Bajar el timer general a 500 ms costaría releer y redecodificar el
///   snapshot entero diez veces más a menudo, para siempre, en todos los Macs.
///   Esto solo despierta cuando el agente escribe.
///
/// POR QUÉ VIGILA EL DIRECTORIO Y NO EL FICHERO
///
///   El agente escribe el snapshot de forma atómica: fichero temporal y
///   rename encima. Un vnode source sobre el FICHERO sigue apuntando al inodo
///   viejo tras el primer rename — recibe `.delete` una vez y después se queda
///   mudo para siempre, que es el modo de fallo peor posible aquí: parece que
///   funciona en la primera prueba y no vuelve a disparar. Vigilar el
///   directorio sobrevive a los renames.
final class SnapshotChangeWatcher {
    private var source: DispatchSourceFileSystemObject?
    private var fd: CInt = -1
    private var debounce: DispatchWorkItem?
    private let onChange: () -> Void

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
    }

    /// Empieza a vigilar el directorio de `path`. Falla en silencio: si no se
    /// puede vigilar —permisos, el directorio aún no existe— la app sigue
    /// funcionando con el timer de 5 s. Un indicador que llega tarde es peor
    /// que uno inmediato, pero mucho mejor que una app que no arranca.
    func start(watching path: String) {
        stop()
        guard !path.isEmpty else { return }

        let dir = (path as NSString).deletingLastPathComponent
        guard !dir.isEmpty else { return }

        // O_EVTONLY: abrir solo para recibir eventos, sin contar como una
        // referencia que impida desmontar el volumen.
        fd = open(dir, O_EVTONLY)
        guard fd >= 0 else { return }

        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete],
            queue: DispatchQueue.global(qos: .utility)
        )

        src.setEventHandler { [weak self] in
            self?.scheduleRefresh()
        }
        src.setCancelHandler { [weak self] in
            guard let self, self.fd >= 0 else { return }
            close(self.fd)
            self.fd = -1
        }

        src.resume()
        source = src
    }

    func stop() {
        debounce?.cancel()
        debounce = nil
        source?.cancel()
        source = nil
    }

    /// Antirrebote. Una escritura atómica genera varios eventos de directorio
    /// (crear el temporal, renombrar, borrar); sin esto, cada snapshot costaría
    /// tres redecodificaciones completas.
    private func scheduleRefresh() {
        debounce?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.onChange()
        }
        debounce = work
        // A la cola principal: onChange toca AppKit, y los eventos del source
        // llegan en una cola de fondo.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15, execute: work)
    }

    deinit {
        stop()
    }
}
