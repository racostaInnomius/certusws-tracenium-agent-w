import Foundation

/// Canal bandeja → núcleo para CORTAR una sesión de control remoto desde el
/// equipo del usuario (ADR-0012).
///
/// Mismo camino mediado por fichero que `CatalogInstallSink` y por el mismo
/// motivo: esta app corre en la sesión del usuario, sin credenciales ni red
/// propias, y el demonio root sondea nuestro Application Support.
///
/// La diferencia está en el ritmo del otro lado: el catálogo se sondea cada
/// 5 s y esto cada 500 ms mientras haya sesión viva. No es un capricho — es la
/// distancia entre pulsar "detener" y dejar de ser observado. Cinco segundos
/// ahí se perciben como que el botón no funciona, y esa es exactamente la
/// sensación que un control de privacidad no puede permitirse.
enum RemoteSessionRevokeSink {
    static var fileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tracenium", isDirectory: true)
        return base.appendingPathComponent("remote-session-revoke.json")
    }

    /// Pide cortar la sesión indicada.
    ///
    /// Lleva el sessionId a propósito: sin él, un fichero que quedara sin
    /// consumir mataría la SIGUIENTE sesión nada más abrirse, y el operador
    /// vería una desconexión sin causa aparente. El agente compara y descarta
    /// lo que no corresponda.
    static func write(sessionId: String) {
        guard !sessionId.isEmpty else { return }

        let payload: [String: Any] = [
            "sessionId": sessionId,
            "atUtc": ISO8601DateFormatter().string(from: Date()),
            // Para el registro de auditoría: el corte lo pidió una persona en
            // el endpoint, no un fallo de red. Que esos dos casos se distingan
            // es la mitad del valor de tener el control.
            "by": NSUserName(),
        ]

        do {
            let dir = fileURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: payload)
            // .atomic: el agente sondea dos veces por segundo y no puede
            // toparse con un fichero a medio escribir. Aquí importa más que en
            // el catálogo, porque un JSON corrupto en este canal significa un
            // corte que no ocurre.
            try data.write(to: fileURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                  ofItemAtPath: fileURL.path)
        } catch {
            Logger.shared.info("Failed to publish remote-session revoke: \(error.localizedDescription)")
        }
    }
}
