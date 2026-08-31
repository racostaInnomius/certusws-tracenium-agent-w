import AppKit

/// Petición de consentimiento publicada por el agente (ADR-0012).
///
/// Decodifica en modo tolerante como el resto del snapshot, con una asimetría
/// que va en la dirección segura: si falta cualquier cosa que haga falta para
/// enseñar un aviso HONESTO —el id, el texto— no se enseña nada. Un diálogo
/// que pide permiso sin decir para qué es peor que no pedirlo: obtiene un "sí"
/// que no significa nada y deja en auditoría que la persona aceptó.
struct ConsentRequest: Decodable {
    let requestId: String
    let sessionId: String
    let kind: String
    let title: String
    let lines: [String]
    let allowLabel: String
    let denyLabel: String
    let expiresAtUtc: Date?

    private enum CodingKeys: String, CodingKey {
        case requestId, sessionId, kind, title, lines, allowLabel, denyLabel, expiresAtUtc
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        requestId = ((try? c.decodeIfPresent(String.self, forKey: .requestId)) ?? nil) ?? ""
        sessionId = ((try? c.decodeIfPresent(String.self, forKey: .sessionId)) ?? nil) ?? ""
        kind = ((try? c.decodeIfPresent(String.self, forKey: .kind)) ?? nil) ?? "view"
        title = ((try? c.decodeIfPresent(String.self, forKey: .title)) ?? nil) ?? "Remote access request"
        lines = ((try? c.decodeIfPresent([String].self, forKey: .lines)) ?? nil) ?? []
        allowLabel = ((try? c.decodeIfPresent(String.self, forKey: .allowLabel)) ?? nil) ?? "Allow"
        denyLabel = ((try? c.decodeIfPresent(String.self, forKey: .denyLabel)) ?? nil) ?? "Don't allow"
        expiresAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .expiresAtUtc)) ?? nil
    }

    /// ¿Se puede enseñar este aviso con honestidad?
    var isShowable: Bool {
        !requestId.isEmpty && !lines.isEmpty
    }

    /// Una petición vencida NO se enseña.
    ///
    /// Sin esto, un fichero que quedara sin consumir —el agente reinicia
    /// mientras el diálogo está abierto— haría aparecer horas después un aviso
    /// pidiendo permiso para una sesión que ya terminó. La persona diría que sí
    /// a algo que no existe, y aprendería que estos avisos no significan nada.
    func isExpired(now: Date = Date()) -> Bool {
        guard let expiresAtUtc else { return false }
        return now >= expiresAtUtc
    }
}

/// Muestra el aviso y publica la respuesta donde el agente la busca.
enum ConsentPrompt {
    /// Petición ya atendida, para no reabrir el diálogo en cada latido del
    /// watcher mientras el agente aún no ha retirado el fichero.
    private static var handledRequestId: String?
    private static var showing = false

    static var responseURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tracenium", isDirectory: true)
        return base.appendingPathComponent("consent-response.json")
    }

    /// Atiende la petición si procede. Idempotente: llamarla en cada refresco
    /// es lo normal.
    static func handle(_ request: ConsentRequest?) {
        guard let request, request.isShowable else { return }
        guard !request.isExpired() else {
            Logger.shared.info("Consent request expired before it could be shown")
            return
        }
        guard handledRequestId != request.requestId else { return }
        // Un segundo diálogo encima del primero dejaría a la persona
        // contestando al de arriba sin ver lo que acepta debajo.
        guard !showing else { return }

        handledRequestId = request.requestId
        showing = true
        DispatchQueue.main.async { present(request) }
    }

    private static func present(_ request: ConsentRequest) {
        defer { showing = false }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = request.title
        alert.informativeText = request.lines.joined(separator: "\n")

        // ⚠️ El PRIMER botón de un NSAlert es el de por defecto: se activa con
        // Return y es donde va la mano. Aquí el primero es DENEGAR a
        // propósito. En un diálogo que concede acceso a la pantalla de alguien,
        // la opción de reposo no puede ser la que concede — un Return
        // distraído no debe regalar el control del equipo.
        alert.addButton(withTitle: request.denyLabel)
        alert.addButton(withTitle: request.allowLabel)

        // La app es .accessory (sin Dock): sin activar, el diálogo puede salir
        // detrás de la ventana en la que la persona está trabajando, y un aviso
        // que no se ve se convierte en un plazo vencido, o sea en una negativa
        // que nadie eligió. Esto SÍ roba el foco, y aquí es lo correcto: se le
        // está pidiendo una decisión.
        NSApp.activate(ignoringOtherApps: true)

        let response = alert.runModal()
        let approved = (response == .alertSecondButtonReturn)

        write(requestId: request.requestId, approved: approved)
        Logger.shared.info("Consent \(approved ? "approved" : "denied") for \(request.kind) session")
    }

    private static func write(requestId: String, approved: Bool) {
        let payload: [String: Any] = [
            "requestId": requestId,
            "decision": approved ? "approved" : "denied",
            "atUtc": ISO8601DateFormatter().string(from: Date()),
        ]
        do {
            let dir = responseURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: payload)
            try data.write(to: responseURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                  ofItemAtPath: responseURL.path)
        } catch {
            // Si no se puede escribir, el agente agota el plazo y eso cuenta
            // como negativa. Fallar hacia el "no" es la dirección correcta.
            Logger.shared.info("Failed to publish consent response: \(error.localizedDescription)")
        }
    }
}

/// Lee la petición del directorio de estado compartido.
enum ConsentRequestReader {
    static func read() -> ConsentRequest? {
        // Vive junto a tray-status.json — el mismo directorio que la app ya
        // vigila, así que la petición llega en ~150 ms sin montar otro canal.
        for statusPath in AgentStatusPaths.trayStatusCandidates() {
            let url = URL(fileURLWithPath: statusPath)
                .deletingLastPathComponent()
                .appendingPathComponent("consent-request.json")
            guard let data = try? Data(contentsOf: url) else { continue }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            if let req = try? decoder.decode(ConsentRequest.self, from: data) {
                return req
            }
        }
        return nil
    }
}
