import Foundation

/// Bandeja → agente: lo que la persona hizo con una «acción para el usuario»
/// (ADR-0036 D1). Es TELEMETRÍA —cuántas veces se enseñó, si pospuso, si abrió
/// Ajustes— y nunca cierra una acción: eso lo decide el agente observando el
/// estado (pulsar «Abrir Ajustes» no instala nada).
///
/// Mismo camino que CatalogInstallSink: esta app no tiene credenciales ni red;
/// escribe en SU carpeta de Application Support y el agente (root) lo recoge
/// y borra (user-action-events-watcher.ts). Se AÑADE al fichero: si el agente
/// no ha pasado todavía, los eventos se acumulan (con tope).
enum UserActionEventSink {
    enum Event: String { case shown, opened, snoozed, dismissed }

    /// Tope defensivo: un puñado de eventos al día como mucho.
    static let maxEvents = 200

    static var fileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tracenium", isDirectory: true)
        return base.appendingPathComponent("user-action-events.json")
    }

    static func record(actionIds: [String], event: Event) {
        record(actionIds: actionIds, event: event, at: Date(), to: fileURL)
    }

    /// Aparte de `record` para poder probarlo contra un fichero temporal.
    static func record(actionIds: [String], event: Event, at date: Date, to url: URL) {
        guard !actionIds.isEmpty else { return }
        let stamp = ISO8601DateFormatter().string(from: date)
        var events: [[String: String]] = []
        if let data = try? Data(contentsOf: url),
           let existing = try? JSONSerialization.jsonObject(with: data) as? [[String: String]] {
            events = existing
        }
        events += actionIds.map { ["actionId": $0, "event": event.rawValue, "atUtc": stamp] }
        if events.count > maxEvents { events = Array(events.suffix(maxEvents)) }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: events)
            try data.write(to: url, options: .atomic)
            // Legible por root (que es quien lo recoge) y por el dueño; no por el resto.
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            Logger.shared.warn("user action event not recorded: \(error.localizedDescription)")
        }
    }
}
