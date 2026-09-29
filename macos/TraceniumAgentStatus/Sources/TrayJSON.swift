import Foundation

/// Cómo lee la bandeja los ficheros que escribe el agente (tray-status.json,
/// consent-request.json).
///
/// ⚠️ Por qué no `.iso8601`.
///
/// El agente escribe todas las fechas con `new Date().toISOString()`, o sea con
/// milisegundos: "2026-10-06T23:00:00.123Z". Qué hace `.iso8601` con eso
/// depende del macOS en el que corre la bandeja, no del SDK con el que se
/// compiló: el JSONDecoder de Swift vive en el sistema. En macOS 27 lo acepta
/// (parsea con `Date.ISO8601FormatStyle`); en el Foundation antiguo —macOS 12,
/// el iMac de T1— se apoyaba en `ISO8601DateFormatter` sin fracción y lo
/// rechaza. Como el modelo decodifica cada fecha con `try?`, el rechazo no
/// rompía nada visible: dejaba el campo en `nil` en silencio.
///
/// Con esto la forma que se acepta es la misma en todos los macOS.
enum TrayJSON {
    static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let c = try decoder.singleValueContainer()
            let raw = try c.decode(String.self)
            guard let date = parseIsoDate(raw) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "bad ISO 8601 date \(raw)")
            }
            return date
        }
        return decoder
    }

    /// ISO 8601 con o sin fracción de segundo.
    static func parseIsoDate(_ raw: String) -> Date? {
        withFraction.date(from: raw) ?? plain.date(from: raw)
    }

    // ISO8601DateFormatter es thread-safe; se crean una vez y no en cada fecha.
    private static let withFraction: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let plain = ISO8601DateFormatter()
}
