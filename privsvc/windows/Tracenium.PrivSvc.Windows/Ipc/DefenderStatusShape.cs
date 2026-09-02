// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/DefenderStatusShape.cs
//
// La forma del bloque `defender` que viaja al control plane, extraída de
// SecurityCompliance.cs para poder probarla.
//
// ── Por qué existe este fichero ──────────────────────────────────────
//
// Aquí vivía un bug que estuvo escondiendo equipos sin antivirus.
// `GetDefenderStatus` hacía:
//
//     if (!svcEnabled) return new { status = "not_present" };
//
// — sin `serviceEnabled`, sin `realTimeProtectionEnabled` y sin
// `antivirusEnabled`, que es justo lo que el catálogo evalúa
// (`all_equal` sobre los tres). El backend veía "path not reported" y
// resolvía `not_applicable`, que queda FUERA del numerador Y del
// denominador del score.
//
// Medido en producción el 2026-09-02 (T111): 38 de 50 equipos con el
// antimalware sin confirmar puntuaban exactamente igual que los 12
// protegidos. Un equipo sin antivirus salía gratis.
//
// ── La distinción que hay que sostener ───────────────────────────────
//
//   lectura OK + servicio apagado  → HALLAZGO. Los campos viajan con su
//                                    valor real (false). El control
//                                    falla, que es la verdad.
//   lectura fallida                → AUSENCIA. status "unknown" y nada
//                                    más; el control no se puede juzgar.
//
// Es la misma regla que el colector de screenLock ya aplicaba bien:
// "no configurado" y "no pude leerlo" son cosas distintas y sólo la
// segunda justifica el silencio.
//
// Se aísla en un fichero propio, y no como método privado, porque
// Tracenium.PrivSvc.Windows compila para net10.0-windows y el proyecto
// de pruebas es net8.0 multiplataforma: sólo puede incluir fuentes que
// no dependan de Windows. Mismo patrón que CryptoKeyNames.cs.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class DefenderStatusShape
{
    /// <summary>
    /// Construye el bloque `defender` a partir del diccionario ya
    /// parseado de `Get-MpComputerStatus`.
    ///
    /// `null` significa que la lectura no produjo nada utilizable — el
    /// llamador devuelve `status = "unknown"` y omite los campos, que es
    /// la única situación en la que omitirlos es correcto.
    /// </summary>
    public static Dictionary<string, object?>? FromComputerStatus(Dictionary<string, object>? obj)
    {
        if (obj == null) return null;

        var rtEnabled = GetBool(obj, "RealTimeProtectionEnabled") ?? false;
        var svcEnabled = GetBool(obj, "AMServiceEnabled") ?? false;

        // El estado se nombra desde lo que se leyó, no desde lo que se
        // esperaba encontrar. "not_present" describe el servicio; los
        // campos de abajo describen la evidencia, y van SIEMPRE.
        var status = !svcEnabled
            ? "not_present"
            : rtEnabled ? "enabled" : "disabled";

        return new Dictionary<string, object?>
        {
            ["status"] = status,
            ["realTimeProtectionEnabled"] = rtEnabled,
            ["serviceEnabled"] = svcEnabled,
            ["antivirusEnabled"] = GetBool(obj, "AntivirusEnabled"),
            ["productVersion"] = GetString(obj, "AMProductVersion"),
            ["engineVersion"] = GetString(obj, "AMEngineVersion"),
            ["signatureVersion"] = GetString(obj, "AntivirusSignatureVersion"),
            ["antispywareSignatureVersion"] = GetString(obj, "AntispywareSignatureVersion"),
            ["lastQuickScanUtc"] = GetDateString(obj, "QuickScanEndTime"),
            ["lastFullScanUtc"] = GetDateString(obj, "FullScanEndTime"),
        };
    }

    // Copias locales de los helpers de SecurityCompliance.cs. Se duplican
    // a propósito: moverlos allí obligaría a incluir el fichero entero en
    // el proyecto de pruebas, y ese depende de Windows.
    internal static string? GetString(Dictionary<string, object> obj, string key)
    {
        if (!obj.TryGetValue(key, out var value) || value == null) return null;
        if (value is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.Null || je.ValueKind == JsonValueKind.Undefined) return null;
            return je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
        }

        return value.ToString();
    }

    internal static bool? GetBool(Dictionary<string, object> obj, string key)
    {
        var value = GetString(obj, key);
        if (bool.TryParse(value, out var parsed)) return parsed;
        if (int.TryParse(value, out var number)) return number != 0;
        return null;
    }

    internal static string? GetDateString(Dictionary<string, object> obj, string key)
    {
        var value = GetString(obj, key);
        if (DateTime.TryParse(value, out var parsed))
            return parsed.ToUniversalTime().ToString("o");
        return value;
    }
}
