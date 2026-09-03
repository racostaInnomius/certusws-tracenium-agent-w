// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/RegistryProbeShape.cs
//
// La parte SIN Windows del lector de sondas de registro: cómo se parsea
// una sonda, cómo se normaliza un valor y cómo se extrae la lista de la
// petición IPC. Vive aparte de RegistryProbes.cs por la misma razón que
// DefenderStatusShape.cs: el proyecto de pruebas es net8.0 multiplataforma
// y sólo puede compilar fuentes que no toquen Microsoft.Win32.Registry.
//
// ── El contrato que estas funciones sostienen ────────────────────────
//
//   · Sólo HKLM. El servicio corre como SYSTEM; su HKCU no es el del
//     usuario y una sonda HKCU devolvería el valor equivocado en silencio.
//   · Una sonda malformada NO se lee y NO aparece en la salida. Nunca se
//     adivina.
//   · Los valores se normalizan a lo que JSON y el evaluador del backend
//     comparan sin conversiones: número, cadena o array de cadenas.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class RegistryProbeShape
{
    /// <summary>
    /// `HKLM\Ruta\Sub\Clave:NombreDelValor` → (subclave, nombre).
    /// El separador es el ÚLTIMO ':' — la ruta no lleva dos puntos, pero
    /// conviene no depender de ello. Devuelve null ante cualquier forma
    /// que no se entienda.
    /// </summary>
    public static (string SubKey, string ValueName)? Parse(string? probe)
    {
        if (string.IsNullOrWhiteSpace(probe)) return null;
        var p = probe.Trim();
        if (!p.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)) return null;

        var sep = p.LastIndexOf(':');
        if (sep <= 5 || sep == p.Length - 1) return null;

        var subKey = p.Substring(5, sep - 5).Trim('\\');
        var valueName = p.Substring(sep + 1).Trim();
        if (subKey.Length == 0 || valueName.Length == 0) return null;
        return (subKey, valueName);
    }

    /// <summary>
    /// Lo que el registro devuelve, en una forma comparable por el
    /// evaluador con `equals` / `in_set` / `numeric_between`:
    ///   REG_DWORD / REG_QWORD → número
    ///   REG_SZ / EXPAND_SZ    → cadena
    ///   REG_MULTI_SZ          → array de cadenas
    ///   REG_BINARY            → hex en minúsculas (se reporta para poder
    ///                           diagnosticar; ningún control lo compara)
    /// null entra y sale null: la decisión de omitirlo es del llamador.
    /// </summary>
    public static object? Normalize(object? raw)
    {
        return raw switch
        {
            null => null,
            int i => i,
            long l => l,
            uint ui => (long)ui,
            ulong ul => (long)ul,
            string s => s,
            string[] arr => arr,
            byte[] bytes => Convert.ToHexString(bytes).ToLowerInvariant(),
            _ => raw.ToString()
        };
    }

    /// <summary>
    /// La lista de sondas de `params.registryProbes`. El agente la reenvía
    /// desde la policy; aquí sólo se filtra lo que no sea cadena. Sin
    /// params, o sin la clave, lista vacía.
    /// </summary>
    public static List<string> FromParams(Dictionary<string, object>? parameters)
    {
        var list = new List<string>();
        if (parameters is null || !parameters.TryGetValue("registryProbes", out var raw) || raw is null)
            return list;

        if (raw is JsonElement el && el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String && item.GetString() is { } s) list.Add(s);
            return list;
        }
        if (raw is IEnumerable<object> seq)
        {
            foreach (var item in seq)
                if (item is string s) list.Add(s);
        }
        return list;
    }
}
