// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/UserRegistryProbeShape.cs
//
// La parte SIN Windows de las sondas de registro DE USUARIO (CIS 19.x,
// "User Configuration"). El servicio corre como SYSTEM: su HKCU no es el
// de nadie. Lo que sí puede leer es HKEY_USERS\<SID> de cada perfil
// cargado, y eso es lo que estas sondas recorren.
//
// ── La sonda ─────────────────────────────────────────────────────────
//
// Llega SIN hive: `Software\Microsoft\Windows\CurrentVersion\Policies\
// Attachments:SaveZoneInformation`. El catálogo la indexa como
// `registryUser.<sonda>`. Una sonda con hive (HKLM\, HKU\) o con comodín
// se rechaza: nunca se adivina.
//
// ── Cómo se agrega entre usuarios ────────────────────────────────────
//
// CIS pide la directiva PARA CADA usuario. Con N hives cargados:
//   · presente en los N con el mismo valor  → ese valor
//   · presente en los N con valores distintos → "<mixed>" (falla equals)
//   · ausente en alguno                       → OMITIDA (el catálogo dice
//                                               onMissing: fail — "no hay
//                                               política" para alguien)
//   · cero hives cargados                     → NO se emite el bloque:
//                                               sin nadie con sesión no se
//                                               puede afirmar nada, y el
//                                               catálogo resuelve
//                                               not_applicable
//
// `hives` acompaña siempre al bloque para que un auditor vea sobre
// cuántos perfiles se afirma lo que se afirma.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class UserRegistryProbeShape
{
    public const string MixedMarker = "<mixed>";

    /// <summary>`Software\Ruta:Valor` → (subclave, nombre). null si no se entiende.</summary>
    public static (string SubKey, string ValueName)? Parse(string? probe)
    {
        if (string.IsNullOrWhiteSpace(probe)) return null;
        var p = probe.Trim();
        if (p.StartsWith("HK", StringComparison.OrdinalIgnoreCase)) return null;
        if (p.StartsWith('\\') || p.IndexOfAny(new[] { '*', '?', '\r', '\n' }) >= 0) return null;
        var sep = p.LastIndexOf(':');
        if (sep <= 0 || sep == p.Length - 1) return null;
        var subKey = p.Substring(0, sep).Trim('\\');
        var valueName = p.Substring(sep + 1).Trim();
        if (subKey.Length == 0 || valueName.Length == 0 || valueName.Contains('\\')) return null;
        return (subKey, valueName);
    }

    /// <summary>`params.registryUserProbes`, sólo cadenas.</summary>
    public static List<string> FromParams(Dictionary<string, object>? parameters)
    {
        var list = new List<string>();
        if (parameters is null || !parameters.TryGetValue("registryUserProbes", out var raw) || raw is null)
            return list;
        if (raw is JsonElement el && el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String && item.GetString() is { } s) list.Add(s);
            return list;
        }
        if (raw is IEnumerable<object> seq)
            foreach (var item in seq) if (item is string s) list.Add(s);
        return list;
    }

    /// <summary>¿Es un hive de perfil de usuario? S-1-5-21-…, sin sufijo _Classes.</summary>
    public static bool IsUserProfileHive(string name)
    {
        if (name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return false;
        return System.Text.RegularExpressions.Regex.IsMatch(name, @"^S-1-5-21-\d+-\d+-\d+-\d+$");
    }

    /// <summary>
    /// perHive: hive → (sonda → valor normalizado). Sólo las sondas leídas
    /// en ese hive. Devuelve la evidencia agregada o null si no hay hives.
    /// </summary>
    public static Dictionary<string, object?>? Aggregate(
        IReadOnlyDictionary<string, Dictionary<string, object?>> perHive,
        IEnumerable<string> probes)
    {
        var hives = perHive.Count;
        if (hives == 0) return null;
        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var probe in probes)
        {
            string? first = null;
            var present = 0;
            var mixed = false;
            object? firstValue = null;
            foreach (var (_, dict) in perHive)
            {
                if (!dict.TryGetValue(probe, out var v)) continue;
                present++;
                var key = Canonical(v);
                if (first is null) { first = key; firstValue = v; }
                else if (!string.Equals(first, key, StringComparison.Ordinal)) mixed = true;
            }
            if (present < hives) continue; // ausente en alguno → omitida
            values[probe] = mixed ? MixedMarker : firstValue;
        }
        var result = new Dictionary<string, object?>(StringComparer.Ordinal) { ["hives"] = hives };
        foreach (var (k, v) in values) result[k] = v;
        return result;
    }

    private static string Canonical(object? v) => v switch
    {
        null => "null",
        string s => "s:" + s,
        string[] arr => "a:" + string.Join("", arr),
        _ => "n:" + Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)
    };
}
