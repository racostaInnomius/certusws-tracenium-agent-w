// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/BrowserPolicyListShape.cs
//
// La parte SIN Windows de las listas de extensiones de Chrome y Edge
// (ExtensionInstallBlocklist / ExtensionInstallAllowlist). Ver
// BrowserPolicyList.cs para la lectura y escritura reales, y
// src/domain/extension-policy.ts en el agente para el plan.
//
// ── Por qué este primitivo es estrecho a propósito ───────────────────
//
// El PrivSvc corre como LocalSystem y escribe HKLM. Este método NO es un
// escritor de registro: sólo conoce cuatro claves fijas, sólo escribe
// valores numerados "1".."N" de tipo REG_SZ, y cada cadena que escribe tiene
// que ser un id de extensión válido, `*` en la blocklist, o una entrada que
// YA estaba en la lista (lo que puso una GPO se conserva tal cual, pero no se
// puede colar un texto nuevo cualquiera).
//
// Y escribe sólo si la lista sigue siendo la que el agente leyó (`expected`):
// si alguien la tocó entre la lectura y la escritura, devuelve `conflict` y
// el agente vuelve a planificar en la siguiente pasada.

using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class BrowserPolicyListShape
{
    public const int MaxEntries = 1000;
    public const int MaxEntryLength = 512;

    private static readonly Regex ExtensionId = new("^[a-p]{32}$", RegexOptions.CultureInvariant);

    /// <summary>(navegador, lista) → subclave bajo HKLM. Null si no es una de las cuatro.</summary>
    public static string? KeyFor(string? browser, string? list)
    {
        var suffix = list switch
        {
            "blocklist" => "ExtensionInstallBlocklist",
            "allowlist" => "ExtensionInstallAllowlist",
            _ => null
        };
        if (suffix is null) return null;
        return browser switch
        {
            "chrome" => $@"SOFTWARE\Policies\Google\Chrome\{suffix}",
            "edge" => $@"SOFTWARE\Policies\Microsoft\Edge\{suffix}",
            _ => null
        };
    }

    /// <summary>"7" → 7. "07", "0", "-1", "a" → null: Chromium sólo lee enteros canónicos desde 1.</summary>
    public static int? IndexOf(string name)
    {
        if (!int.TryParse(name, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n)) return null;
        if (n < 1 || n.ToString(System.Globalization.CultureInfo.InvariantCulture) != name) return null;
        return n;
    }

    /// <summary>
    /// Los valores numerados, en orden numérico. Sólo cadenas: un valor de otro
    /// tipo bajo esa clave no es una entrada que Chromium lea.
    /// </summary>
    public static List<string> OrderedEntries(IEnumerable<(string Name, object? Value)> values)
    {
        return values
            .Select(v => (Index: IndexOf(v.Name), v.Value))
            .Where(v => v.Index is not null && v.Value is string)
            .OrderBy(v => v.Index)
            .Select(v => (string)v.Value!)
            .ToList();
    }

    public static string? StringParam(Dictionary<string, object>? p, string name)
    {
        if (p is null || !p.TryGetValue(name, out var raw) || raw is null) return null;
        if (raw is JsonElement el) return el.ValueKind == JsonValueKind.String ? el.GetString() : null;
        return raw as string;
    }

    /// <summary>Lista de cadenas; null si el parámetro falta o no es una lista de cadenas.</summary>
    public static List<string>? ListParam(Dictionary<string, object>? p, string name)
    {
        if (p is null || !p.TryGetValue(name, out var raw) || raw is null) return null;
        var list = new List<string>();
        if (raw is JsonElement el)
        {
            if (el.ValueKind != JsonValueKind.Array) return null;
            foreach (var item in el.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) return null;
                list.Add(item.GetString()!);
            }
            return list;
        }
        if (raw is IEnumerable<object> seq)
        {
            foreach (var item in seq)
            {
                if (item is not string s) return null;
                list.Add(s);
            }
            return list;
        }
        return null;
    }

    /// <summary>
    /// Null si `next` se puede escribir; si no, el motivo. Cada entrada es un id
    /// válido, `*` (sólo blocklist) o algo que ya estaba en `current`.
    /// </summary>
    public static string? RejectReason(string list, IReadOnlyList<string> next, IReadOnlyList<string> current)
    {
        if (next.Count > MaxEntries) return $"too many entries ({next.Count} > {MaxEntries})";
        var existing = new HashSet<string>(current, StringComparer.Ordinal);
        foreach (var entry in next)
        {
            if (entry.Length == 0 || entry.Length > MaxEntryLength) return "empty or oversized entry";
            if (existing.Contains(entry)) continue;
            if (ExtensionId.IsMatch(entry)) continue;
            if (entry == "*" && list == "blocklist") continue;
            return $"not an extension id: {entry}";
        }
        return null;
    }

    /// <summary>Nombres numerados que sobran tras escribir `count` entradas ("1".."count").</summary>
    public static List<string> NamesToDelete(IEnumerable<string> existingNames, int count)
    {
        return existingNames.Where(n => IndexOf(n) is int i && i > count).ToList();
    }
}
