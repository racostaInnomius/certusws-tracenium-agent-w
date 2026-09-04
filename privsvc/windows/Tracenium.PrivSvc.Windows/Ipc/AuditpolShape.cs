// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AuditpolShape.cs
//
// La parte SIN Windows de la política de auditoría avanzada (CIS 17.x).
//
// ── Por qué `auditpol /backup` y no `auditpol /get` ──────────────────
//
// `auditpol /get /category:* /r` devuelve el ajuste como TEXTO y lo
// localiza: "Success and Failure" en inglés, "Éxito y error" en español.
// Esta flota corre Windows en español (es lo que ya obligó a secedit en
// vez de `net accounts`). `auditpol /backup /file:x.csv` escribe el mismo
// CSV con una columna más, `Setting Value`, numérica y estable:
//
//   0 = No Auditing   1 = Success   2 = Failure   3 = Success and Failure
//
// Se indexa por el GUID de la subcategoría — que es lo que el propio CIS
// cita en cada Audit: `auditpol /get /subcategory:"{0cce9235-…}"` — y se
// emite el nombre canónico en inglés, que es lo que el catálogo compara.
// El nombre localizado de la subcategoría se conserva para el humano.

using System.Globalization;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AuditpolShape
{
    public static string SettingName(int value) => value switch
    {
        0 => "No Auditing",
        1 => "Success",
        2 => "Failure",
        3 => "Success and Failure",
        _ => $"Unknown({value})"
    };

    /// <summary>
    /// CSV de `auditpol /backup` → { available, byGuid: {guid → nombre canónico},
    /// settingValue: {guid → 0..3}, subcategory: {guid → nombre local} }.
    /// null si no hay ninguna fila utilizable: el bloque NO se emite y el
    /// catálogo resuelve `not_applicable`, que es lo correcto.
    /// </summary>
    public static Dictionary<string, object?>? ParseBackupCsv(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var byGuid = new Dictionary<string, string>(StringComparer.Ordinal);
        var values = new Dictionary<string, int>(StringComparer.Ordinal);
        var names = new Dictionary<string, string>(StringComparer.Ordinal);

        string[]? header = null;
        int guidIdx = -1, valueIdx = -1, nameIdx = -1;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimStart('﻿');
            if (line.Length == 0) continue;
            var cols = SplitCsv(line);
            if (header is null)
            {
                header = cols;
                for (var i = 0; i < header.Length; i++)
                {
                    var h = header[i].Trim();
                    if (h.Equals("Subcategory GUID", StringComparison.OrdinalIgnoreCase)) guidIdx = i;
                    else if (h.Equals("Setting Value", StringComparison.OrdinalIgnoreCase)) valueIdx = i;
                    else if (h.Equals("Subcategory", StringComparison.OrdinalIgnoreCase)) nameIdx = i;
                }
                // Sin cabecera reconocible no se adivina por posición.
                if (guidIdx < 0 || valueIdx < 0) return null;
                continue;
            }
            if (cols.Length <= Math.Max(guidIdx, valueIdx)) continue;
            var guid = cols[guidIdx].Trim().Trim('{', '}').ToLowerInvariant();
            if (guid.Length != 36) continue;
            if (!int.TryParse(cols[valueIdx].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)) continue;
            byGuid[guid] = SettingName(v);
            values[guid] = v;
            if (nameIdx >= 0 && nameIdx < cols.Length) names[guid] = cols[nameIdx].Trim();
        }
        if (byGuid.Count == 0) return null;
        return new Dictionary<string, object?>
        {
            ["available"] = true,
            ["byGuid"] = byGuid,
            ["settingValue"] = values,
            ["subcategory"] = names
        };
    }

    // CSV sin comillas anidadas en la práctica; se respeta el entrecomillado
    // simple por si un nombre localizado lleva coma.
    private static string[] SplitCsv(string line)
    {
        var cols = new List<string>();
        var cur = new System.Text.StringBuilder();
        var quoted = false;
        foreach (var ch in line)
        {
            if (ch == '"') { quoted = !quoted; continue; }
            if (ch == ',' && !quoted) { cols.Add(cur.ToString()); cur.Clear(); continue; }
            cur.Append(ch);
        }
        cols.Add(cur.ToString());
        return cols.ToArray();
    }
}
