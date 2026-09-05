// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SeceditShape.cs
//
// La parte SIN Windows del lector de directiva local: cómo se parsea el
// INI que escribe `secedit /export` y cómo se convierte en evidencia.
// Vive aparte de SecurityCompliance.cs por la misma razón que
// RegistryProbeShape.cs: el proyecto de pruebas es net8.0 multiplataforma.
//
// ── Qué hay en el export ─────────────────────────────────────────────
//
//   [System Access]      PasswordHistorySize = 24, LockoutBadCount = 5,
//                        NewAdministratorName = "Administrator", …
//                        Los 1.x y varios 2.3.x de CIS Windows.
//   [Privilege Rights]   SeDebugPrivilege = *S-1-5-32-544,*S-1-5-21-…
//                        Los 2.2.x. Un derecho que NO aparece no está
//                        asignado a nadie: por eso se OMITE, y el
//                        catálogo dice `onMissing: "pass"` en los
//                        "is set to 'No One'".
//   [Registry Values]    MACHINE\…\Lsa\LimitBlankPasswordUse=4,1
//                        Se ignoran: ésos ya los lee RegistryProbes.
//
// ── Por qué SIDs → nombres aquí y no en el backend ───────────────────
//
// CIS escribe "Administrators, LOCAL SERVICE, NETWORK SERVICE". El SID de
// un grupo de dominio o local sólo se resuelve en el equipo. Se
// reportan los dos: `privilegeRights` con nombres (lo que compara el
// catálogo) y `privilegeRightsSids` con lo crudo (lo que un auditor
// necesita para no fiarse del nombre). Un SID que no resuelve se deja
// tal cual en la lista de nombres: mejor un "S-1-5-21-…" visible que un
// hueco.
//
// Las claves del INI son estables entre idiomas (`net accounts` las
// localiza; secedit no) — es lo que ya sostenía passwordPolicy.

using System.Globalization;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class SeceditShape
{
    /// <summary>INI → sección → clave → valor crudo (sin comillas ni espacios).</summary>
    public static Dictionary<string, Dictionary<string, string>> ParseIni(string? text)
    {
        var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(text)) return result;

        Dictionary<string, string>? current = null;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimStart('﻿');
            if (line.Length == 0 || line.StartsWith(';')) continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                var name = line.Substring(1, line.Length - 2).Trim();
                if (!result.TryGetValue(name, out current))
                {
                    current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    result[name] = current;
                }
                continue;
            }
            if (current is null) continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line.Substring(0, eq).Trim();
            var value = line.Substring(eq + 1).Trim();
            if (key.Length == 0) continue;
            current[key] = value;
        }
        return result;
    }

    /// <summary>
    /// Evidencia para el catálogo:
    ///   systemAccess       clave → número, o cadena sin comillas
    ///   privilegeRights    SeX → nombres de cuenta (sin BUILTIN\ ni NT AUTHORITY\)
    ///   privilegeRightsSids SeX → SIDs / cadenas crudas
    /// `resolveSid` traduce "S-1-5-32-544" → "BUILTIN\Administrators"; null si
    /// no se puede.
    /// </summary>
    public static Dictionary<string, object?> Build(
        Dictionary<string, Dictionary<string, string>> ini,
        Func<string, string?> resolveSid)
    {
        var systemAccess = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (ini.TryGetValue("System Access", out var sa))
        {
            foreach (var (key, raw) in sa)
            {
                var v = raw.Trim();
                if (v.Length >= 2 && v.StartsWith('"') && v.EndsWith('"'))
                    systemAccess[key] = v.Substring(1, v.Length - 2);
                else if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
                    systemAccess[key] = n;
                else
                    systemAccess[key] = v;
            }
        }

        var rights = new Dictionary<string, string[]>(StringComparer.Ordinal);
        var rightsSids = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (ini.TryGetValue("Privilege Rights", out var pr))
        {
            foreach (var (right, raw) in pr)
            {
                var entries = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var names = new List<string>();
                var sids = new List<string>();
                foreach (var entry in entries)
                {
                    if (entry.StartsWith('*'))
                    {
                        var sid = entry.Substring(1);
                        sids.Add(sid);
                        names.Add(StripWellKnownDomain(resolveSid(sid) ?? sid));
                    }
                    else
                    {
                        sids.Add(entry);
                        names.Add(StripWellKnownDomain(entry));
                    }
                }
                rights[right] = names.ToArray();
                rightsSids[right] = sids.ToArray();
            }
        }

        return new Dictionary<string, object?>
        {
            ["available"] = true,
            ["systemAccess"] = systemAccess,
            ["privilegeRights"] = rights,
            ["privilegeRightsSids"] = rightsSids
        };
    }

    /// <summary>
    /// "BUILTIN\Administrators" → "Administrators", "NT AUTHORITY\LOCAL
    /// SERVICE" → "LOCAL SERVICE". Es como CIS los nombra. Cualquier otro
    /// dominio se conserva ("NT SERVICE\WdiServiceHost", "Window
    /// Manager\Window Manager Group", "CONTOSO\Domain Admins"): el
    /// evaluador compara también por el último segmento, así que no hace
    /// falta adivinar más aquí.
    /// </summary>
    public static string StripWellKnownDomain(string name)
    {
        foreach (var prefix in new[] { "BUILTIN\\", "NT AUTHORITY\\" })
        {
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return name.Substring(prefix.Length);
        }
        return name;
    }
}
