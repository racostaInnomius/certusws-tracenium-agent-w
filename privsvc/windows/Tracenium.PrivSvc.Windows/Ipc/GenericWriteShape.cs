// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GenericWriteShape.cs
//
// Remediación GENÉRICA de Windows: la parte PURA (parseo y validación de
// los parámetros, guardas, plantilla .inf). Sin Microsoft.Win32 dentro
// para poder compilarse y probarse fuera de Windows, como
// RegistryProbeShape. La escritura real vive en PmpRemediation.cs.
//
// ── Contrato ─────────────────────────────────────────────────────────
//
// params.params.writes = [
//   { kind:"registry", hive:"HKLM"|"HKU", keyPath:"SOFTWARE\...", valueName:"X",
//     valueType:"dword"|"sz"|"multi_sz"|"delete", value:0|"str"|["a","b"] },
//     (HKU = cada perfil de usuario cargado, sólo bajo Software\)
//   { kind:"secedit", section:"System Access", key:"MinimumPasswordLength", value:14 },
// ]
//
// Lo emite el backend (desired-state.ts) a partir del valor esperado del
// catálogo. Aquí NO se confía en él: cada escritura se valida por forma
// (hive, ruta sin "..", tipo del valor acorde a valueType, tamaños) y
// contra la MISMA lista de guardas del backend. Una guarda aquí es
// defensa en profundidad: un payload manipulado que llegara al PrivSvc no
// puede tocar LSA, RDP, WinRM, Netlogon, la firma SMB, UAC ni renombrar
// cuentas aunque el backend lo pidiera.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public enum GenericValueKind
{
    DWord,
    String,
    MultiString,
    /// <summary>
    /// Quitar el valor. ⚠️ Sin esto toda escritura era una puerta de un solo
    /// sentido: se podía fijar una política en la flota y no había forma de
    /// retirarla, ni siquiera para deshacer un error. Pasa por las MISMAS
    /// guardas que una escritura: borrar un valor de LSA rompe igual que
    /// cambiarlo.
    /// </summary>
    Delete,
}

public enum RegistryHiveKind
{
    /// <summary>HKEY_LOCAL_MACHINE: la máquina.</summary>
    LocalMachine,
    /// <summary>
    /// HKEY_USERS\S-1-5-21-* de CADA perfil cargado — lo que lee la sonda
    /// `registryUser.*` (UserRegistryProbes) y, por tanto, lo único que un
    /// fix puede hacer pasar. Un perfil sin sesión no está cargado y no se
    /// carga a propósito (`reg load` de su NTUSER.DAT lo bloquearía al
    /// iniciar sesión): ese usuario no queda cubierto hasta que entre y
    /// se vuelva a aplicar, o hasta que una GPO de usuario lo haga.
    /// </summary>
    Users,
}

public sealed class RegistryWriteSpec
{
    public RegistryHiveKind Hive { get; init; } = RegistryHiveKind.LocalMachine;
    public required string SubKey { get; init; }
    public required string ValueName { get; init; }
    public required GenericValueKind Kind { get; init; }
    public uint DwordValue { get; init; }
    public string? StringValue { get; init; }
    public string[]? MultiValue { get; init; }

    /// <summary>"HKLM" o "HKU\*" (todos los perfiles cargados) para los textos.</summary>
    public string HiveLabel => Hive == RegistryHiveKind.Users ? "HKU\\*" : "HKLM";

    public string Describe() => Kind switch
    {
        GenericValueKind.DWord => $"{HiveLabel}\\{SubKey}:{ValueName}={DwordValue}",
        GenericValueKind.String => $"{HiveLabel}\\{SubKey}:{ValueName}=\"{StringValue}\"",
        GenericValueKind.Delete => $"{HiveLabel}\\{SubKey}:{ValueName} (deleted)",
        _ =>$"{HiveLabel}\\{SubKey}:{ValueName}=[{string.Join(",", MultiValue ?? Array.Empty<string>())}]",
    };
}

public sealed class SeceditWriteSpec
{
    public required string Key { get; init; }
    /// <summary>Número o cadena, tal y como irá al .inf.</summary>
    public required string Value { get; init; }
    public bool IsNumeric { get; init; }
}

/// <summary>Subcategoría de auditoría avanzada por GUID (estable entre idiomas).</summary>
public sealed class AuditpolWriteSpec
{
    public required string Subcategory { get; init; }
    public required bool Success { get; init; }
    public required bool Failure { get; init; }
    /// <summary>Nombre canónico como lo emite AuditpolShape.SettingName.</summary>
    public string SettingName => AuditpolShape.SettingName((Success ? 1 : 0) | (Failure ? 2 : 0));
    public string Describe() => $"auditpol {{{Subcategory}}} success={(Success ? "enable" : "disable")} failure={(Failure ? "enable" : "disable")}";
}

public sealed class GenericWrites
{
    public List<RegistryWriteSpec> Registry { get; } = new();
    public List<SeceditWriteSpec> Secedit { get; } = new();
    public List<AuditpolWriteSpec> Auditpol { get; } = new();
    /// <summary>Escrituras que no pasaron la validación o la guarda, con el motivo.</summary>
    public List<string> Rejected { get; } = new();
    public bool IsEmpty => Registry.Count == 0 && Secedit.Count == 0 && Auditpol.Count == 0;
}

public static class GenericWriteShape
{
    public const int MaxWrites = 64;

    // Espejo de GUARDED_KEY_PREFIXES / GUARDED_SECEDIT_KEYS en
    // modules/patch-management/desired-state.ts del backend.
    private static readonly (string Prefix, string Reason)[] GuardedKeyPrefixes =
    {
        (@"SYSTEM\CurrentControlSet\Control\Lsa", "LSA authentication settings can break logons and domain trust"),
        (@"SYSTEM\CurrentControlSet\Control\Terminal Server", "Remote Desktop settings can lock administrators out"),
        (@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "Remote Desktop policies can lock administrators out"),
        (@"SOFTWARE\Policies\Microsoft\Windows\WinRM", "WinRM policies can break remote management"),
        (@"SYSTEM\CurrentControlSet\Services\Netlogon", "Netlogon settings can break the domain secure channel"),
        (@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation", "SMB client signing/encryption can cut access to file servers"),
        (@"SYSTEM\CurrentControlSet\Services\LanmanServer", "SMB server signing/encryption can cut clients off"),
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC and logon settings can break interactive and elevated logons"),
    };

    private static readonly Dictionary<string, string> GuardedSeceditKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["NewAdministratorName"] = "renames the built-in Administrator account",
        ["NewGuestName"] = "renames the built-in Guest account",
        ["EnableAdminAccount"] = "enables or disables the built-in Administrator account",
        ["EnableGuestAccount"] = "enables or disables the built-in Guest account",
    };

    /// <summary>Sólo [System Access] y sólo claves con nombre de identificador.</summary>
    private static readonly HashSet<string> SeceditSections = new(StringComparer.OrdinalIgnoreCase) { "System Access" };

    public static string? GuardReasonForKey(string subKey)
    {
        var k = NormalizeSubKey(subKey);
        foreach (var (prefix, reason) in GuardedKeyPrefixes)
        {
            if (k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return reason;
        }
        return null;
    }

    public static string? GuardReasonForSecedit(string key) =>
        GuardedSeceditKeys.TryGetValue(key, out var r) ? r : null;

    public static string NormalizeSubKey(string subKey) =>
        subKey.Replace('/', '\\').Trim().Trim('\\');

    /// <summary>
    /// `params.params.writes` → escrituras tipadas. Lo que no cuadra va a
    /// `Rejected` con su motivo; nunca se lanza: el llamador decide si una
    /// sola rechazada aborta el lote (sí: un check es todo o nada).
    /// </summary>
    public static GenericWrites FromParams(Dictionary<string, object>? parameters)
    {
        var out_ = new GenericWrites();
        if (parameters is null || !parameters.TryGetValue("params", out var raw) || raw is null)
        {
            out_.Rejected.Add("params missing");
            return out_;
        }
        if (raw is not JsonElement p || p.ValueKind != JsonValueKind.Object ||
            !p.TryGetProperty("writes", out var writes) || writes.ValueKind != JsonValueKind.Array)
        {
            out_.Rejected.Add("params.writes missing");
            return out_;
        }
        var n = 0;
        foreach (var w in writes.EnumerateArray())
        {
            if (++n > MaxWrites) { out_.Rejected.Add($"more than {MaxWrites} writes"); break; }
            if (w.ValueKind != JsonValueKind.Object) { out_.Rejected.Add("write is not an object"); continue; }
            var kind = Str(w, "kind");
            if (kind == "registry") ParseRegistry(w, out_);
            else if (kind == "secedit") ParseSecedit(w, out_);
            else if (kind == "auditpol") ParseAuditpol(w, out_);
            else out_.Rejected.Add($"unknown write kind '{kind}'");
        }
        return out_;
    }

    private static void ParseRegistry(JsonElement w, GenericWrites out_)
    {
        var hive = Str(w, "hive") ?? "";
        RegistryHiveKind hiveKind;
        if (hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase) ||
            hive.Equals("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
            hiveKind = RegistryHiveKind.LocalMachine;
        else if (hive.Equals("HKU", StringComparison.OrdinalIgnoreCase) ||
                 hive.Equals("HKEY_USERS", StringComparison.OrdinalIgnoreCase))
            hiveKind = RegistryHiveKind.Users;
        else
        {
            // HKCU no existe para un servicio: no hay "usuario actual". Lo que
            // hay son perfiles cargados, y eso es HKU.
            out_.Rejected.Add($"hive '{hive}' not allowed (HKLM or HKU)");
            return;
        }
        var subKey = NormalizeSubKey(Str(w, "keyPath") ?? "");
        var valueName = Str(w, "valueName") ?? "";
        if (subKey.Length == 0 || subKey.Length > 512 || subKey.Contains("..") || subKey.Contains('\0'))
        {
            out_.Rejected.Add($"keyPath '{subKey}' invalid");
            return;
        }
        if (hiveKind == RegistryHiveKind.Users &&
            !subKey.StartsWith("SOFTWARE\\", StringComparison.OrdinalIgnoreCase))
        {
            // Toda directiva de usuario vive bajo Software\. Fuera de ahí
            // (Control Panel, Environment, Keyboard Layout…) es el perfil de
            // alguien, no una política, y el catálogo nunca lo pide.
            out_.Rejected.Add($"HKU write outside Software\\ refused: {subKey}");
            return;
        }
        if (valueName.Length > 255 || valueName.Contains('\0'))
        {
            out_.Rejected.Add($"valueName invalid under {subKey}");
            return;
        }
        var guard = GuardReasonForKey(subKey);
        if (guard is not null)
        {
            out_.Rejected.Add($"guarded: {(hiveKind == RegistryHiveKind.Users ? "HKU\\*" : "HKLM")}\\{subKey} — {guard}");
            return;
        }
        var type = Str(w, "valueType") ?? "";
        if (type == "delete")
        {
            // Sin `value`: no hay nada que escribir. Si el payload lo trae, se
            // ignora — un borrado no puede convertirse en escritura por un
            // campo de más.
            out_.Registry.Add(new RegistryWriteSpec { Hive = hiveKind, SubKey = subKey, ValueName = valueName, Kind = GenericValueKind.Delete });
            return;
        }
        if (!w.TryGetProperty("value", out var v))
        {
            out_.Rejected.Add($"value missing for {subKey}:{valueName}");
            return;
        }
        switch (type)
        {
            case "dword":
                if (v.ValueKind != JsonValueKind.Number || !v.TryGetUInt32(out var d))
                {
                    out_.Rejected.Add($"dword value invalid for {subKey}:{valueName}");
                    return;
                }
                out_.Registry.Add(new RegistryWriteSpec { Hive = hiveKind, SubKey = subKey, ValueName = valueName, Kind = GenericValueKind.DWord, DwordValue = d });
                return;
            case "sz":
                if (v.ValueKind != JsonValueKind.String)
                {
                    out_.Rejected.Add($"sz value invalid for {subKey}:{valueName}");
                    return;
                }
                var s = v.GetString() ?? "";
                if (s.Length > 4096 || s.Contains('\0')) { out_.Rejected.Add($"sz value too long for {subKey}:{valueName}"); return; }
                out_.Registry.Add(new RegistryWriteSpec { Hive = hiveKind, SubKey = subKey, ValueName = valueName, Kind = GenericValueKind.String, StringValue = s });
                return;
            case "multi_sz":
                if (v.ValueKind != JsonValueKind.Array)
                {
                    out_.Rejected.Add($"multi_sz value invalid for {subKey}:{valueName}");
                    return;
                }
                var items = new List<string>();
                foreach (var it in v.EnumerateArray())
                {
                    if (it.ValueKind != JsonValueKind.String) { out_.Rejected.Add($"multi_sz item invalid for {subKey}:{valueName}"); return; }
                    var str = it.GetString() ?? "";
                    if (str.Length > 4096 || str.Contains('\0')) { out_.Rejected.Add($"multi_sz item too long for {subKey}:{valueName}"); return; }
                    items.Add(str);
                }
                if (items.Count > 256) { out_.Rejected.Add($"multi_sz too many items for {subKey}:{valueName}"); return; }
                out_.Registry.Add(new RegistryWriteSpec { Hive = hiveKind, SubKey = subKey, ValueName = valueName, Kind = GenericValueKind.MultiString, MultiValue = items.ToArray() });
                return;
            default:
                out_.Rejected.Add($"valueType '{type}' not allowed");
                return;
        }
    }

    private static readonly System.Text.RegularExpressions.Regex GuidRe =
        new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private static void ParseAuditpol(JsonElement w, GenericWrites out_)
    {
        var guid = (Str(w, "subcategory") ?? "").Trim().Trim('{', '}').ToLowerInvariant();
        if (!GuidRe.IsMatch(guid))
        {
            out_.Rejected.Add($"auditpol subcategory '{guid}' is not a GUID");
            return;
        }
        if (!w.TryGetProperty("success", out var s) || (s.ValueKind != JsonValueKind.True && s.ValueKind != JsonValueKind.False) ||
            !w.TryGetProperty("failure", out var f) || (f.ValueKind != JsonValueKind.True && f.ValueKind != JsonValueKind.False))
        {
            out_.Rejected.Add($"auditpol {guid}: success/failure must be booleans");
            return;
        }
        out_.Auditpol.Add(new AuditpolWriteSpec { Subcategory = guid, Success = s.GetBoolean(), Failure = f.GetBoolean() });
    }

    private static void ParseSecedit(JsonElement w, GenericWrites out_)
    {
        var section = Str(w, "section") ?? "";
        if (!SeceditSections.Contains(section))
        {
            out_.Rejected.Add($"secedit section '{section}' not allowed");
            return;
        }
        var key = Str(w, "key") ?? "";
        if (key.Length == 0 || key.Length > 64 || !key.All(ch => char.IsLetterOrDigit(ch) || ch == '_'))
        {
            out_.Rejected.Add($"secedit key '{key}' invalid");
            return;
        }
        var guard = GuardReasonForSecedit(key);
        if (guard is not null)
        {
            out_.Rejected.Add($"guarded: {key} — {guard}");
            return;
        }
        if (!w.TryGetProperty("value", out var v))
        {
            out_.Rejected.Add($"value missing for secedit {key}");
            return;
        }
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var num))
        {
            out_.Secedit.Add(new SeceditWriteSpec { Key = key, Value = num.ToString(), IsNumeric = true });
            return;
        }
        if (v.ValueKind == JsonValueKind.String)
        {
            var s = v.GetString() ?? "";
            if (s.Length > 256 || s.Contains('\0') || s.Contains('\n') || s.Contains('\r')) { out_.Rejected.Add($"secedit value invalid for {key}"); return; }
            out_.Secedit.Add(new SeceditWriteSpec { Key = key, Value = s, IsNumeric = false });
            return;
        }
        out_.Rejected.Add($"secedit value invalid for {key}");
    }

    /// <summary>
    /// La plantilla que traga `secedit /configure /areas SECURITYPOLICY`:
    /// sólo [System Access] con las claves pedidas. Las que no se nombran
    /// no cambian (secedit aplica lo que hay en el fichero).
    /// </summary>
    public static string RenderSeceditInf(IEnumerable<SeceditWriteSpec> writes)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[System Access]\r\n");
        foreach (var w in writes)
        {
            sb.Append(w.Key).Append(" = ");
            sb.Append(w.IsNumeric ? w.Value : "\"" + w.Value.Replace("\"", "\"\"") + "\"");
            sb.Append("\r\n");
        }
        return sb.ToString();
    }

    /// <summary>Compara lo leído del registro con lo pedido, con la normalización de las sondas.</summary>
    public static bool RegistryValueMatches(RegistryWriteSpec spec, object? normalized)
    {
        // Un borrado se cumple cuando el valor NO está. Tiene que ir antes del
        // `null → false` de abajo, que para todo lo demás es lo correcto.
        if (spec.Kind == GenericValueKind.Delete) return normalized is null;
        if (normalized is null) return false;
        switch (spec.Kind)
        {
            case GenericValueKind.DWord:
                return normalized switch
                {
                    long l => l == spec.DwordValue,
                    int i => i == spec.DwordValue,
                    uint u => u == spec.DwordValue,
                    double d => d == spec.DwordValue,
                    string s => uint.TryParse(s, out var parsed) && parsed == spec.DwordValue,
                    _ => false,
                };
            case GenericValueKind.String:
                return normalized is string str && string.Equals(str, spec.StringValue, StringComparison.Ordinal);
            default:
                if (normalized is not IEnumerable<string> seq) return false;
                var have = seq.ToArray();
                var want = spec.MultiValue ?? Array.Empty<string>();
                return have.Length == want.Length && have.Zip(want).All(p => string.Equals(p.First, p.Second, StringComparison.Ordinal));
        }
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
