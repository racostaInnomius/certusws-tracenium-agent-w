// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/RevertShape.cs
//
// Deshacer un fix DEDICADO de Windows (`pmp.revert`): la parte PURA. Aquí
// se valida el `stateBefore` y se decide QUÉ hay que hacer; tocar el
// registro y lanzar PowerShell queda en PmpRemediation.HandleRevert. Sin
// Microsoft.Win32 dentro para compilarse y probarse fuera de Windows, como
// GenericWriteShape.
//
// ── Contrato ─────────────────────────────────────────────────────────
//
// params = { checkId, params: { stateBefore: {...} }, timeoutSeconds? }
//
// `stateBefore` es EXACTAMENTE el `state` que devolvió pmp.read_check_state
// para ese checkId antes del fix. Tras revertir, esa misma lectura tiene que
// devolver lo mismo en cada clave de `stateBefore`: es lo que comprueba el
// agente Node para dar el revert por aplicado. Por eso las claves y rutas
// de aquí son las MISMAS constantes que usan los handlers de ida (las
// comparten con PmpRemediation, no se copian).
//
// Los genéricos (registry/secedit/auditpol.set_value) NO pasan por aquí: el
// backend los deshace mandando otra escritura por el camino de aplicar, y
// ese camino ya tiene sus guardas.
//
// ── Por qué se valida todo antes de tocar nada ──────────────────────
//
// El `stateBefore` lo guarda nuestro backend, pero llega por la red y sale
// de una fila de base de datos: se trata como entrada no fiable. Cada clave
// se contrasta con la lista FIJA del handler y cada valor con su tipo JSON.
// Una sola cosa rara rechaza el revert entero (todo o nada, como
// ApplyGenericRegistry): un revert a medias deja el equipo en un estado que
// no es ni el de antes ni el de después, y nadie lo ha pedido.

using System.Globalization;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public enum RevertOpKind
{
    /// <summary>HKLM\SubKey:ValueName = DWORD.</summary>
    RegistrySetDword,
    /// <summary>
    /// Quitar HKLM\SubKey:ValueName. Antes del fix NO había DWORD ahí (la
    /// lectura daba null); el fix lo creó y deshacerlo es borrarlo.
    /// </summary>
    RegistryDeleteValue,
    /// <summary>Enable-WindowsOptionalFeature SMB1Protocol.</summary>
    EnableSmb1Feature,
    /// <summary>Set-NetFirewallProfile -Profile X -Enabled False.</summary>
    DisableFirewallProfile,
    /// <summary>Grant-SmbShareAccess -Name X -AccountName Everyone -AccessRight Full.</summary>
    GrantShareEveryoneFull,
}

public sealed class RevertOp
{
    public required RevertOpKind Kind { get; init; }
    /// <summary>Subclave bajo HKLM (sólo registro).</summary>
    public string? SubKey { get; init; }
    /// <summary>Nombre del valor (registro), del perfil (firewall) o del recurso compartido.</summary>
    public string? Name { get; init; }
    public int Dword { get; init; }

    public string Describe() => Kind switch
    {
        RevertOpKind.RegistrySetDword => $"{SubKey}\\{Name}={RevertShape.FormatDword(Dword)}",
        RevertOpKind.RegistryDeleteValue => $"{SubKey}\\{Name} (deleted)",
        RevertOpKind.EnableSmb1Feature => "Enable-WindowsOptionalFeature SMB1Protocol -NoRestart -All",
        RevertOpKind.DisableFirewallProfile => $"Set-NetFirewallProfile -Profile {Name} -Enabled False",
        _ => $"Grant-SmbShareAccess -Name '{Name}' -AccountName Everyone -AccessRight Full",
    };
}

public sealed class RevertPlan
{
    public List<RevertOp> Ops { get; } = new();
    public bool RequiresReboot { get; init; }
}

public static class RevertShape
{
    // ── checkIds con revert dedicado ─────────────────────────────────
    public const string LegacyTlsCheck = "windows.cryptography.legacy_tls_disabled";
    public const string WeakCiphersCheck = "windows.cryptography.weak_ciphers_disabled";
    public const string SmbV1Check = "windows.network_sharing.smbv1_disabled";
    public const string FirewallCheck = "windows.firewall.profiles_enabled";
    public const string SharesCheck = "windows.shares.no_everyone_full_control";

    // ── Constantes compartidas con los handlers de ida ───────────────
    //
    // ⚠️ PmpRemediation las usa para LEER y APLICAR. Viven aquí para que el
    // revert escriba justo donde la lectura mira: una ruta copiada que
    // divergiera daría un revert «correcto» que la verificación nunca ve.

    public const string TlsProtocolsRoot =
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    public static readonly string[] LegacyTlsProtocols = { "TLS 1.0", "TLS 1.1" };
    public static readonly string[] TlsRoles = { "Server", "Client" };
    public static readonly string[] TlsValueNames = { "Enabled", "DisabledByDefault" };

    public const string CiphersRoot =
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers";

    public static readonly string[] WeakCiphers =
    {
        "NULL",
        "DES 56/56",
        "RC2 40/128",
        "RC2 56/128",
        "RC2 128/128",
        "RC4 40/128",
        "RC4 56/128",
        "RC4 64/128",
        "RC4 128/128",
        "Triple DES 168",  // SWEET32 (3DES)
    };

    public const string LanmanServerParamsKey =
        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

    public const string SmbRegistryStateKey = "LanmanServer.SMB1";
    public const string SmbFeatureStateKey = "OptionalFeature.SMB1Protocol.Enabled";

    public static readonly string[] FirewallProfiles = { "Domain", "Private", "Public" };

    public const string SharesStateKey = "sharesWithEveryoneFullControl";
    public const string SharesQueryErrorKey = "queryError";

    /// <summary>Tope de recursos en un revert: una lista mayor no sale de una lectura real.</summary>
    public const int MaxShares = 256;

    // ── Entrada ──────────────────────────────────────────────────────

    public static bool IsSupported(string checkId) => checkId switch
    {
        LegacyTlsCheck or WeakCiphersCheck or SmbV1Check or FirewallCheck or SharesCheck => true,
        _ => false,
    };

    /// <summary>
    /// `params.params.stateBefore` de la petición IPC. Devuelve el objeto o
    /// el motivo del rechazo; nunca lanza.
    /// </summary>
    public static (JsonElement? State, string? Error) StateBeforeFromParams(Dictionary<string, object>? parameters)
    {
        if (parameters is null || !parameters.TryGetValue("params", out var raw) || raw is null)
            return (null, "params missing");
        if (raw is not JsonElement p || p.ValueKind != JsonValueKind.Object)
            return (null, "params is not an object");
        if (!p.TryGetProperty("stateBefore", out var sb) || sb.ValueKind == JsonValueKind.Null || sb.ValueKind == JsonValueKind.Undefined)
            return (null, "stateBefore missing");
        if (sb.ValueKind != JsonValueKind.Object)
            return (null, "stateBefore is not an object");
        return (sb, null);
    }

    /// <summary>
    /// checkId + stateBefore → plan. `Plan` null y `Error` null = checkId sin
    /// revert dedicado (unsupported_check); `Error` no nulo = bad_request.
    /// </summary>
    public static (RevertPlan? Plan, string? Error) Plan(string checkId, JsonElement stateBefore) => checkId switch
    {
        LegacyTlsCheck => PlanLegacyTls(stateBefore),
        WeakCiphersCheck => PlanWeakCiphers(stateBefore),
        SmbV1Check => PlanSmbV1(stateBefore),
        FirewallCheck => PlanFirewall(stateBefore),
        SharesCheck => PlanShares(stateBefore),
        _ => (null, null),
    };

    // ── 1) TLS 1.0/1.1 ───────────────────────────────────────────────

    /// <summary>Las 8 claves que emite ReadLegacyTls, en su mismo orden.</summary>
    public static IEnumerable<string> LegacyTlsKeys()
    {
        foreach (var proto in LegacyTlsProtocols)
            foreach (var role in TlsRoles)
                foreach (var value in TlsValueNames)
                    yield return $"{proto}.{role}.{value}";
    }

    public static (RevertPlan? Plan, string? Error) PlanLegacyTls(JsonElement stateBefore)
    {
        var (values, error) = ReadDwordOrNullMap(stateBefore, LegacyTlsKeys());
        if (error is not null) return (null, error);

        var plan = new RevertPlan { RequiresReboot = true }; // SCHANNEL: igual que la ida
        // Orden canónico (el de la lectura), no el del JSON: el resultado no
        // depende de cómo serializó el backend.
        foreach (var proto in LegacyTlsProtocols)
            foreach (var role in TlsRoles)
                foreach (var valueName in TlsValueNames)
                {
                    var key = $"{proto}.{role}.{valueName}";
                    if (!values!.TryGetValue(key, out var v)) continue;
                    plan.Ops.Add(RegistryOp($@"{TlsProtocolsRoot}\{proto}\{role}", valueName, v));
                }
        return (plan, null);
    }

    // ── 2) Cifrados débiles ──────────────────────────────────────────

    public static (RevertPlan? Plan, string? Error) PlanWeakCiphers(JsonElement stateBefore)
    {
        var (values, error) = ReadDwordOrNullMap(stateBefore, WeakCiphers);
        if (error is not null) return (null, error);

        var plan = new RevertPlan { RequiresReboot = true };
        foreach (var cipher in WeakCiphers)
        {
            if (!values!.TryGetValue(cipher, out var v)) continue;
            // ⚠️ "RC4 128/128" es UN nombre de subclave con barra dentro, no
            // dos niveles. Se concatena tal cual: normalizar "/" a "\" (como
            // hace GenericWriteShape con las rutas) escribiría en
            // Ciphers\RC4 128\128, que SCHANNEL no lee.
            plan.Ops.Add(RegistryOp(CiphersRoot + "\\" + cipher, "Enabled", v));
        }
        return (plan, null);
    }

    // ── 3) SMBv1 ─────────────────────────────────────────────────────

    public static (RevertPlan? Plan, string? Error) PlanSmbV1(JsonElement stateBefore)
    {
        var (entries, error) = ReadObject(stateBefore, new[] { SmbRegistryStateKey, SmbFeatureStateKey });
        if (error is not null) return (null, error);

        var plan = new RevertPlan { RequiresReboot = true };
        // El registro primero, como en la ida: es lo barato y lo que no puede
        // colgarse; la característica opcional puede tardar minutos.
        if (entries!.TryGetValue(SmbRegistryStateKey, out var reg))
        {
            var (dword, dwErr) = DwordOrNull(reg, SmbRegistryStateKey);
            if (dwErr is not null) return (null, dwErr);
            plan.Ops.Add(RegistryOp(LanmanServerParamsKey, "SMB1", dword));
        }
        if (entries.TryGetValue(SmbFeatureStateKey, out var feature))
        {
            switch (feature.ValueKind)
            {
                case JsonValueKind.True:
                    plan.Ops.Add(new RevertOp { Kind = RevertOpKind.EnableSmb1Feature });
                    break;
                case JsonValueKind.False:
                case JsonValueKind.Null:
                    // false: la ida no la cambió (ya estaba apagada). null: no se
                    // pudo leer y no hay base para encender un protocolo roto
                    // «por si acaso». En los dos casos se deja como está.
                    break;
                default:
                    return (null, $"{SmbFeatureStateKey} must be a boolean or null");
            }
        }
        return (plan, null);
    }

    // ── 4) Perfiles del firewall ─────────────────────────────────────

    public static (RevertPlan? Plan, string? Error) PlanFirewall(JsonElement stateBefore)
    {
        var (entries, error) = ReadObject(stateBefore, FirewallProfiles);
        if (error is not null) return (null, error);

        var plan = new RevertPlan { RequiresReboot = false };
        // Sólo se APAGA lo que estaba apagado. Un perfil que ya estaba
        // encendido la ida no lo tocó, y apagarlo sería abrir un equipo que
        // nadie pidió abrir.
        foreach (var profile in FirewallProfiles)
        {
            if (!entries!.TryGetValue(profile, out var v)) continue;
            if (v.ValueKind == JsonValueKind.False)
                plan.Ops.Add(new RevertOp { Kind = RevertOpKind.DisableFirewallProfile, Name = profile });
            else if (v.ValueKind != JsonValueKind.True)
                return (null, $"{profile} must be a boolean");
        }
        return (plan, null);
    }

    // ── 5) Recursos compartidos con Everyone:Full ────────────────────

    public static (RevertPlan? Plan, string? Error) PlanShares(JsonElement stateBefore)
    {
        if (stateBefore.ValueKind != JsonValueKind.Object) return (null, "stateBefore is not an object");
        // queryError: la lectura de antes no pudo enumerar. Su lista (vacía o
        // no) no es el estado de antes, y restaurar a partir de ella sería
        // inventar. Se comprueba antes que las claves para dar ESTE motivo.
        if (stateBefore.TryGetProperty(SharesQueryErrorKey, out _))
            return (null, "stateBefore has queryError: the state before the fix was not read reliably");

        var (entries, error) = ReadObject(stateBefore, new[] { SharesStateKey });
        if (error is not null) return (null, error);
        if (!entries!.TryGetValue(SharesStateKey, out var list) || list.ValueKind != JsonValueKind.Array)
            return (null, $"{SharesStateKey} must be an array of strings");

        var plan = new RevertPlan { RequiresReboot = false };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) return (null, $"{SharesStateKey} must be an array of strings");
            var name = item.GetString() ?? "";
            var nameErr = ShareNameError(name);
            if (nameErr is not null) return (null, nameErr);
            // Los nombres de recurso SMB no distinguen mayúsculas: dos entradas
            // que sólo difieren en eso son el mismo recurso.
            if (!seen.Add(name)) continue;
            if (seen.Count > MaxShares) return (null, $"more than {MaxShares} shares");
            plan.Ops.Add(new RevertOp { Kind = RevertOpKind.GrantShareEveryoneFull, Name = name });
        }
        return (plan, null);
    }

    // Caracteres que Windows no admite en un nombre de recurso compartido. Un
    // nombre con ellos no salió de Get-SmbShare, y varios (" \) romperían el
    // entrecomillado de la línea de órdenes de powershell.exe.
    private const string ShareNameForbidden = "\"/\\[]:|<>+=;,?*";

    /// <summary>
    /// Null si el nombre puede ser el de un recurso compartido real. Es la
    /// primera barrera; la segunda es que tiene que existir HOY en
    /// Get-SmbShare (PmpRemediation), y sólo se usa el nombre que devuelve él.
    /// </summary>
    public static string? ShareNameError(string name)
    {
        if (name.Length == 0) return "share name is empty";
        // 80 es el máximo de NetShareAdd; con margen no se gana nada.
        if (name.Length > 80) return "share name longer than 80 characters";
        foreach (var ch in name)
        {
            if (char.IsControl(ch)) return "share name contains a control character";
            if (ShareNameForbidden.IndexOf(ch) >= 0) return $"share name contains '{ch}'";
        }
        return null;
    }

    /// <summary>
    /// Contenido de una cadena PowerShell entre comillas simples. Se dobla la
    /// comilla simple como en el camino de Revoke, y ADEMÁS las tipográficas
    /// (‘ ’ ‚ ‛): PowerShell también cierra la cadena con ellas, y doblar sólo
    /// la ASCII dejaría escapar un nombre que las lleve. Es lo mismo que hace
    /// CodeGeneration.EscapeSingleQuotedStringContent.
    /// </summary>
    public static string EscapePsSingleQuoted(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length + 4);
        foreach (var ch in s)
        {
            if (ch is '\'' or '‘' or '’' or '‚' or '‛') sb.Append(ch);
            sb.Append(ch);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Salida de `@(Get-SmbShare ... | % Name) | ConvertTo-Json -Compress`:
    /// array, cadena suelta (un solo recurso) o vacío/"null" (ninguno). Null
    /// si no se entiende — un fallo NO puede leerse como «no hay recursos».
    /// </summary>
    public static List<string>? ParseShareNames(string? stdout)
    {
        var names = new List<string>();
        var trimmed = (stdout ?? "").Trim();
        if (trimmed.Length == 0 || trimmed == "null") return names;
        try
        {
            using var doc = JsonDocument.Parse(trimmed);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.String)
            {
                var s = root.GetString();
                if (!string.IsNullOrEmpty(s)) names.Add(s);
                return names;
            }
            if (root.ValueKind != JsonValueKind.Array) return null;
            foreach (var item in root.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) return null;
                var s = item.GetString();
                if (!string.IsNullOrEmpty(s)) names.Add(s);
            }
            return names;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reparte los recursos pedidos según lo que hay HOY: a qué se le concede
    /// (con el nombre tal y como lo devuelve Get-SmbShare), cuáles ya tienen
    /// Everyone:Full y cuáles ya no existen.
    /// </summary>
    public static (List<string> ToGrant, List<string> AlreadyGranted, List<string> Missing) ResolveShares(
        IEnumerable<string> wanted, IEnumerable<string> currentShares, IEnumerable<string> currentlyGranted)
    {
        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in currentShares) current.TryAdd(c, c);
        var granted = new HashSet<string>(currentlyGranted, StringComparer.OrdinalIgnoreCase);

        var toGrant = new List<string>();
        var already = new List<string>();
        var missing = new List<string>();
        foreach (var w in wanted)
        {
            if (!current.TryGetValue(w, out var actual)) { missing.Add(w); continue; }
            if (granted.Contains(actual)) already.Add(actual);
            else toGrant.Add(actual);
        }
        return (toGrant, already, missing);
    }

    /// <summary>
    /// exitCode del revert de recursos. Un recurso borrado desde el fix no se
    /// puede restaurar y se cuenta en stderr, pero sólo es fallo si no se
    /// pudo restaurar NINGUNO: con uno restaurado, el resto del estado de
    /// antes sí volvió. Un Grant que falla manda sobre todo lo demás.
    /// </summary>
    public const int SharesNothingRestoredExit = 6;

    public static int SharesExitCode(int restoredOrAlreadyGranted, int missing, int lastGrantFailureExit)
    {
        if (lastGrantFailureExit != 0) return lastGrantFailureExit;
        if (missing > 0 && restoredOrAlreadyGranted == 0) return SharesNothingRestoredExit;
        return 0;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    public static string FormatDword(int v) =>
        v < 0
            ? $"{v.ToString(CultureInfo.InvariantCulture)} (0x{unchecked((uint)v):X8})"
            : v.ToString(CultureInfo.InvariantCulture);

    private static RevertOp RegistryOp(string subKey, string valueName, int? value) =>
        value is int d
            ? new RevertOp { Kind = RevertOpKind.RegistrySetDword, SubKey = subKey, Name = valueName, Dword = d }
            : new RevertOp { Kind = RevertOpKind.RegistryDeleteValue, SubKey = subKey, Name = valueName };

    /// <summary>
    /// Objeto con claves de una lista fija, sin repetir. Vacío = rechazo: no
    /// hay nada que restaurar y un revert que «aplica» sin hacer nada sería
    /// un verde falso.
    /// </summary>
    private static (Dictionary<string, JsonElement>? Entries, string? Error) ReadObject(
        JsonElement stateBefore, IEnumerable<string> allowedKeys)
    {
        if (stateBefore.ValueKind != JsonValueKind.Object) return (null, "stateBefore is not an object");
        // Ordinal: son las claves exactas que emite la lectura, y la
        // verificación del agente las compara tal cual.
        var allowed = new HashSet<string>(allowedKeys, StringComparer.Ordinal);
        var entries = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var prop in stateBefore.EnumerateObject())
        {
            if (!allowed.Contains(prop.Name)) return (null, $"unexpected key '{Clip(prop.Name)}' in stateBefore");
            // Una clave repetida deja dos «antes» distintos: ¿cuál?
            if (!entries.TryAdd(prop.Name, prop.Value)) return (null, $"duplicate key '{Clip(prop.Name)}' in stateBefore");
        }
        if (entries.Count == 0) return (null, "stateBefore has no keys for this check");
        return (entries, null);
    }

    private static (Dictionary<string, int?>? Values, string? Error) ReadDwordOrNullMap(
        JsonElement stateBefore, IEnumerable<string> allowedKeys)
    {
        var (entries, error) = ReadObject(stateBefore, allowedKeys);
        if (error is not null) return (null, error);
        var values = new Dictionary<string, int?>(StringComparer.Ordinal);
        foreach (var (k, v) in entries!)
        {
            var (dword, dwErr) = DwordOrNull(v, k);
            if (dwErr is not null) return (null, dwErr);
            values[k] = dword;
        }
        return (values, null);
    }

    /// <summary>
    /// null o un entero de 32 bits CON signo. La lectura hace `GetValue(..)
    /// as int?`, así que un DWORD 0xFFFFFFFF sale como -1 y es -1 lo que hay
    /// que aceptar. 4294967295 no lo emite nunca la lectura, y aceptarlo
    /// daría un revert que escribe bien pero que la verificación ve distinto.
    /// </summary>
    private static (int? Value, string? Error) DwordOrNull(JsonElement v, string key)
    {
        if (v.ValueKind == JsonValueKind.Null) return (null, null);
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)) return (i, null);
        return (null, $"'{Clip(key)}' must be a 32-bit integer or null");
    }

    private static string Clip(string s) => s.Length <= 64 ? s : s.Substring(0, 64) + "…";
}
