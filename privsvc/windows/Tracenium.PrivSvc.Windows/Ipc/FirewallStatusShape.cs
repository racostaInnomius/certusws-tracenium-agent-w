// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/FirewallStatusShape.cs
//
// El bloque `firewall` del snapshot de SCP: la parte PURA (leer la salida del
// script y las cadenas de regla del registro). Sin Microsoft.Win32 dentro para
// poder compilarse y probarse fuera de Windows; la lectura real vive en
// SecurityCompliance.GetFirewallStatus.
//
// 🔴 25-sep-2026 — TODA la flota Windows salía con el firewall apagado.
//
// El colector anterior hacía `Get-NetFirewallProfile | Select Name, Enabled |
// ConvertTo-Json`. `Enabled` es un enum (GpoBoolean) y Windows PowerShell 5.1
// lo serializa como NÚMERO (1 = True, 0 = False, 2 = NotConfigured). El C#
// lo leía con `bool.TryParse("1")`, que falla, y caía en `false`. Resultado en
// producción: 0 equipos en `pass` en los tres checks de perfil, en todos los
// tenants, desde el primer commit. Una consulta en vivo del registro sobre los
// Windows de T1 dio 3 de 4 con los tres perfiles encendidos.
//
// Tres reglas que salen de ahí:
//
//   1. El script convierte cada enum a TEXTO con `[string]` (los nombres de un
//      enum no se traducen: "True", "Block"), y aquí se acepta además el
//      número por si algún día llega crudo. Lo que no se entiende NO es
//      `false`: el perfil se omite y el control queda sin evaluar, nunca en
//      fail con un dato inventado.
//   2. Estado EFECTIVO (`-PolicyStore ActiveStore`): lo local mezclado con la
//      GPO. El almacén por defecto es sólo lo local, y en un equipo de
//      dominio no es lo que manda.
//   3. El firewall de otro fabricante (ESET, Kaspersky… registran uno en el
//      Centro de seguridad y apagan el de Windows a propósito) se REPORTA,
//      como el antivirus de terceros. Igual que allí (antivirus-evidence.ts
//      del backend), `productState` NO se decodifica: se afirma que hay un
//      producto registrado, no que esté encendido.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class FirewallStatusShape
{
    /// <summary>
    /// El script: perfiles efectivos y firewalls del Centro de seguridad, en
    /// UNA llamada de PowerShell. ⚠️ Una sola a propósito: el techo del
    /// colector está a pocos segundos del presupuesto del carril IPC (ver
    /// DOMAIN_IDENTITY_TIMEOUT_MS en SecurityCompliance.cs), y cada llamada
    /// nueva le suma su timeout entero en el peor caso.
    /// </summary>
    public const string Script = @"
$ErrorActionPreference = 'SilentlyContinue'
$store = 'ActiveStore'
$p = $null
try { $p = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop } catch { $store = 'PersistentStore'; $p = Get-NetFirewallProfile }
$profiles = @($p | ForEach-Object { [pscustomobject]@{
  Name = [string]$_.Name
  Enabled = [string]$_.Enabled
  DefaultInboundAction = [string]$_.DefaultInboundAction
  DefaultOutboundAction = [string]$_.DefaultOutboundAction
  AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
  LogBlocked = [string]$_.LogBlocked
  LogAllowed = [string]$_.LogAllowed
  LogFileName = [string]$_.LogFileName
} })
$sc = $false
$products = @()
try {
  $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ displayName = [string]$_.displayName; productState = [int64]$_.productState }
  })
  $sc = $true
} catch {}
[pscustomobject]@{ store = $store; profiles = $profiles; securityCenter = $sc; products = $products } | ConvertTo-Json -Depth 4 -Compress
";

    private static readonly string[] ProfileNames = { "domain", "private", "public" };

    /// <summary>Productos que son el propio firewall de Windows: no cuentan como terceros.</summary>
    private static bool IsWindowsOwn(string name) =>
        name.Contains("Windows Firewall", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Windows Defender Firewall", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Microsoft Defender Firewall", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// GpoBoolean → bool. Acepta el nombre del enum ("True"/"False"), un
    /// booleano JSON y el número (1/0). "NotConfigured" (2) y cualquier otra
    /// cosa son null: no se sabe, y no saber no es `false`.
    /// </summary>
    public static bool? ParseGpoBoolean(JsonElement v)
    {
        switch (v.ValueKind)
        {
            case JsonValueKind.True: return true;
            case JsonValueKind.False: return false;
            case JsonValueKind.Number:
                if (v.TryGetInt32(out var n)) return n == 1 ? true : n == 0 ? false : null;
                return null;
            case JsonValueKind.String:
                var s = v.GetString()?.Trim() ?? "";
                if (s.Equals("True", StringComparison.OrdinalIgnoreCase) || s == "1") return true;
                if (s.Equals("False", StringComparison.OrdinalIgnoreCase) || s == "0") return false;
                return null;
            default: return null;
        }
    }

    /// <summary>
    /// Acción por defecto → "allow" | "block" | null. El enum Action de
    /// NetSecurity vale 2 = Allow, 4 = Block, 0 = NotConfigured.
    /// </summary>
    public static string? ParseAction(JsonElement v)
    {
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n))
            return n == 2 ? "allow" : n == 4 ? "block" : null;
        if (v.ValueKind != JsonValueKind.String) return null;
        var s = v.GetString()?.Trim() ?? "";
        if (s.Equals("Allow", StringComparison.OrdinalIgnoreCase) || s == "2") return "allow";
        if (s.Equals("Block", StringComparison.OrdinalIgnoreCase) || s == "4") return "block";
        return null;
    }

    private static JsonElement Prop(JsonElement o, string name)
    {
        if (o.ValueKind != JsonValueKind.Object) return default;
        foreach (var p in o.EnumerateObject())
            if (p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) return p.Value;
        return default;
    }

    private static string? Text(JsonElement o, string name)
    {
        var v = Prop(o, name);
        if (v.ValueKind != JsonValueKind.String) return null;
        var s = v.GetString()?.Trim();
        return string.IsNullOrEmpty(s) ? null : s;
    }

    /// <summary>Lo que dice la directiva de grupo de un perfil: EnableFirewall, si está puesto.</summary>
    public sealed class GpoProfile
    {
        public bool? EnableFirewall { get; init; }
        /// <summary>Hay al menos un valor de firewall bajo la clave de directiva de este perfil.</summary>
        public bool AnyValue { get; init; }
    }

    /// <summary>
    /// La salida del script → el bloque `firewall`. Null si la salida no es
    /// un JSON con perfiles: el llamador emite `status = unknown` y el
    /// catálogo resuelve not_applicable.
    /// </summary>
    /// <param name="gpo">Directiva por perfil ("domain"/"private"/"public"), leída del registro. Puede faltar.</param>
    /// <param name="rules">Resumen de reglas (SummarizeRules), o null si no se pudo leer.</param>
    public static Dictionary<string, object?>? FromScriptOutput(
        string? output,
        IReadOnlyDictionary<string, GpoProfile>? gpo = null,
        Dictionary<string, object?>? rules = null)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;
        JsonDocument doc;
        try { doc = JsonDocument.Parse(output.Trim()); }
        catch (JsonException) { return null; }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            var rawProfiles = Prop(root, "profiles");
            var list = rawProfiles.ValueKind == JsonValueKind.Array
                ? rawProfiles.EnumerateArray().ToList()
                : rawProfiles.ValueKind == JsonValueKind.Object ? new List<JsonElement> { rawProfiles } : new List<JsonElement>();

            // `profiles` lleva SÓLO los perfiles que se pudieron leer: es lo
            // que evalúan los tres checks, y un perfil ausente es
            // not_applicable, no fail.
            var profiles = new Dictionary<string, object?>();
            var settings = new Dictionary<string, object?>();
            foreach (var p in list)
            {
                var name = Text(p, "Name")?.ToLowerInvariant();
                if (name is null || !ProfileNames.Contains(name) || settings.ContainsKey(name)) continue;
                var enabled = ParseGpoBoolean(Prop(p, "Enabled"));
                if (enabled.HasValue) profiles[name] = enabled.Value;
                GpoProfile? g = null;
                if (gpo != null) gpo.TryGetValue(name, out g);
                settings[name] = new Dictionary<string, object?>
                {
                    ["enabled"] = enabled,
                    ["defaultInboundAction"] = ParseAction(Prop(p, "DefaultInboundAction")),
                    ["defaultOutboundAction"] = ParseAction(Prop(p, "DefaultOutboundAction")),
                    ["allowLocalRules"] = ParseGpoBoolean(Prop(p, "AllowLocalFirewallRules")),
                    ["logBlocked"] = ParseGpoBoolean(Prop(p, "LogBlocked")),
                    ["logAllowed"] = ParseGpoBoolean(Prop(p, "LogAllowed")),
                    ["logFileName"] = Text(p, "LogFileName"),
                    // La directiva de dominio para este perfil. `gpoManaged`
                    // true = cualquier cambio local lo pisa la GPO en el
                    // siguiente refresco (ADR-0035 D5).
                    ["gpoEnabled"] = g?.EnableFirewall,
                    ["gpoManaged"] = g?.AnyValue ?? false,
                };
            }
            if (settings.Count == 0) return null;

            var bools = profiles.Values.OfType<bool>().ToList();
            var status = bools.Any(b => b) ? "enabled" : bools.Count > 0 ? "disabled" : "unknown";

            // Firewalls de terceros registrados en el Centro de seguridad.
            // Windows Server no tiene Centro de seguridad: ahí la lista no se
            // pudo pedir, y se dice (`thirdPartySource`). El recuento es 0 —
            // no hay nada REGISTRADO— y los controles del firewall de Windows
            // siguen aplicando, que es lo correcto en un servidor.
            var sc = Prop(root, "securityCenter").ValueKind == JsonValueKind.True;
            var names = new List<string>();
            var products = new List<Dictionary<string, object?>>();
            var rawProducts = Prop(root, "products");
            var plist = rawProducts.ValueKind == JsonValueKind.Array
                ? rawProducts.EnumerateArray().ToList()
                : rawProducts.ValueKind == JsonValueKind.Object ? new List<JsonElement> { rawProducts } : new List<JsonElement>();
            foreach (var pr in plist)
            {
                var dn = Text(pr, "displayName");
                if (dn is null) continue;
                long? state = Prop(pr, "productState").ValueKind == JsonValueKind.Number && Prop(pr, "productState").TryGetInt64(out var st) ? st : null;
                products.Add(new Dictionary<string, object?> { ["displayName"] = dn, ["productState"] = state });
                if (!IsWindowsOwn(dn) && !names.Contains(dn, StringComparer.OrdinalIgnoreCase)) names.Add(dn);
            }

            var result = new Dictionary<string, object?>
            {
                ["status"] = status,
                ["profiles"] = profiles,
                ["store"] = Text(root, "store") ?? "unknown",
                ["profileSettings"] = settings,
                ["thirdPartySource"] = sc ? "security_center" : "unavailable",
                ["thirdPartyCount"] = names.Count,
                ["thirdPartyNames"] = names,
                ["thirdPartyProducts"] = products,
            };
            if (rules != null) result["rules"] = rules;
            return result;
        }
    }

    // ── Reglas ───────────────────────────────────────────────────────────
    //
    // Se leen del REGISTRO, no de Get-NetFirewallRule: cada valor de
    //   SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
    //   SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules   (GPO)
    // es una cadena `v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|
    // Profile=Public|LPort=445|App=C:\…|Name=…|`. Formato estable y sin textos
    // traducidos, y leerla cuesta milisegundos — Get-NetFirewallRule tarda
    // segundos y no cabría en el presupuesto.
    //
    // F0 sólo resume: cuántas reglas de entrada activas permiten y bloquean,
    // y el detalle de las de BLOQUEO. Ésas son las que se aplican en cuanto el
    // firewall se enciende (Windows crea una por programa cuando un usuario
    // cancela el aviso), y son la primera cosa que puede «romper» algo.

    public const int MaxBlockRules = 50;

    public sealed class ParsedRule
    {
        public string? Action { get; init; }
        public bool Active { get; init; }
        public string? Dir { get; init; }
        public string? Protocol { get; init; }
        public List<string> LocalPorts { get; } = new();
        public List<string> Profiles { get; } = new();
        public string? App { get; init; }
        public string? Service { get; init; }
        public string? Name { get; init; }
    }

    /// <summary>Una cadena de regla → sus campos. Null si no tiene la forma `vN.M|…`.</summary>
    public static ParsedRule? ParseRule(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var parts = raw.Split('|');
        if (parts.Length < 2 || !parts[0].StartsWith("v", StringComparison.OrdinalIgnoreCase)) return null;
        string? action = null, dir = null, protocol = null, app = null, svc = null, name = null;
        var active = false;
        var ports = new List<string>();
        var profiles = new List<string>();
        foreach (var part in parts.Skip(1))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var k = part.Substring(0, eq);
            var v = part.Substring(eq + 1);
            switch (k.ToLowerInvariant())
            {
                case "action": action = v.ToLowerInvariant(); break;
                case "active": active = v.Equals("TRUE", StringComparison.OrdinalIgnoreCase); break;
                case "dir": dir = v.ToLowerInvariant(); break;
                case "protocol": protocol = ProtocolName(v); break;
                case "lport": ports.Add(v); break;
                case "profile": profiles.Add(v.ToLowerInvariant()); break;
                case "app": app = v; break;
                case "svc": svc = v; break;
                case "name": name = v; break;
            }
        }
        var rule = new ParsedRule { Action = action, Active = active, Dir = dir, Protocol = protocol, App = app, Service = svc, Name = name };
        rule.LocalPorts.AddRange(ports);
        rule.Profiles.AddRange(profiles);
        return rule;
    }

    private static string ProtocolName(string v) => v switch
    {
        "6" => "tcp",
        "17" => "udp",
        "1" => "icmpv4",
        "58" => "icmpv6",
        _ => v,
    };

    /// <summary>
    /// Las reglas crudas (origen "local"/"gpo", cadena) → el resumen que viaja
    /// en `firewall.rules`. Sólo cuentan las de ENTRADA activas.
    /// </summary>
    public static Dictionary<string, object?> SummarizeRules(IEnumerable<(string Source, string Raw)> raws)
    {
        int allow = 0, block = 0, unparsed = 0;
        var blockRules = new List<Dictionary<string, object?>>();
        var truncated = false;
        foreach (var (source, raw) in raws)
        {
            var r = ParseRule(raw);
            if (r is null) { unparsed++; continue; }
            if (!r.Active || r.Dir != "in") continue;
            if (r.Action == "allow") { allow++; continue; }
            if (r.Action != "block") continue;
            block++;
            if (blockRules.Count >= MaxBlockRules) { truncated = true; continue; }
            blockRules.Add(new Dictionary<string, object?>
            {
                ["source"] = source,
                ["name"] = r.Name,
                ["app"] = r.App,
                ["service"] = r.Service,
                ["protocol"] = r.Protocol,
                ["localPorts"] = r.LocalPorts.Count > 0 ? r.LocalPorts : null,
                // Sin `Profile=` la regla aplica a todos los perfiles.
                ["profiles"] = r.Profiles.Count > 0 ? r.Profiles : new List<string> { "all" },
            });
        }
        return new Dictionary<string, object?>
        {
            ["source"] = "registry",
            ["inboundAllow"] = allow,
            ["inboundBlock"] = block,
            ["inboundBlockRules"] = blockRules,
            ["truncated"] = truncated,
            ["unparsed"] = unparsed,
        };
    }
}
