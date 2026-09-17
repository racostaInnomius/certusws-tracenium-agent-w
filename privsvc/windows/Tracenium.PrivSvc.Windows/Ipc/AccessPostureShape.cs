// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AccessPostureShape.cs
//
// Dos señales de acceso que faltaban para ISO 27001 / SOC 2 (P2-10 de
// SCP-VALIDACION-PROD-2026-09-16.md), extraídas para poder probarlas:
//
//   deviceJoin   a qué directorio pertenece el equipo, por `dsregcmd /status`:
//                Entra ID (AzureAdJoined), AD (DomainJoined), registrado
//                (WorkplaceJoined). El bloque `domain` sólo sabía de AD.
//   localAdmins  quién está en el grupo local de Administradores, por SID
//                (S-1-5-32-544: el nombre del grupo se traduce, "Administradores"
//                en la flota en español). Es lo que se revisa en una revisión
//                de accesos privilegiados.
//
// Mismas reglas que el resto de formas: una lectura fallida es
// { status: "unknown" } sin los campos que se evalúan, nunca "no unido" o
// "sin administradores".

using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AccessPostureShape
{
    public static Dictionary<string, object?> Unknown() => new() { ["status"] = "unknown" };

    // ── deviceJoin ───────────────────────────────────────────────────

    private static readonly Regex KeyValue = new(@"^\s*([A-Za-z]+)\s*:\s*(.*?)\s*$", RegexOptions.Compiled);

    /// <summary>
    /// `dsregcmd /status` escribe "Clave : VALOR" por líneas; las claves no se
    /// traducen. Sin la línea AzureAdJoined la salida no es la esperada: unknown.
    /// </summary>
    public static Dictionary<string, object?> ParseDsregcmd(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return Unknown();
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in output.Split('\n'))
        {
            var m = KeyValue.Match(line);
            if (!m.Success) continue;
            // La primera aparición manda: la sección de dispositivo va antes.
            values.TryAdd(m.Groups[1].Value, m.Groups[2].Value);
        }
        bool? Flag(string key) =>
            values.TryGetValue(key, out var v)
                ? v.Equals("YES", StringComparison.OrdinalIgnoreCase) ? true
                  : v.Equals("NO", StringComparison.OrdinalIgnoreCase) ? false
                  : null
                : null;

        var azure = Flag("AzureAdJoined");
        if (azure is null) return Unknown();
        var block = new Dictionary<string, object?>
        {
            ["status"] = "collected",
            ["azureAdJoined"] = azure.Value,
        };
        var domain = Flag("DomainJoined");
        if (domain.HasValue) block["domainJoined"] = domain.Value;
        var workplace = Flag("WorkplaceJoined");
        if (workplace.HasValue) block["workplaceJoined"] = workplace.Value;
        var enterprise = Flag("EnterpriseJoined");
        if (enterprise.HasValue) block["enterpriseJoined"] = enterprise.Value;
        if (values.TryGetValue("TenantName", out var tenantName) && tenantName.Length > 0) block["tenantName"] = tenantName;
        if (values.TryGetValue("TenantId", out var tenantId) && tenantId.Length > 0) block["tenantId"] = tenantId;
        // Unido a Entra ID o a AD: gestionado por un directorio.
        block["directoryJoined"] = azure.Value || domain == true;
        return block;
    }

    // ── localAdmins ──────────────────────────────────────────────────

    public const string LocalAdminsScript =
        "$sid = 'S-1-5-32-544'; $out = [pscustomobject]@{ Ok = $false; Source = $null; Members = @() }; " +
        "try { $m = Get-LocalGroupMember -SID $sid -ErrorAction Stop; " +
        "$out.Members = @($m | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Class = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource } }); " +
        "$out.Ok = $true; $out.Source = 'Get-LocalGroupMember' } " +
        // Get-LocalGroupMember falla con SIDs huérfanos en el grupo; ADSI no.
        "catch { try { $g = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[-1]; " +
        "$adsi = [ADSI](\"WinNT://./$g,group\"); " +
        "$out.Members = @($adsi.Invoke('Members') | ForEach-Object { $p = $_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null); $c = $_.GetType().InvokeMember('Class','GetProperty',$null,$_,$null); [pscustomobject]@{ Name = [string]($p -replace '^WinNT://',''); Class = [string]$c; Source = $null } }); " +
        "$out.Ok = $true; $out.Source = 'ADSI' } catch { } }; " +
        "$out | ConvertTo-Json -Depth 4";

    public static Dictionary<string, object?> ParseLocalAdmins(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unknown();
        Dictionary<string, JsonElement>? obj;
        try
        {
            obj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
        }
        catch (JsonException)
        {
            return Unknown();
        }
        if (obj == null || !obj.TryGetValue("Ok", out var ok) || ok.ValueKind != JsonValueKind.True) return Unknown();

        var members = new List<Dictionary<string, object?>>();
        if (obj.TryGetValue("Members", out var arr))
        {
            IEnumerable<JsonElement> items = arr.ValueKind == JsonValueKind.Array
                ? arr.EnumerateArray()
                : arr.ValueKind == JsonValueKind.Object ? new[] { arr } : Array.Empty<JsonElement>();
            foreach (var it in items)
            {
                var name = Str(it, "Name");
                if (string.IsNullOrWhiteSpace(name)) continue;
                members.Add(new Dictionary<string, object?>
                {
                    ["name"] = name,
                    ["class"] = Str(it, "Class"),
                    ["source"] = Str(it, "Source"),
                });
            }
        }
        return new Dictionary<string, object?>
        {
            ["status"] = "collected",
            ["source"] = obj.TryGetValue("Source", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null,
            ["count"] = members.Count,
            ["members"] = members,
        };
    }

    private static string? Str(JsonElement e, string key) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
