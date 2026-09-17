// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/PlatformIntegrityShape.cs
//
// Los bloques `tpm` y `secureBoot` que evalúa el control plane
// (windows.tpm.present, windows.tpm.version_2, windows.secureboot.enabled),
// extraídos de SecurityCompliance.cs para poder probarlos. Mismo motivo que
// DefenderStatusShape.cs: el proyecto de pruebas es net8.0 multiplataforma.
//
// ── Por qué ──────────────────────────────────────────────────────────
//
// Hasta el 16-sep, cualquier fallo de lectura se reportaba como la peor
// respuesta: TPM "ausente" y Secure Boot "desactivado". Un fallo de lectura
// acababa en FAIL de un control SOC 2 / ISO. Y con TPM se veía en campo: las
// máquinas QEMU de T1 mandaban `present:false` con `version:"2.0"`. La
// versión sale de Win32_Tpm, que sólo tiene instancia si hay TPM; lo que
// falló fue Get-Tpm (con -ErrorAction SilentlyContinue devolvía null, y
// `[bool]$null` es false).
//
// ── La distinción que hay que sostener ───────────────────────────────
//
//   lectura OK, no hay TPM / Secure Boot apagado → HALLAZGO, valor real.
//   BIOS legacy (Confirm-SecureBootUEFI no soportado) → Secure Boot apagado,
//                                                  que es la verdad.
//   lectura fallida                               → { status: "unknown" }
//                                                  sin los campos que se
//                                                  evalúan: not_applicable.
//
// ⚠️ "unknown" NO llama a RecordSectionError: ese error marca TODO el
// snapshot de cumplimiento como stale en el servidor, y un TPM ilegible no
// invalida el firewall ni BitLocker del mismo equipo.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class PlatformIntegrityShape
{
    /// <summary>
    /// Get-Tpm y Win32_Tpm por separado, cada uno con su éxito explícito. Un
    /// equipo sin TPM responde a Get-Tpm con TpmPresent=false y a Win32_Tpm
    /// sin instancia; ninguno de los dos lanza.
    /// </summary>
    public const string TpmScript =
        "$t = $null; $tOk = $false; try { $t = Get-Tpm -ErrorAction Stop; $tOk = ($null -ne $t) } catch { }; " +
        "$w = $null; $wOk = $false; try { $w = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1; $wOk = $true } catch { }; " +
        "[pscustomobject]@{ GetTpmOk = $tOk; Present = $t.TpmPresent; Ready = $t.TpmReady; Enabled = $t.TpmEnabled; Activated = $t.TpmActivated; " +
        "WmiOk = $wOk; WmiFound = ($null -ne $w); SpecVersion = $w.SpecVersion; WmiEnabled = $w.IsEnabled_InitialValue; WmiActivated = $w.IsActivated_InitialValue } | ConvertTo-Json -Depth 3";

    /// <summary>
    /// Confirm-SecureBootUEFI lanza PlatformNotSupportedException en BIOS
    /// legacy (0xC0000002). Se reconoce por tipo o por código, nunca por el
    /// texto: la flota corre Windows en español.
    /// </summary>
    public const string SecureBootScript =
        "$r = [pscustomobject]@{ Enabled = $null; Unsupported = $false; Failed = $false }; " +
        "try { $r.Enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } " +
        "catch { if ($_.Exception -is [System.PlatformNotSupportedException] -or $_.Exception.Message -match '0xC0000002') { $r.Unsupported = $true } else { $r.Failed = $true } }; " +
        "$r | ConvertTo-Json";

    public static Dictionary<string, object?> Unknown() => new() { ["status"] = "unknown" };

    /// <summary>El bloque `tpm` a partir de la salida de <see cref="TpmScript"/>.</summary>
    public static Dictionary<string, object?> ParseTpm(string? json)
    {
        var obj = Parse(json);
        if (obj == null) return Unknown();

        var getTpmOk = GetBool(obj, "GetTpmOk") == true;
        var wmiOk = GetBool(obj, "WmiOk") == true;
        var wmiFound = GetBool(obj, "WmiFound") == true;
        if (!getTpmOk && !wmiOk) return Unknown();

        var tpmSaysPresent = getTpmOk && GetBool(obj, "Present") == true;
        var present = tpmSaysPresent || wmiFound;
        if (!present)
        {
            // Ausencia afirmada por quien sí respondió: Get-Tpm dijo que no, o
            // WMI respondió sin instancia.
            return new() { ["present"] = false, ["ready"] = false, ["version"] = "" };
        }

        var version = "";
        var spec = GetString(obj, "SpecVersion");
        if (!string.IsNullOrWhiteSpace(spec)) version = spec.Split(',')[0].Trim();

        bool? ready;
        if (tpmSaysPresent)
        {
            ready = GetBool(obj, "Ready") == true || (GetBool(obj, "Enabled") == true && GetBool(obj, "Activated") == true);
        }
        else
        {
            // Sólo WMI: listo = habilitado y activado. Si WMI no lo dice, no se inventa.
            var en = GetBool(obj, "WmiEnabled");
            var act = GetBool(obj, "WmiActivated");
            ready = en.HasValue && act.HasValue ? en.Value && act.Value : null;
        }

        var block = new Dictionary<string, object?> { ["present"] = true, ["version"] = version };
        if (ready.HasValue) block["ready"] = ready.Value;
        else block["status"] = "partial";
        return block;
    }

    /// <summary>El bloque `secureBoot` a partir de la salida de <see cref="SecureBootScript"/>.</summary>
    public static Dictionary<string, object?> ParseSecureBoot(string? json)
    {
        var obj = Parse(json);
        if (obj == null) return Unknown();
        if (GetBool(obj, "Unsupported") == true) return new() { ["enabled"] = false, ["legacyBoot"] = true };
        if (GetBool(obj, "Failed") == true) return Unknown();
        var enabled = GetBool(obj, "Enabled");
        return enabled.HasValue ? new() { ["enabled"] = enabled.Value } : Unknown();
    }

    private static Dictionary<string, JsonElement>? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool? GetBool(Dictionary<string, JsonElement> obj, string key)
    {
        if (!obj.TryGetValue(key, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(v.GetString(), out var b) => b,
            _ => null,
        };
    }

    private static string? GetString(Dictionary<string, JsonElement> obj, string key)
    {
        if (!obj.TryGetValue(key, out var v)) return null;
        return v.ValueKind == JsonValueKind.String ? v.GetString() : v.ValueKind == JsonValueKind.Null ? null : v.ToString();
    }
}
