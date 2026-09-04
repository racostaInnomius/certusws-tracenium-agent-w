// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SecurityCompliance.cs
using System.Diagnostics;
using System.Text.Json;
using System.Security.Principal;
using System.Linq;
using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class SecurityCompliance
{
    // Tracks the first section that failed (timeout or exception) during
    // a Handle() invocation so we can return a structured collectorError
    // alongside whatever partial evidence we did manage to collect.
    // Thread-local because Handle can in principle run concurrently for
    // independent IPC calls — keeping the field instance-free avoids
    // contention without forcing every helper signature to thread an
    // error sink through.
    private static readonly System.Threading.ThreadLocal<CollectorError?> _firstError =
        new(() => null);

    private sealed record CollectorError(string Phase, string Reason, string Message);

    private static void RecordSectionError(string phase, string reason, string message)
    {
        // Only record the FIRST error — subsequent failures stay in the
        // section status fields. The top-level signal is the one the
        // backend's stale-preservation gate consumes; multiple errors
        // would just clutter it.
        if (_firstError.Value is null)
        {
            _firstError.Value = new CollectorError(phase, reason, message);
        }
    }

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        _firstError.Value = null;
        try
        {
            // Computed once and shared with GetAntivirusStatus below.
            // It used to be invoked twice (top-level `defender` + again
            // inside `antivirus.defender`), which cost a redundant
            // PowerShell process — 15s of budget on a host where
            // Get-MpComputerStatus times out — for byte-identical data.
            var defender = GetDefenderStatus();

            // Claves de registro que pide el control plane (vienen en la
            // policy, el agente las reenvía en params). Lista vacía = no
            // se emite el bloque: el catálogo resuelve esos controles como
            // not_applicable, que es lo correcto para un agente que aún no
            // recibe sondas. Ver RegistryProbes.cs.
            var registryProbes = RegistryProbeShape.FromParams(req.Params);
            var probed = registryProbes.Count > 0 ? RegistryProbes.Read(registryProbes) : null;
            // Ausente = omitido (nunca null): ver la cabecera de
            // RegistryProbes.cs — un null aquí haría fallar los controles
            // "4, o que la clave no exista" en equipos que cumplen.
            var registry = probed is { Values.Count: > 0 } ? probed.Values : null;
            var registryErrors = probed is { Errors.Count: > 0 } ? probed.Errors : null;

            // Sondas de registro DE USUARIO (CIS 19.x): HKEY_USERS\<SID> de
            // cada perfil cargado, agregadas. Sin perfiles cargados no se
            // emite el bloque. Ver UserRegistryProbeShape.cs.
            var userProbes = UserRegistryProbeShape.FromParams(req.Params);
            var userProbed = userProbes.Count > 0 ? UserRegistryProbes.Read(userProbes) : null;
            var registryUser = userProbed is { Hives: > 0 }
                ? UserRegistryProbeShape.Aggregate(userProbed.PerHive, userProbes)
                : null;
            var registryUserErrors = userProbed is { Errors.Count: > 0 } ? userProbed.Errors : null;

            var result = new
            {
                bitlocker = GetBitlockerStatus(),
                defender,
                firewall = GetFirewallStatus(),
                smb = GetSmbStatus(),
                shares = GetRiskyShares(),
                antivirus = GetAntivirusStatus(defender),
                domain = GetDomainAndGpoStatus(),
                // Platform integrity — TPM + UEFI Secure Boot. Consumed by the
                // backend catalog checks windows.tpm.* / windows.secureboot.*.
                tpm = GetTpmStatus(),
                secureBoot = GetSecureBootStatus(),
                // Sprint 4 — screen lock policy (parity with macOS
                // screenLock; Linux ships gsettings/loginctl parity).
                screenLock = GetScreenLockStatus(),
                // Platform parity — local password policy (Linux ships
                // login.defs/pwquality parity). secedit export, NOT
                // `net accounts`: secedit's INI keys are locale-stable
                // while `net accounts` labels localize (this fleet runs
                // Spanish Windows).
                passwordPolicy = GetPasswordPolicyStatus(),
                // Valores de registro pedidos por el control plane, sin
                // juzgar. null cuando no se pidió ninguno — el serializador
                // omite el bloque y el evaluador ve "no reportado".
                registry,
                // Sondas que no se pudieron leer (motivo por sonda). Como
                // SYSTEM lee cualquier clave de directiva bajo HKLM, esto
                // debería ir siempre vacío; si no, es un hallazgo.
                registryErrors,
                registryUser,
                registryUserErrors,
                // Directiva local completa (secedit /export): [System Access]
                // y [Privilege Rights] — CIS 1.x, 2.2.x y parte de 2.3.x.
                // null si no se pudo exportar: el bloque no viaja y el
                // catálogo resuelve not_applicable. Ver SeceditShape.cs.
                secedit = GetSeceditPolicy(),
                // Política de auditoría avanzada (CIS 17.x), por GUID de
                // subcategoría y con el ajuste numérico estable entre
                // idiomas. Ver AuditpolShape.cs.
                auditpol = GetAuditPolicy(),
                ciphers = GetEnabledCiphers(),
                protocols = GetTlsProtocols(),
                patches = GetInstalledSecurityPatches(),
                // Top-level signal: if ANY section bailed out
                // (PowerShell timeout, COM exception, etc.), this is
                // non-null. The agent-side SCP collector propagates it
                // to `scp.collectorError`, which the backend's
                // upsertSecurityComplianceCurrent CASE uses to KEEP the
                // device's last good snapshot rather than overwriting
                // with the partial/empty payload we're returning here.
                //
                // Why include partial evidence at all (vs failing the
                // whole call): some sections may have succeeded — e.g.
                // bitlocker is fast, patches is slow. Without this
                // top-level error marker, a slow-patches host that
                // succeeded on every other check would have its OTHER
                // evidence overwritten by the backend with a snapshot
                // that included `patches.count = 0`, regressing the
                // dashboard. With this marker, the backend short-
                // circuits the overwrite entirely.
                collectorError = _firstError.Value is null
                    ? null
                    : new
                    {
                        phase = _firstError.Value.Phase,
                        reason = _firstError.Value.Reason,
                        message = _firstError.Value.Message
                    }
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "security_compliance_error", ex.Message)
            );
        }
        finally
        {
            _firstError.Value = null;
        }
    }

    private static object GetBitlockerStatus()
    {
        try
        {
            var output = RunPs(
                "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus | ConvertTo-Json -Depth 3"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { status = "unknown" };

            List<Dictionary<string, object>>? arr;

            if (output.TrimStart().StartsWith("["))
            {
                arr = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(output);
            }
            else
            {
                var single = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
                arr = single != null ? new List<Dictionary<string, object>> { single } : null;
            }

            if (arr == null || arr.Count == 0)
                return new { status = "unknown" };

            var enabledDrives = arr
                .Where(v => v.ContainsKey("VolumeStatus") &&
                            v["VolumeStatus"]?.ToString()?.Contains("FullyEncrypted") == true)
                .Select(v => v["MountPoint"]?.ToString())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();

            double coverage = 0;
            if (arr.Count > 0)
            {
                coverage = (double)enabledDrives.Count / arr.Count;
            }

            return new
            {
                status = enabledDrives.Count > 0 ? "enabled" : "disabled",
                drives = enabledDrives,
                coverage
            };
        }
        catch
        {
            return new { status = "unknown" };
        }
    }

    // ── Screen lock (Sprint 4 — platform parity) ─────────────────
    //
    // Reads the MACHINE-scoped policy the domain/MDM pushes:
    //   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    //     InactivityTimeoutSecs        — machine inactivity lock (CIS 2.3.7.4)
    //   HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop
    //     ScreenSaveActive / ScreenSaverIsSecure / ScreenSaveTimeOut
    //                                  — the per-user policy mirror GPO
    //                                    writes at machine scope
    // We do NOT read HKCU: privsvc runs as SYSTEM, so HKCU is SYSTEM's
    // hive, not the console user's — reading it would report the wrong
    // account (the same trap the macOS collector fell into with root's
    // ~/Library defaults).
    //
    // Absent ≠ compliant: every field is OMITTED when the key/value
    // isn't there, never coerced to false. The catalog rule reads
    // `screenLock.inactivityTimeoutSecs` and resolves not_applicable
    // when no policy is set — "not configured" is a real posture
    // (arguably a fail), but a failed READ must not look like it.
    private static object GetScreenLockStatus()
    {
        try
        {
            var output = RunPs(
                "$o = [ordered]@{}; " +
                "try { $v = Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name InactivityTimeoutSecs -ErrorAction Stop; $o.InactivityTimeoutSecs = [int]$v } catch {} ; " +
                "$d = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop'; " +
                "try { $o.ScreenSaveActive = ([string](Get-ItemPropertyValue -Path $d -Name ScreenSaveActive -ErrorAction Stop)) -eq '1' } catch {} ; " +
                "try { $o.ScreenSaverIsSecure = ([string](Get-ItemPropertyValue -Path $d -Name ScreenSaverIsSecure -ErrorAction Stop)) -eq '1' } catch {} ; " +
                "try { $o.ScreenSaveTimeOut = [int](Get-ItemPropertyValue -Path $d -Name ScreenSaveTimeOut -ErrorAction Stop) } catch {} ; " +
                "[pscustomobject]$o | ConvertTo-Json -Compress"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { available = false };

            var obj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(output);
            if (obj == null)
                return new { available = false };

            var result = new Dictionary<string, object?> { ["available"] = true };
            if (obj.TryGetValue("InactivityTimeoutSecs", out var it) && it.ValueKind == JsonValueKind.Number)
                result["inactivityTimeoutSecs"] = it.GetInt32();
            if (obj.TryGetValue("ScreenSaveActive", out var sa) && (sa.ValueKind == JsonValueKind.True || sa.ValueKind == JsonValueKind.False))
                result["screenSaverActive"] = sa.GetBoolean();
            if (obj.TryGetValue("ScreenSaverIsSecure", out var ss) && (ss.ValueKind == JsonValueKind.True || ss.ValueKind == JsonValueKind.False))
                result["screenSaverSecure"] = ss.GetBoolean();
            if (obj.TryGetValue("ScreenSaveTimeOut", out var st) && st.ValueKind == JsonValueKind.Number)
                result["screenSaverTimeoutSecs"] = st.GetInt32();
            return result;
        }
        catch (Exception ex)
        {
            RecordSectionError("screenLock", "read_failed", ex.Message);
            return new { available = false };
        }
    }


    // Local password policy via `secedit /export`. The [System Access]
    // INI keys are locale-independent (`net accounts` localizes its
    // labels and would silently parse nothing on non-English Windows).
    // Each field is emitted ONLY when the export carries it, so the
    // backend's absent≠compliant rule holds per attribute. secedit
    // semantics worth pinning:
    //   - MaximumPasswordAge = -1 means "never expires"; the catalog
    //     rule is numeric_between 1..365, so -1 (and 0) FAIL rather
    //     than pass a less-than.
    //   - LockoutBadCount = 0 means "never lock out" → fails the
    //     1..5 bound the same way.
    private static object GetPasswordPolicyStatus()
    {
        try
        {
            var output = RunPs(
                "$o = [ordered]@{}; " +
                "try { " +
                "$f = Join-Path $env:TEMP ('trc-secpol-' + [guid]::NewGuid().ToString('N') + '.cfg'); " +
                "secedit /export /cfg $f /quiet | Out-Null; " +
                "$t = Get-Content $f -Raw -ErrorAction Stop; Remove-Item $f -Force -ErrorAction SilentlyContinue; " +
                "if ($t -match 'MinimumPasswordLength\\s*=\\s*(\\d+)') { $o.MinimumPasswordLength = [int]$Matches[1] } ; " +
                "if ($t -match 'MaximumPasswordAge\\s*=\\s*(-?\\d+)') { $o.MaximumPasswordAge = [int]$Matches[1] } ; " +
                "if ($t -match 'PasswordComplexity\\s*=\\s*(\\d+)') { $o.PasswordComplexity = [int]$Matches[1] } ; " +
                "if ($t -match 'PasswordHistorySize\\s*=\\s*(\\d+)') { $o.PasswordHistorySize = [int]$Matches[1] } ; " +
                "if ($t -match 'LockoutBadCount\\s*=\\s*(\\d+)') { $o.LockoutBadCount = [int]$Matches[1] } " +
                "} catch {} ; " +
                "[pscustomobject]$o | ConvertTo-Json -Compress"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { available = false };

            var obj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(output);
            if (obj == null)
                return new { available = false };

            var result = new Dictionary<string, object?> { ["available"] = true };
            if (obj.TryGetValue("MinimumPasswordLength", out var ml) && ml.ValueKind == JsonValueKind.Number)
                result["minimumLength"] = ml.GetInt32();
            if (obj.TryGetValue("MaximumPasswordAge", out var ma) && ma.ValueKind == JsonValueKind.Number)
                result["maximumAgeDays"] = ma.GetInt32();
            if (obj.TryGetValue("PasswordComplexity", out var pc) && pc.ValueKind == JsonValueKind.Number)
                result["complexityEnabled"] = pc.GetInt32() == 1;
            if (obj.TryGetValue("PasswordHistorySize", out var ph) && ph.ValueKind == JsonValueKind.Number)
                result["historySize"] = ph.GetInt32();
            if (obj.TryGetValue("LockoutBadCount", out var lb) && lb.ValueKind == JsonValueKind.Number)
                result["lockoutThreshold"] = lb.GetInt32();
            return result;
        }
        catch (Exception ex)
        {
            RecordSectionError("passwordPolicy", "read_failed", ex.Message);
            return new { available = false };
        }
    }

    // ── secedit completo: [System Access] + [Privilege Rights] ──────────
    //
    // passwordPolicy (arriba) extrae cinco claves con regex; esto exporta la
    // directiva entera para los controles de CIS que no caben ahí: derechos
    // de usuario (2.2.x), cuentas (2.3.1.x) y el resto de [System Access].
    // Los SIDs de los derechos se resuelven a nombre AQUÍ, que es el único
    // sitio donde un SID local o de dominio resuelve. Null = no se emite.
    private static object? GetSeceditPolicy()
    {
        try
        {
            var text = RunPs(
                "$f = Join-Path $env:TEMP ('trc-secedit-' + [guid]::NewGuid().ToString('N') + '.cfg'); " +
                "secedit /export /cfg $f /quiet | Out-Null; " +
                "if (Test-Path $f) { Get-Content $f -Raw; Remove-Item $f -Force -ErrorAction SilentlyContinue }"
            );
            if (string.IsNullOrWhiteSpace(text)) return null;
            var ini = SeceditShape.ParseIni(text);
            if (!ini.ContainsKey("System Access") && !ini.ContainsKey("Privilege Rights")) return null;
            return SeceditShape.Build(ini, ResolveSidToName);
        }
        catch (Exception ex)
        {
            RecordSectionError("secedit", "read_failed", ex.Message);
            return null;
        }
    }

    private static string? ResolveSidToName(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            return null;
        }
    }

    // ── auditpol /backup: el ajuste numérico, no el texto localizado ──────
    private static object? GetAuditPolicy()
    {
        try
        {
            var text = RunPs(
                "$f = Join-Path $env:TEMP ('trc-auditpol-' + [guid]::NewGuid().ToString('N') + '.csv'); " +
                "auditpol /backup /file:$f | Out-Null; " +
                "if (Test-Path $f) { Get-Content $f -Raw; Remove-Item $f -Force -ErrorAction SilentlyContinue }"
            );
            return AuditpolShape.ParseBackupCsv(text);
        }
        catch (Exception ex)
        {
            RecordSectionError("auditpol", "read_failed", ex.Message);
            return null;
        }
    }

    // Platform integrity — TPM. Emits { present, ready, version } for the
    // backend catalog checks windows.tpm.present (tpm.ready) and
    // windows.tpm.version_2 (tpm.version === "2.0"). `ready` = present AND
    // enabled AND activated. `version` is the spec major.minor ("2.0" | "1.2").
    private static object GetTpmStatus()
    {
        try
        {
            var output = RunPs(
                "$t = Get-Tpm -ErrorAction SilentlyContinue; " +
                "$v = (Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion; " +
                "[pscustomobject]@{ Present = [bool]$t.TpmPresent; Ready = [bool]$t.TpmReady; Enabled = [bool]$t.TpmEnabled; Activated = [bool]$t.TpmActivated; SpecVersion = $v } | ConvertTo-Json -Depth 3"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { present = false, ready = false, version = "" };

            var obj = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
            if (obj == null)
                return new { present = false, ready = false, version = "" };

            bool present = false, ready = false, enabled = false, activated = false;
            if (obj.TryGetValue("Present", out var p)) bool.TryParse(p?.ToString(), out present);
            if (obj.TryGetValue("Ready", out var r)) bool.TryParse(r?.ToString(), out ready);
            if (obj.TryGetValue("Enabled", out var e)) bool.TryParse(e?.ToString(), out enabled);
            if (obj.TryGetValue("Activated", out var a)) bool.TryParse(a?.ToString(), out activated);

            // Win32_Tpm.SpecVersion is like "2.0, 0, 1.38" — take the leading
            // "major.minor" so the catalog can equals-match "2.0".
            string version = "";
            if (obj.TryGetValue("SpecVersion", out var sv) && sv != null)
                version = (sv.ToString() ?? "").Split(',')[0].Trim();

            return new
            {
                present,
                ready = ready || (present && enabled && activated),
                version
            };
        }
        catch
        {
            // Non-fatal: TPM absent / query blocked → report "not present" and
            // let the backend mark the checks accordingly. Don't fail the whole
            // compliance collection over one section.
            RecordSectionError("tpm", "collect_failed", "Get-Tpm / Win32_Tpm query failed");
            return new { present = false, ready = false, version = "" };
        }
    }

    // Platform integrity — UEFI Secure Boot. Emits { enabled } for the backend
    // catalog check windows.secureboot.enabled. Confirm-SecureBootUEFI throws on
    // legacy/non-UEFI systems, so we swallow that and report enabled=false.
    private static object GetSecureBootStatus()
    {
        try
        {
            var output = RunPs(
                "$e = $false; try { $e = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $e = $false }; " +
                "[pscustomobject]@{ Enabled = $e } | ConvertTo-Json"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { enabled = false };

            var obj = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
            bool enabled = false;
            if (obj != null && obj.TryGetValue("Enabled", out var en) && en != null)
                bool.TryParse(en.ToString(), out enabled);

            return new { enabled };
        }
        catch
        {
            return new { enabled = false };
        }
    }

    private static object GetDefenderStatus()
    {
        try
        {
            var output = RunPs(
                "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AMServiceEnabled, AntivirusEnabled, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntispywareSignatureVersion, QuickScanEndTime, FullScanEndTime | ConvertTo-Json -Depth 4"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { status = "unknown" };

            Dictionary<string, object>? obj;

            if (output.TrimStart().StartsWith("["))
            {
                var arr = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(output);
                obj = arr?.FirstOrDefault();
            }
            else
            {
                obj = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
            }

            if (obj != null)
            {
                bool rtEnabled = false;
                bool svcEnabled = false;

                if (obj.TryGetValue("RealTimeProtectionEnabled", out var rtVal))
                    bool.TryParse(rtVal?.ToString(), out rtEnabled);

                if (obj.TryGetValue("AMServiceEnabled", out var svcVal))
                    bool.TryParse(svcVal?.ToString(), out svcEnabled);

                if (!svcEnabled)
                    return new { status = "not_present" };

                return new
                {
                    status = rtEnabled ? "enabled" : "disabled",
                    realTimeProtectionEnabled = rtEnabled,
                    serviceEnabled = svcEnabled,
                    antivirusEnabled = GetBool(obj, "AntivirusEnabled"),
                    productVersion = GetString(obj, "AMProductVersion"),
                    engineVersion = GetString(obj, "AMEngineVersion"),
                    signatureVersion = GetString(obj, "AntivirusSignatureVersion"),
                    antispywareSignatureVersion = GetString(obj, "AntispywareSignatureVersion"),
                    lastQuickScanUtc = GetDateString(obj, "QuickScanEndTime"),
                    lastFullScanUtc = GetDateString(obj, "FullScanEndTime")
                };
            }

            return new { status = "unknown" };
        }
        catch
        {
            return new { status = "unknown" };
        }
    }

    private static object GetAntivirusStatus(object defender)
    {
        try
        {
            var securityCenterOutput = RunPs(
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName, pathToSignedProductExe, productState, timestamp | ConvertTo-Json -Depth 4"
            );

            var products = ParseJsonArray(securityCenterOutput);

            return new
            {
                defender,
                products
            };
        }
        catch
        {
            return new { status = "unknown", products = Array.Empty<object>() };
        }
    }

    private static object GetFirewallStatus()
    {
        try
        {
            var output = RunPs(
                "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Depth 3"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { status = "unknown" };

            List<Dictionary<string, object>>? arr;

            if (output.TrimStart().StartsWith("["))
            {
                arr = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(output);
            }
            else
            {
                var single = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
                arr = single != null ? new List<Dictionary<string, object>> { single } : null;
            }

            if (arr == null || arr.Count == 0)
                return new { status = "unknown" };

            var profiles = arr.ToDictionary(
                p => p.ContainsKey("Name") ? p["Name"]?.ToString()?.ToLowerInvariant() ?? "unknown" : "unknown",
                p =>
                {
                    if (p.TryGetValue("Enabled", out var v) &&
                        bool.TryParse(v?.ToString(), out var b))
                        return b;

                    return false;
                });

            var anyEnabled = profiles.Values.Any(v => v);

            return new
            {
                status = anyEnabled ? "enabled" : "disabled",
                profiles
            };
        }
        catch
        {
            return new { status = "unknown" };
        }
    }

    private static object GetSmbStatus()
    {
        try
        {
            var output = RunPs(@"
$server = $null
try { $server = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol } catch {}
$feature = $null
try { $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Select-Object FeatureName, State } catch {}
[pscustomobject]@{
  smb1Enabled = if ($server -ne $null) { [bool]$server.EnableSMB1Protocol } else { $null }
  smb2Enabled = if ($server -ne $null) { [bool]$server.EnableSMB2Protocol } else { $null }
  smb1FeatureState = if ($feature -ne $null) { [string]$feature.State } else { $null }
} | ConvertTo-Json -Depth 4
");

            var obj = ParseJsonObject(output);
            var smb1Enabled = GetBool(obj, "smb1Enabled");
            var featureState = GetString(obj, "smb1FeatureState");
            var enabledByFeature = string.Equals(featureState, "Enabled", StringComparison.OrdinalIgnoreCase);

            return new
            {
                smb1 = new
                {
                    status = smb1Enabled == true || enabledByFeature ? "enabled" : "disabled",
                    enabled = smb1Enabled,
                    featureState
                },
                smb2 = new
                {
                    enabled = GetBool(obj, "smb2Enabled")
                }
            };
        }
        catch
        {
            return new { smb1 = new { status = "unknown" }, smb2 = new { enabled = (bool?)null } };
        }
    }

    private static object GetRiskyShares()
    {
        try
        {
            var output = RunPs(@"
$shares = @()
try {
  Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object {
    $share = $_
    Get-SmbShareAccess -Name $share.Name | Where-Object {
      $_.AccessControlType -eq 'Allow' -and
      $_.AccessRight -eq 'Full' -and
      ($_.AccountName -match '(^|\\)(Everyone|Todos)$' -or $_.AccountName -eq 'Everyone' -or $_.AccountName -eq 'Todos')
    } | ForEach-Object {
      $shares += [pscustomobject]@{
        name = $share.Name
        path = $share.Path
        accountName = $_.AccountName
        accessRight = [string]$_.AccessRight
        accessControlType = [string]$_.AccessControlType
      }
    }
  }
} catch {}
[pscustomobject]@{
  riskyCount = $shares.Count
  items = $shares
} | ConvertTo-Json -Depth 6
");

            var obj = ParseJsonObject(output);
            return new
            {
                riskyCount = GetInt(obj, "riskyCount") ?? 0,
                items = obj.TryGetValue("items", out var items) ? items : Array.Empty<object>()
            };
        }
        catch
        {
            return new { riskyCount = 0, items = Array.Empty<object>(), status = "unknown" };
        }
    }

    private static object GetDomainAndGpoStatus()
    {
        try
        {
            var output = RunPs(@"
$cs = Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain, Domain
function Get-GpResultLines($scope) {
  try {
    $raw = gpresult /Scope $scope /R 2>$null
    if ($LASTEXITCODE -ne 0 -or $raw -eq $null) { return @() }
    return @($raw | ForEach-Object { [string]$_ })
  } catch { return @() }
}
[pscustomobject]@{
  partOfDomain = [bool]$cs.PartOfDomain
  domain = [string]$cs.Domain
  computer = Get-GpResultLines 'Computer'
  user = Get-GpResultLines 'User'
} | ConvertTo-Json -Depth 8
");

            var obj = ParseJsonObject(output);
            // Sprint 4 hardening: NO `raw` here. It used to ship the entire
            // gpresult /R output for BOTH scopes — the User scope carries
            // the logged-on user's name, every group they belong to and
            // the site/OU path. The catalog reads only the extracted GPO
            // lists; shipping the transcript was PII in the evidence
            // blob for no rule's benefit. (Linux has capped raw at 4 KB
            // since day one; macOS got the cap the same day as this.)
            return new
            {
                partOfDomain = GetBool(obj, "partOfDomain") ?? false,
                domain = GetString(obj, "domain"),
                appliedComputerGpos = ExtractAppliedGpos(obj, "computer"),
                appliedUserGpos = ExtractAppliedGpos(obj, "user")
            };
        }
        catch
        {
            return new { partOfDomain = false, domain = (string?)null, appliedComputerGpos = Array.Empty<string>(), appliedUserGpos = Array.Empty<string>() };
        }
    }

    private static object GetEnabledCiphers()
    {
        try
        {
            var output = RunPs(@"
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
$items = @()
if (Test-Path $base) {
  Get-ChildItem $base | ForEach-Object {
    $props = Get-ItemProperty $_.PsPath
    $enabled = $null
    if ($props.PSObject.Properties.Name -contains 'Enabled') { $enabled = [int]$props.Enabled }
    $items += [pscustomobject]@{
      name = $_.PSChildName
      enabled = if ($enabled -eq $null) { $null } else { $enabled -ne 0 }
      registryEnabled = $enabled
    }
  }
}
[pscustomobject]@{
  items = $items
} | ConvertTo-Json -Depth 5
");

            var obj = ParseJsonObject(output);
            return new
            {
                items = obj.TryGetValue("items", out var items) ? items : Array.Empty<object>()
            };
        }
        catch
        {
            return new { items = Array.Empty<object>(), status = "unknown" };
        }
    }

    private static object GetTlsProtocols()
    {
        try
        {
            var output = RunPs(@"
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$protocols = @('TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3')
$items = @()
foreach ($p in $protocols) {
  foreach ($role in @('Client','Server')) {
    $path = Join-Path $base (Join-Path $p $role)
    $enabled = $null
    $disabledByDefault = $null
    if (Test-Path $path) {
      $props = Get-ItemProperty $path
      if ($props.PSObject.Properties.Name -contains 'Enabled') { $enabled = [int]$props.Enabled }
      if ($props.PSObject.Properties.Name -contains 'DisabledByDefault') { $disabledByDefault = [int]$props.DisabledByDefault }
    }
    $items += [pscustomobject]@{
      protocol = $p
      role = $role
      enabled = if ($enabled -eq $null) { $null } else { $enabled -ne 0 }
      disabledByDefault = if ($disabledByDefault -eq $null) { $null } else { $disabledByDefault -ne 0 }
      registryEnabled = $enabled
      registryDisabledByDefault = $disabledByDefault
    }
  }
}
[pscustomobject]@{
  items = $items
} | ConvertTo-Json -Depth 5
");

            var obj = ParseJsonObject(output);
            return new
            {
                items = obj.TryGetValue("items", out var items) ? items : Array.Empty<object>()
            };
        }
        catch
        {
            return new { items = Array.Empty<object>(), status = "unknown" };
        }
    }

    private static object GetInstalledSecurityPatches()
    {
        // Use the COM Microsoft.Update.Session API instead of `Get-HotFix`.
        //
        // Why we moved off Get-HotFix:
        //   `Get-HotFix` wraps the WMI class Win32_QuickFixEngineering which
        //   only enumerates a subset of installed updates — specifically the
        //   ones registered as "QuickFixes". It systematically MISSES:
        //     * Modern cumulative updates installed via CBS (the bulk of
        //       Windows 10/11 monthly Patch Tuesday rollups)
        //     * .NET Framework security updates
        //     * Preview / OOB updates
        //     * Driver updates and DISM-applied updates
        //
        //   Result: the SCP `patches` evidence reported 4 KBs while Windows
        //   Settings → Update history showed 10 — the operator's source of
        //   truth disagreed with our audit, which defeats the whole point.
        //
        //   `Microsoft.Update.Session.QueryHistory()` is the SAME API that
        //   "Update history" in Settings reads from, so what we report
        //   matches what the operator sees on the device.
        //
        //   Schema mapping per IUpdateHistoryEntry:
        //     ResultCode 2  → Succeeded   (we filter to this)
        //     Operation 1   → Installation (skip Uninstallation = 2)
        //     Title         → free-form, KB id usually in parens
        //     Date          → install timestamp (UTC)
        //     UpdateIdentity.UpdateID → stable GUID for cross-platform refs
        //
        //   We extract the KB id with a regex on the title (e.g.
        //   "...(KB5083769)" → "KB5083769") so the agent-side normalizer can
        //   keep using `hotFixId` as the primary display key. If a title
        //   doesn't match, hotFixId stays null and the UI shows the title
        //   instead — graceful degradation rather than dropping the row.
        //
        //   `installedBy` is hardcoded to "Windows Update" because the COM
        //   API doesn't expose the principal that triggered the install.
        //   Get-HotFix did expose it (via WMI), but losing that field is an
        //   acceptable trade-off for getting the COMPLETE history.
        //
        //   `lastScanUtc` records when WE ran THIS query — gives the UI a
        //   "data freshness" signal even when the device hasn't installed
        //   anything new in months. Was missing entirely before this fix.
        // 45s budget for the WU history query. On heavily-patched WSUS-
        // bound hosts `GetTotalHistoryCount` + a full `QueryHistory(0,N)`
        // can legitimately take 30-40s; we want to allow that and fail
        // hard past it, not crash mid-call and pretend the device has
        // zero patches. The agent-side IPC timeout (90s in
        // privsvc-client-windows.ts) is sized to accommodate this 45s
        // plus the ~15s the other 9 sections take.
        const int PATCHES_TIMEOUT_MS = 45_000;

        try
        {
            var ps = RunPsWithTimeout(@"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$total = $searcher.GetTotalHistoryCount()
if ($total -le 0) {
  '[]'
  return
}

$history = $searcher.QueryHistory(0, $total)
$items = @()
foreach ($entry in $history) {
  # Only successful installs. ResultCode enum:
  #   0 NotStarted, 1 InProgress, 2 Succeeded, 3 SucceededWithErrors,
  #   4 Failed, 5 Aborted
  # Operation enum: 1 Installation, 2 Uninstallation
  if ([int]$entry.ResultCode -ne 2) { continue }
  if ([int]$entry.Operation -ne 1) { continue }

  $title = [string]$entry.Title
  $kb = $null
  $kbMatch = [regex]::Match($title, '\(KB(\d+)\)')
  if ($kbMatch.Success) { $kb = 'KB' + $kbMatch.Groups[1].Value }

  $updateId = $null
  try { $updateId = [string]$entry.UpdateIdentity.UpdateID } catch {}

  $items += [pscustomobject]@{
    hotFixId      = $kb
    title         = $title
    description   = [string]$entry.Description
    installedOn   = $entry.Date.ToUniversalTime().ToString('o')
    installedBy   = 'Windows Update'
    operation     = 'install'
    resultCode    = [int]$entry.ResultCode
    updateId      = $updateId
    supportUrl    = $(try { [string]$entry.SupportUrl } catch { $null })
  }
}

# Sort newest-first. Stable string sort works because installedOn is
# ISO-8601 UTC.
$items = $items | Sort-Object -Property installedOn -Descending
$items | ConvertTo-Json -Depth 4
", PATCHES_TIMEOUT_MS);

            if (ps.TimedOut)
            {
                // 45 seconds wasn't enough — wuauserv is degraded, WSUS
                // pointer is unreachable, or the host has truly massive
                // history. Record the failure for the top-level
                // collectorError and try the fast fallback so we at
                // least ship SOMETHING. The fallback (Get-HotFix)
                // returns a subset of installed updates (no cumulative
                // rollups) but enough for the UI to render a non-empty
                // "Last patch" date — far better than a 0/unknown
                // regression.
                RecordSectionError(
                    "patches",
                    "powershell_timeout",
                    $"Microsoft.Update.Session.QueryHistory exceeded {PATCHES_TIMEOUT_MS / 1000}s"
                );
                return TryPatchesFallback();
            }

            var items = ParseJsonArray(ps.Stdout);
            var nowUtc = DateTime.UtcNow.ToString("O");

            return new
            {
                status = items.Count > 0 ? "present" : "empty",
                count = items.Count,
                lastScanUtc = nowUtc,
                items
            };
        }
        catch (Exception ex)
        {
            RecordSectionError(
                "patches",
                "wua_com_exception",
                ex.Message ?? "Microsoft.Update.Session COM call threw"
            );
            return TryPatchesFallback();
        }
    }

    private static object TryPatchesFallback()
    {
        // Fall back to Get-HotFix on COM failures (e.g. WUA service
        // disabled, COM objects unavailable, Microsoft.Update.Session
        // timed out). It's a strict subset of the WU history (Get-HotFix
        // misses cumulative updates installed via CBS — which is most of
        // modern Patch Tuesday) but better than reporting nothing.
        try
        {
            var fb = RunPsWithTimeout(
                "Get-HotFix | Where-Object { $_.HotFixID -match '^KB' -and ($_.Description -match 'Security|Update|Hotfix') } | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledBy, InstalledOn | ConvertTo-Json -Depth 4",
                DEFAULT_PS_TIMEOUT_MS
            );

            if (fb.TimedOut)
            {
                RecordSectionError(
                    "patches",
                    "fallback_timeout",
                    $"Get-HotFix fallback exceeded {DEFAULT_PS_TIMEOUT_MS / 1000}s"
                );
                return new
                {
                    status = "unknown",
                    count = 0,
                    lastScanUtc = DateTime.UtcNow.ToString("O"),
                    source = "fallback_timeout",
                    items = Array.Empty<object>()
                };
            }

            var fbItems = ParseJsonArray(fb.Stdout);
            return new
            {
                status = fbItems.Count > 0 ? "present" : "unknown",
                count = fbItems.Count,
                lastScanUtc = DateTime.UtcNow.ToString("O"),
                source = "get_hotfix_fallback",
                items = fbItems
            };
        }
        catch (Exception ex)
        {
            RecordSectionError(
                "patches",
                "fallback_exception",
                ex.Message ?? "Get-HotFix fallback threw"
            );
            return new
            {
                status = "unknown",
                count = 0,
                lastScanUtc = DateTime.UtcNow.ToString("O"),
                items = Array.Empty<object>()
            };
        }
    }

    private sealed class PsResult
    {
        public string Stdout { get; init; } = "";
        public string Stderr { get; init; } = "";
        public bool TimedOut { get; init; }
        public int? ExitCode { get; init; }
    }

    // Default per-PowerShell timeout. Most of our compliance scripts
    // return in well under 5 seconds; 15s covers the slow outliers like
    // `Get-NetFirewallProfile` on a fresh boot or `Get-BitLockerVolume`
    // on a host with several encrypted volumes. The patches collector
    // overrides this — see `RunPsWithTimeout` callers below.
    private const int DEFAULT_PS_TIMEOUT_MS = 15_000;

    // ── PowerShell launcher with a hard timeout ────────────────────
    //
    // The legacy `RunPs(cmd)` API returned `stdout` and silently
    // dropped any indication that the script had timed out. Worse,
    // it called `ReadToEnd()` BEFORE `WaitForExit(15000)` — which
    // means the read blocks until stdout closes (i.e. the PS process
    // exits naturally). The 15s WaitForExit was effectively dead code:
    // by the time we reached it, ReadToEnd had already waited as long
    // as PowerShell wanted to take. A single slow
    // `Microsoft.Update.Session.QueryHistory()` call would freeze the
    // whole SecurityCompliance.Handle() pipeline for 40-60s, which is
    // exactly what we observed against DESKTOP-9G467VM (intermittent
    // 30s+ scans, agent-side IPC timeout, dashboard regressing to
    // "Last patch = unknown").
    //
    // The new shape:
    //   * BeginOutputReadLine / BeginErrorReadLine drains stdout +
    //     stderr asynchronously into buffers so we can't deadlock
    //     when the child fills its output pipe.
    //   * WaitForExit(timeoutMs) is the actual bound. On timeout we
    //     Kill the entire process tree (Kill(entireProcessTree:true)
    //     covers any nested processes the script spawned —
    //     `wmic`, `Get-HotFix`, etc).
    //   * Returns a structured result so callers can distinguish
    //     timeout from "ran clean but produced no output".
    //
    // RunPs (singular) is preserved as a thin shim over
    // RunPsWithTimeout so existing call sites that don't care about
    // timeouts keep their pre-fix behavior.
    private static string RunPs(string command)
    {
        return RunPsWithTimeout(command, DEFAULT_PS_TIMEOUT_MS).Stdout;
    }

    private static PsResult RunPsWithTimeout(string command, int timeoutMs)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        var psi = new ProcessStartInfo("powershell",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null)
        {
            return new PsResult { TimedOut = false, ExitCode = null };
        }

        var stdoutBuf = new StringBuilder();
        var stderrBuf = new StringBuilder();

        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null) stdoutBuf.AppendLine(e.Data);
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null) stderrBuf.AppendLine(e.Data);
        };

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        var exited = proc.WaitForExit(timeoutMs);

        if (!exited)
        {
            // Hard kill. entireProcessTree=true reaches any nested
            // helpers the script spawned (Get-HotFix → wmic, etc).
            try
            {
                proc.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort; if the kill itself fails the child will
                // be reaped when its handles drop.
            }

            // Give async readers a brief grace window to drain
            // whatever made it onto stdout/stderr before the kill —
            // useful for forensics ("did the script even start?").
            proc.WaitForExit(500);

            var stderrText = stderrBuf.ToString();
            if (!string.IsNullOrWhiteSpace(stderrText))
            {
                Console.WriteLine($"[PrivSvc][SecurityCompliance] PowerShell stderr (timed out): {stderrText}");
            }

            return new PsResult
            {
                Stdout = stdoutBuf.ToString(),
                Stderr = stderrText,
                TimedOut = true,
                ExitCode = null
            };
        }

        var stderrFinal = stderrBuf.ToString();
        if (!string.IsNullOrWhiteSpace(stderrFinal))
        {
            Console.WriteLine($"[PrivSvc][SecurityCompliance] PowerShell stderr: {stderrFinal}");
        }

        return new PsResult
        {
            Stdout = stdoutBuf.ToString(),
            Stderr = stderrFinal,
            TimedOut = false,
            ExitCode = proc.ExitCode
        };
    }

    private static Dictionary<string, object> ParseJsonObject(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var obj = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
            return obj ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static List<Dictionary<string, object>> ParseJsonArray(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return new List<Dictionary<string, object>>();

        try
        {
            if (output.TrimStart().StartsWith("["))
            {
                return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(output)
                    ?? new List<Dictionary<string, object>>();
            }

            var single = JsonSerializer.Deserialize<Dictionary<string, object>>(output);
            return single != null
                ? new List<Dictionary<string, object>> { single }
                : new List<Dictionary<string, object>>();
        }
        catch
        {
            return new List<Dictionary<string, object>>();
        }
    }

    private static string? GetString(Dictionary<string, object> obj, string key)
    {
        if (!obj.TryGetValue(key, out var value) || value == null) return null;
        if (value is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.Null || je.ValueKind == JsonValueKind.Undefined) return null;
            return je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
        }

        return value.ToString();
    }

    private static bool? GetBool(Dictionary<string, object> obj, string key)
    {
        var value = GetString(obj, key);
        if (bool.TryParse(value, out var parsed)) return parsed;
        if (int.TryParse(value, out var number)) return number != 0;
        return null;
    }

    private static int? GetInt(Dictionary<string, object> obj, string key)
    {
        var value = GetString(obj, key);
        if (int.TryParse(value, out var parsed)) return parsed;
        return null;
    }

    private static string? GetDateString(Dictionary<string, object> obj, string key)
    {
        var value = GetString(obj, key);
        if (DateTime.TryParse(value, out var parsed))
            return parsed.ToUniversalTime().ToString("o");
        return value;
    }

    private static List<string> ExtractAppliedGpos(Dictionary<string, object> obj, string key)
    {
        if (!obj.TryGetValue(key, out var value) || value is not JsonElement je || je.ValueKind != JsonValueKind.Array)
            return new List<string>();

        // El algoritmo vive en GpResultParsing para poder probarlo: es logica
        // de texto pura y aqui dentro, junto a PowerShell y WMI, ninguna suite
        // podia ejercitarlo. El bug que tenia vivio ahi sin que nadie lo viera.
        var lines = je.EnumerateArray().Select(x => x.ToString()).ToList();
        return GpResultParsing.ExtractAppliedGpoNames(lines);
    }

}
