// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/PmpRemediation.cs
//
// Patch Management v2 — privsvc primitives for non-patch security
// remediation on Windows. Two methods exposed via Router.cs:
//
//   pmp.read_check_state — pure read of system state for a checkId.
//                          Returns { state, isCompliant, supported }.
//                          Used by the agent for pre-flight (idempotency
//                          + state_before) and post-flight (verification +
//                          state_after).
//   pmp.remediate        — apply the registry / powershell change.
//                          Returns { exitCode, stderrExcerpt, durationMs,
//                          requiresReboot, changesApplied[] }.
//
// Both gated by LocalSystem in Router.cs (`pmp.*` prefix joins the
// existing `crypto.|grpc.|sdp.` check). Phase 1 ships 4 checkIds:
//   * windows.cryptography.legacy_tls_disabled
//   * windows.cryptography.weak_ciphers_disabled
//   * windows.network_sharing.smbv1_disabled
//   * windows.firewall.profiles_enabled
// Phase 2 adds:
//   * windows.shares.no_everyone_full_control
// Generic (2026-09, parameterised — see GenericWriteShape.cs):
//   * windows.registry.set_value   params.writes[] of kind "registry"
//   * windows.secedit.set_value    params.writes[] of kind "secedit"
//   The value to write is the catalog's expected value; every write is
//   re-validated here (HKLM only, typed value, guarded keys refused).
//
// The dispatch keys MUST match exactly what the backend snapshots
// from the catalog and what the agent's remediation-checks.ts
// whitelists. Three-source-of-truth discipline (catalog seed,
// agent whitelist, this dict) is documented in the agent file.
//
// Security model — IMPORTANT:
//   * The catalog's `remediationDetails.steps` is treated as
//     OPERATOR-FACING DOCUMENTATION ONLY. Privsvc NEVER executes
//     anything from it. Real fix logic lives in this file as
//     hardcoded C# methods. A compromise of the backend → catalog
//     row can NOT be turned into RCE on the host.
//   * Each handler is deterministic with no payload-derived
//     paths/cmds. Inputs are limited to a small set of typed
//     params per checkId; everything else is constants.

using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class PmpRemediation
{
    // ── Public entry points ───────────────────────────────────────

    public static Task<PrivSvcResponse> HandleReadCheckState(PrivSvcRequest req)
    {
        var checkId = GetString(req.Params, "checkId")?.Trim() ?? "";
        if (string.IsNullOrEmpty(checkId))
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "checkId required"));
        }

        try
        {
            ReadResult? result = checkId switch
            {
                "windows.cryptography.legacy_tls_disabled" => ReadLegacyTls(),
                "windows.cryptography.weak_ciphers_disabled" => ReadWeakCiphers(),
                "windows.network_sharing.smbv1_disabled" => ReadSmbV1(),
                "windows.firewall.profiles_enabled" => ReadFirewallProfiles(),
                "windows.shares.no_everyone_full_control" => ReadSharesEveryoneFullControl(),
                "windows.registry.set_value" => ReadGenericRegistry(req.Params),
                "windows.secedit.set_value" => ReadGenericSecedit(req.Params),
                "windows.auditpol.set_value" => ReadGenericAuditpol(req.Params),
                _ => null
            };

            if (result == null)
            {
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "unsupported_check",
                        $"no read handler for checkId {checkId} on windows"));
            }

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                state = result.State,
                isCompliant = result.IsCompliant,
                supported = true,
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "read_state_failed", ex.Message));
        }
    }

    public static async Task<PrivSvcResponse> HandleRemediate(PrivSvcRequest req)
    {
        var checkId = GetString(req.Params, "checkId")?.Trim() ?? "";
        if (string.IsNullOrEmpty(checkId))
        {
            return PrivSvcResponse.Fail(req.Id, "bad_request", "checkId required");
        }

        try
        {
            RemediateResult result = checkId switch
            {
                "windows.cryptography.legacy_tls_disabled" => ApplyLegacyTlsDisabled(),
                "windows.cryptography.weak_ciphers_disabled" => ApplyWeakCiphersDisabled(),
                "windows.network_sharing.smbv1_disabled" => await ApplySmbV1Disabled(),
                "windows.firewall.profiles_enabled" => await ApplyFirewallProfilesEnabled(),
                "windows.shares.no_everyone_full_control" => await ApplySharesEveryoneFullControlRevoked(),
                "windows.registry.set_value" => ApplyGenericRegistry(req.Params),
                "windows.secedit.set_value" => ApplyGenericSecedit(req.Params),
                "windows.auditpol.set_value" => ApplyGenericAuditpol(req.Params),
                _ => RemediateResult.ForUnsupported(checkId),
            };

            if (result.Unsupported)
            {
                return PrivSvcResponse.Fail(req.Id, "unsupported_check",
                    $"no remediation handler for checkId {checkId} on windows");
            }

            return PrivSvcResponse.Success(req.Id, new
            {
                exitCode = result.ExitCode,
                stderrExcerpt = result.StderrExcerpt,
                durationMs = result.DurationMs,
                requiresReboot = result.RequiresReboot,
                changesApplied = result.ChangesApplied,
            });
        }
        catch (TimeoutException tex)
        {
            return PrivSvcResponse.Fail(req.Id, "remediate_timeout", tex.Message);
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "remediate_failed", ex.Message);
        }
    }

    // ── Result types ──────────────────────────────────────────────

    private sealed class ReadResult
    {
        public required object State { get; init; }
        public required bool IsCompliant { get; init; }
    }

    private sealed class RemediateResult
    {
        public int ExitCode { get; init; }
        public string? StderrExcerpt { get; init; }
        public long DurationMs { get; init; }
        public bool RequiresReboot { get; init; }
        public List<string> ChangesApplied { get; init; } = new();
        public bool Unsupported { get; init; }

        public static RemediateResult ForUnsupported(string checkId) =>
            new() { Unsupported = true, ExitCode = -1, ChangesApplied = new List<string> { $"unsupported:{checkId}" } };
    }

    // ── 1) Legacy TLS (1.0 + 1.1) ─────────────────────────────────
    //
    // SCHANNEL protocols are configured under
    //   HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\
    //     SCHANNEL\Protocols\<Proto>\<Server|Client>
    // with two DWORDs that BOTH must be set:
    //   Enabled            = 0  → disable the protocol entirely
    //   DisabledByDefault  = 1  → don't negotiate when not requested
    //
    // The Windows defaults vary by OS version; setting both
    // explicitly to (0, 1) gives a compliant state regardless.
    // Compliance check is symmetric — for compliance we want all 8
    // values (TLS 1.0 server + client × Enabled + DisabledByDefault,
    // idem 1.1) to read as expected.

    private const string TlsProtocolsRoot =
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    private static readonly string[] LegacyTlsProtocols = { "TLS 1.0", "TLS 1.1" };
    private static readonly string[] TlsRoles = { "Server", "Client" };

    private static ReadResult ReadLegacyTls()
    {
        var observed = new Dictionary<string, object?>();
        bool isCompliant = true;

        foreach (var proto in LegacyTlsProtocols)
        {
            foreach (var role in TlsRoles)
            {
                var subKey = $@"{TlsProtocolsRoot}\{proto}\{role}";
                using var key = Registry.LocalMachine.OpenSubKey(subKey);

                int? enabled = null, disabledByDefault = null;
                if (key != null)
                {
                    enabled = key.GetValue("Enabled") as int?;
                    disabledByDefault = key.GetValue("DisabledByDefault") as int?;
                }
                observed[$"{proto}.{role}.Enabled"] = enabled;
                observed[$"{proto}.{role}.DisabledByDefault"] = disabledByDefault;

                // Compliance per (proto, role): Enabled MUST be 0
                // AND DisabledByDefault MUST be 1. Treating an
                // absent key as non-compliant — operator can't claim
                // "absent means default" because default values
                // shifted across OS releases.
                if (enabled != 0 || disabledByDefault != 1)
                {
                    isCompliant = false;
                }
            }
        }

        return new ReadResult { State = observed, IsCompliant = isCompliant };
    }

    private static RemediateResult ApplyLegacyTlsDisabled()
    {
        var sw = Stopwatch.StartNew();
        var changes = new List<string>();

        foreach (var proto in LegacyTlsProtocols)
        {
            foreach (var role in TlsRoles)
            {
                var subKey = $@"{TlsProtocolsRoot}\{proto}\{role}";
                using var key = Registry.LocalMachine.CreateSubKey(subKey, writable: true)
                    ?? throw new InvalidOperationException($"could not create {subKey}");

                key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                key.SetValue("DisabledByDefault", 1, RegistryValueKind.DWord);
                changes.Add($"{subKey}\\Enabled=0");
                changes.Add($"{subKey}\\DisabledByDefault=1");
            }
        }

        sw.Stop();
        // SCHANNEL changes don't fully apply until the LSA / Schannel
        // SSP is reloaded — practically that means a reboot. Report
        // it so the operator sees the prompt in the UI and the
        // outcome rolls up to applied_reboot_required.
        return new RemediateResult
        {
            ExitCode = 0,
            DurationMs = sw.ElapsedMilliseconds,
            RequiresReboot = true,
            ChangesApplied = changes,
        };
    }

    // ── 2) Weak ciphers ───────────────────────────────────────────
    //
    // SCHANNEL ciphers are configured under
    //   HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\
    //     SCHANNEL\Ciphers\<CipherName>
    // with a single Enabled DWORD (0 = disabled, 0xffffffff = enabled).
    //
    // We disable the historically-broken cipher families: NULL, RC4
    // (BEAST/Lucky13), DES, 3DES (SWEET32), and EXPORT. Each
    // sub-key name comes from Microsoft's Secure Channel docs.

    private const string CiphersRoot =
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers";

    private static readonly string[] WeakCiphers =
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

    private static ReadResult ReadWeakCiphers()
    {
        var observed = new Dictionary<string, object?>();
        bool isCompliant = true;

        foreach (var cipher in WeakCiphers)
        {
            var subKey = $@"{CiphersRoot}\{cipher}";
            using var key = Registry.LocalMachine.OpenSubKey(subKey);
            int? enabled = null;
            if (key != null)
            {
                enabled = key.GetValue("Enabled") as int?;
            }
            observed[cipher] = enabled;
            // Compliance: Enabled must exist AND be 0. Absent =
            // "default" which has historically been ENABLED for
            // most of these → treat as non-compliant.
            if (enabled != 0)
            {
                isCompliant = false;
            }
        }

        return new ReadResult { State = observed, IsCompliant = isCompliant };
    }

    private static RemediateResult ApplyWeakCiphersDisabled()
    {
        var sw = Stopwatch.StartNew();
        var changes = new List<string>();

        foreach (var cipher in WeakCiphers)
        {
            var subKey = $@"{CiphersRoot}\{cipher}";
            using var key = Registry.LocalMachine.CreateSubKey(subKey, writable: true)
                ?? throw new InvalidOperationException($"could not create {subKey}");
            key.SetValue("Enabled", 0, RegistryValueKind.DWord);
            changes.Add($"{subKey}\\Enabled=0");
        }

        sw.Stop();
        return new RemediateResult
        {
            ExitCode = 0,
            DurationMs = sw.ElapsedMilliseconds,
            RequiresReboot = true, // SCHANNEL — same as TLS protos
            ChangesApplied = changes,
        };
    }

    // ── 3) SMBv1 disable ──────────────────────────────────────────
    //
    // Two pieces:
    //   * Server-side feature `SMB1Protocol` in Windows Optional
    //     Features (we use Disable-WindowsOptionalFeature -NoRestart).
    //   * Server-side service registry value
    //     HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\
    //       Parameters\SMB1 = 0
    //
    // Both gates close SMBv1 — the registry path takes effect
    // without a reboot for new connections, the optional feature
    // removal needs a reboot to fully unload the driver.

    private const string LanmanServerParamsKey =
        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

    private static ReadResult ReadSmbV1()
    {
        var state = new Dictionary<string, object?>();

        using (var key = Registry.LocalMachine.OpenSubKey(LanmanServerParamsKey))
        {
            state["LanmanServer.SMB1"] = key?.GetValue("SMB1") as int?;
        }

        // Asking for the optional-feature state is best-effort — the
        // Get-WindowsOptionalFeature cmdlet returns
        // "Enabled"/"Disabled"/"DisablePending"/etc. We translate to
        // a plain boolean.
        bool? featureEnabled = null;
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -ExecutionPolicy Bypass -Command "
                + "\"(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var stdout = proc.StandardOutput.ReadToEnd().Trim();
                proc.WaitForExit(15_000);
                if (stdout.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ||
                    stdout.Equals("DisablePending", StringComparison.OrdinalIgnoreCase))
                {
                    featureEnabled = false;
                }
                else if (stdout.Equals("Enabled", StringComparison.OrdinalIgnoreCase) ||
                         stdout.Equals("EnablePending", StringComparison.OrdinalIgnoreCase))
                {
                    featureEnabled = true;
                }
            }
        }
        catch
        {
            // best-effort — leave null, compliance below will gate
            // on the registry value alone in that case.
        }
        state["OptionalFeature.SMB1Protocol.Enabled"] = featureEnabled;

        // Compliance: registry SMB1 must be 0 AND optional feature
        // not enabled. If we couldn't read the feature state we
        // accept the registry value alone (over-strict would flap on
        // hosts where Get-WindowsOptionalFeature errors).
        var smb1Reg = state["LanmanServer.SMB1"] as int?;
        var compliant = smb1Reg == 0 && featureEnabled != true;

        return new ReadResult { State = state, IsCompliant = compliant };
    }

    private static async Task<RemediateResult> ApplySmbV1Disabled()
    {
        var sw = Stopwatch.StartNew();
        var changes = new List<string>();

        // (a) Registry — takes effect immediately for new sessions.
        using (var key = Registry.LocalMachine.CreateSubKey(LanmanServerParamsKey, writable: true)
            ?? throw new InvalidOperationException($"could not create {LanmanServerParamsKey}"))
        {
            key.SetValue("SMB1", 0, RegistryValueKind.DWord);
            changes.Add($"{LanmanServerParamsKey}\\SMB1=0");
        }

        // (b) Optional feature — unload the driver. -NoRestart so we
        // don't reboot under the operator; we surface
        // requiresReboot=true and let them schedule it.
        var psi = new ProcessStartInfo("powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -Command "
            + "\"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120)))
        {
            try { await proc.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                throw new TimeoutException("Disable-WindowsOptionalFeature timed out");
            }
        }
        var stderr = await stderrTask;
        var stdout = await stdoutTask;
        changes.Add("Disable-WindowsOptionalFeature SMB1Protocol -NoRestart");
        sw.Stop();

        return new RemediateResult
        {
            ExitCode = proc.ExitCode,
            StderrExcerpt = CombinedExcerpt(stdout, stderr),
            DurationMs = sw.ElapsedMilliseconds,
            RequiresReboot = true, // optional-feature unload
            ChangesApplied = changes,
        };
    }

    // ── 4) Firewall profiles enabled (Domain + Private + Public) ──
    //
    // Powershell `Set-NetFirewallProfile -Profile <P> -Enabled True`
    // for each of Domain/Private/Public. Read state via
    // Get-NetFirewallProfile.
    //
    // Some checks split this into 3 separate checkIds (one per
    // profile) — the Phase 1 catalog has exactly that, but the
    // single-checkId remediation here covers all three at once. The
    // backend dispatches by checkId, so the 3-per-profile checkIds
    // each map to this single handler in Phase 1; if Phase 2 wants
    // per-profile granularity, split the dispatch table.

    private static readonly string[] FirewallProfiles = { "Domain", "Private", "Public" };

    private static ReadResult ReadFirewallProfiles()
    {
        var state = new Dictionary<string, object?>();
        bool isCompliant = true;

        var psi = new ProcessStartInfo("powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -Command "
            + "\"Get-NetFirewallProfile -Profile Domain,Private,Public | "
            + "Select-Object Name,Enabled | ConvertTo-Json\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi);
        if (proc == null)
        {
            return new ReadResult { State = state, IsCompliant = false };
        }
        var stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(15_000);

        try
        {
            using var doc = JsonDocument.Parse(stdout);
            foreach (var item in doc.RootElement.EnumerateArray())
            {
                var name = item.GetProperty("Name").GetString() ?? "";
                bool enabled;
                var enabledProp = item.GetProperty("Enabled");
                // Powershell's ConvertTo-Json yields enums as either
                // numbers or strings depending on version. Accept
                // both shapes.
                if (enabledProp.ValueKind == JsonValueKind.Number)
                {
                    enabled = enabledProp.GetInt32() == 1;
                }
                else
                {
                    var s = enabledProp.ToString();
                    enabled = s.Equals("True", StringComparison.OrdinalIgnoreCase) ||
                              s.Equals("Enabled", StringComparison.OrdinalIgnoreCase) ||
                              s == "1";
                }
                state[name] = enabled;
                if (!enabled) isCompliant = false;
            }
        }
        catch
        {
            // If we couldn't parse, mark non-compliant so the
            // remediation runs. The apply call itself is
            // idempotent.
            isCompliant = false;
        }

        return new ReadResult { State = state, IsCompliant = isCompliant };
    }

    private static async Task<RemediateResult> ApplyFirewallProfilesEnabled()
    {
        var sw = Stopwatch.StartNew();
        var changes = new List<string>();
        var stderrAccum = new StringBuilder();
        int exitCode = 0;

        foreach (var profile in FirewallProfiles)
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -Command "
                + $"\"Set-NetFirewallProfile -Profile {profile} -Enabled True -ErrorAction Stop\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Process.Start returned null");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            {
                try { await proc.WaitForExitAsync(cts.Token); }
                catch (OperationCanceledException)
                {
                    try { proc.Kill(entireProcessTree: true); } catch { }
                    throw new TimeoutException($"Set-NetFirewallProfile {profile} timed out");
                }
            }

            var stderr = await stderrTask;
            await stdoutTask; // drain
            if (proc.ExitCode != 0)
            {
                exitCode = proc.ExitCode;
                stderrAccum.AppendLine($"[{profile}] {stderr.Trim()}");
            }
            changes.Add($"Set-NetFirewallProfile -Profile {profile} -Enabled True");
        }

        sw.Stop();
        return new RemediateResult
        {
            ExitCode = exitCode,
            StderrExcerpt = stderrAccum.Length == 0
                ? null
                : Truncate(stderrAccum.ToString(), 1024),
            DurationMs = sw.ElapsedMilliseconds,
            RequiresReboot = false, // takes effect immediately
            ChangesApplied = changes,
        };
    }

    // ── 5) SMB shares granting Everyone:FullControl ────────────────
    //
    // A share-level ACL problem, distinct from NTFS permissions:
    //   Get-SmbShare              — enumerate non-administrative shares
    //                                (Special shares like C$/ADMIN$/IPC$
    //                                are OS-managed; touching their ACLs
    //                                is out of scope and risks breaking
    //                                remote administration).
    //   Get-SmbShareAccess <name> — the share's ACL entries.
    //
    // Remediation removes ONLY the offending ACE (Everyone: Full) via
    // Revoke-SmbShareAccess, one share at a time. It does not invent a
    // replacement grant — the catalog's own remediation text ("replace
    // Everyone with least-privilege ACLs") requires knowing who SHOULD
    // have access, which is a judgment call this handler can't make
    // safely. Revoking the overly-broad grant is the deterministic,
    // safe subset of that guidance and is exactly what the check
    // (Everyone:Full specifically, not "Everyone has any access") flags.
    //
    // AccessControlType matters: both the read query and the detection
    // used after a revoke must match AccessControlType='Allow' only.
    // Once a share has no remaining explicit grant, Get-SmbShareAccess
    // reports a synthetic Everyone/Deny/Full row for the empty ACL —
    // matching on AccountName+AccessRight alone would keep flagging an
    // already-fixed share as non-compliant.

    private static (List<string> Shares, bool Ok) QuerySharesWithEveryoneFullControl()
    {
        // AccessControlType must be constrained to 'Allow'. Once a share's
        // only grant is revoked, Get-SmbShareAccess synthesizes an
        // Everyone/Deny/Full row to represent the now-empty ACL ("no
        // explicit grant = nobody connects") — without this filter that
        // synthetic row keeps matching AccountName+AccessRight and the
        // share is flagged as non-compliant forever, even right after a
        // successful remediation.
        var psi = new ProcessStartInfo("powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -Command "
            + "\"$shares = @(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { "
            + "$n = $_.Name; "
            + "if (@(Get-SmbShareAccess -Name $n | Where-Object { $_.AccountName -eq 'Everyone' -and $_.AccessRight -eq 'Full' -and $_.AccessControlType -eq 'Allow' }).Count -gt 0) { $n } "
            + "}); $shares | ConvertTo-Json -Compress\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi);
        if (proc == null) return (new List<string>(), false);

        var stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(20_000);
        if (proc.ExitCode != 0) return (new List<string>(), false);

        var shares = new List<string>();
        var trimmed = stdout.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed == "null") return (shares, true);

        try
        {
            using var doc = JsonDocument.Parse(trimmed);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var s = item.GetString();
                    if (!string.IsNullOrEmpty(s)) shares.Add(s);
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.String)
            {
                var s = doc.RootElement.GetString();
                if (!string.IsNullOrEmpty(s)) shares.Add(s);
            }
        }
        catch
        {
            return (shares, false);
        }

        return (shares, true);
    }

    private static ReadResult ReadSharesEveryoneFullControl()
    {
        var (shares, ok) = QuerySharesWithEveryoneFullControl();
        var state = new Dictionary<string, object?>
        {
            ["sharesWithEveryoneFullControl"] = shares,
        };

        if (!ok)
        {
            // Query failed — report non-compliant rather than silently
            // claiming a clean state we couldn't actually verify; the
            // next remediation attempt will re-query.
            state["queryError"] = true;
            return new ReadResult { State = state, IsCompliant = false };
        }

        return new ReadResult { State = state, IsCompliant = shares.Count == 0 };
    }

    private static async Task<RemediateResult> ApplySharesEveryoneFullControlRevoked()
    {
        var sw = Stopwatch.StartNew();
        var changes = new List<string>();
        var stderrAccum = new StringBuilder();
        int exitCode = 0;

        var (shares, ok) = QuerySharesWithEveryoneFullControl();
        if (!ok)
        {
            return new RemediateResult
            {
                ExitCode = -1,
                StderrExcerpt = "failed to enumerate SMB shares",
                DurationMs = sw.ElapsedMilliseconds,
                RequiresReboot = false,
                ChangesApplied = changes,
            };
        }

        foreach (var share in shares)
        {
            var escaped = share.Replace("'", "''");
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -ExecutionPolicy Bypass -Command "
                + $"\"Revoke-SmbShareAccess -Name '{escaped}' -AccountName Everyone -Force -ErrorAction Stop\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Process.Start returned null");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            {
                try { await proc.WaitForExitAsync(cts.Token); }
                catch (OperationCanceledException)
                {
                    try { proc.Kill(entireProcessTree: true); } catch { }
                    throw new TimeoutException($"Revoke-SmbShareAccess on '{share}' timed out");
                }
            }

            var stderr = await stderrTask;
            await stdoutTask; // drain
            if (proc.ExitCode != 0)
            {
                exitCode = proc.ExitCode;
                stderrAccum.AppendLine($"[{share}] {stderr.Trim()}");
            }
            changes.Add($"Revoke-SmbShareAccess -Name '{share}' -AccountName Everyone");
        }

        sw.Stop();
        return new RemediateResult
        {
            ExitCode = exitCode,
            StderrExcerpt = stderrAccum.Length == 0
                ? null
                : Truncate(stderrAccum.ToString(), 1024),
            DurationMs = sw.ElapsedMilliseconds,
            RequiresReboot = false, // share ACL changes apply immediately
            ChangesApplied = changes,
        };
    }


    // ── Generic: registry values ──────────────────────────────────
    //
    // Escribe los valores que el catálogo declara como esperados. Las
    // escrituras llegan tipadas en params.params.writes y se validan en
    // GenericWriteShape (HKLM sólo, sin "..", tipo acorde, guardas). Un
    // check es todo o nada: una escritura rechazada aborta el lote antes
    // de tocar el registro, para no dejar el check en fail con un cambio
    // a medias. Si la clave existe con OTRO tipo de valor (un REG_SZ donde
    // se pide DWORD) no se sobreescribe: es señal de que la sonda y el
    // sistema no hablan de lo mismo.

    private static ReadResult ReadGenericRegistry(Dictionary<string, object>? p)
    {
        var writes = GenericWriteShape.FromParams(p);
        if (writes.Rejected.Count > 0 || writes.Registry.Count == 0)
            throw new InvalidOperationException("invalid writes: " + string.Join("; ", writes.Rejected.DefaultIfEmpty("none")));

        var entries = new List<object>();
        var compliant = true;
        foreach (var w in writes.Registry)
        {
            object? current = null;
            string? kind = null;
            var present = false;
            using (var key = Registry.LocalMachine.OpenSubKey(w.SubKey))
            {
                if (key is not null)
                {
                    var raw = key.GetValue(w.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (raw is not null)
                    {
                        present = true;
                        current = RegistryProbeShape.Normalize(raw);
                        kind = key.GetValueKind(w.ValueName).ToString();
                    }
                }
            }
            // Un borrado cumple cuando NO está; cualquier otra escritura, cuando
            // está y vale lo pedido.
            var matches = w.Kind == GenericValueKind.Delete
                ? !present
                : present && GenericWriteShape.RegistryValueMatches(w, current);
            if (!matches) compliant = false;
            entries.Add(new { key = @"HKLM\" + w.SubKey, name = w.ValueName, present, kind, current, expected = w.Describe(), matches });
        }
        return new ReadResult { State = new { writes = entries }, IsCompliant = compliant };
    }

    private static RemediateResult ApplyGenericRegistry(Dictionary<string, object>? p)
    {
        var sw = Stopwatch.StartNew();
        var writes = GenericWriteShape.FromParams(p);
        if (writes.Rejected.Count > 0 || writes.Registry.Count == 0)
        {
            return new RemediateResult
            {
                ExitCode = 2, DurationMs = sw.ElapsedMilliseconds,
                StderrExcerpt = Truncate("rejected: " + string.Join("; ", writes.Rejected.DefaultIfEmpty("no writes")), 1024),
                ChangesApplied = new List<string>(),
            };
        }

        // Comprobación de tipos ANTES de escribir nada.
        foreach (var w in writes.Registry)
        {
            // Borrar no depende del tipo que tenga el valor.
            if (w.Kind == GenericValueKind.Delete) continue;
            using var key = Registry.LocalMachine.OpenSubKey(w.SubKey);
            if (key is null || key.GetValue(w.ValueName) is null) continue;
            var existing = key.GetValueKind(w.ValueName);
            var wanted = KindOf(w.Kind);
            var compatible = existing == wanted
                || (wanted == RegistryValueKind.String && existing == RegistryValueKind.ExpandString);
            if (!compatible)
            {
                return new RemediateResult
                {
                    ExitCode = 3, DurationMs = sw.ElapsedMilliseconds,
                    StderrExcerpt = $@"HKLM\{w.SubKey}:{w.ValueName} exists as {existing}, expected {wanted}; not overwritten",
                    ChangesApplied = new List<string>(),
                };
            }
        }

        var changes = new List<string>();
        foreach (var w in writes.Registry)
        {
            if (w.Kind == GenericValueKind.Delete)
            {
                // ⚠️ OpenSubKey, NUNCA CreateSubKey: borrar un valor de una clave
                // que no existe no debe dejar la clave creada como efecto
                // secundario. Si ya no está, no es un error: es el estado pedido.
                using var existing = Registry.LocalMachine.OpenSubKey(w.SubKey, writable: true);
                if (existing is null || existing.GetValue(w.ValueName) is null)
                {
                    changes.Add(w.Describe() + " — already absent");
                    continue;
                }
                existing.DeleteValue(w.ValueName, throwOnMissingValue: false);
                changes.Add(w.Describe());
                continue;
            }
            using var key = Registry.LocalMachine.CreateSubKey(w.SubKey, writable: true)
                ?? throw new InvalidOperationException($@"could not open or create HKLM\{w.SubKey}");
            object value = w.Kind switch
            {
                GenericValueKind.DWord => unchecked((int)w.DwordValue),
                GenericValueKind.String => w.StringValue ?? "",
                _ => w.MultiValue ?? Array.Empty<string>(),
            };
            key.SetValue(w.ValueName, value, KindOf(w.Kind));
            changes.Add(w.Describe());
        }
        sw.Stop();
        return new RemediateResult { ExitCode = 0, DurationMs = sw.ElapsedMilliseconds, RequiresReboot = false, ChangesApplied = changes };
    }

    private static RegistryValueKind KindOf(GenericValueKind k) => k switch
    {
        GenericValueKind.DWord => RegistryValueKind.DWord,
        GenericValueKind.String => RegistryValueKind.String,
        GenericValueKind.MultiString => RegistryValueKind.MultiString,
        // Un borrado no tiene tipo: nunca se llama a SetValue con él.
        _ => throw new InvalidOperationException("a delete has no registry value kind"),
    };

    // ── Generic: secedit [System Access] ──────────────────────────
    //
    // Exporta la directiva actual (secedit /export), compara la clave, y
    // para aplicar escribe una plantilla con SOLO [System Access] y las
    // claves pedidas, que `secedit /configure /areas SECURITYPOLICY`
    // aplica sin tocar lo que no se nombra. Después se vuelve a exportar
    // para verificar: secedit devuelve 0 aunque una clave no cambie.

    private static ReadResult ReadGenericSecedit(Dictionary<string, object>? p)
    {
        var writes = GenericWriteShape.FromParams(p);
        if (writes.Rejected.Count > 0 || writes.Secedit.Count == 0)
            throw new InvalidOperationException("invalid writes: " + string.Join("; ", writes.Rejected.DefaultIfEmpty("none")));

        var ini = ExportSecedit();
        ini.TryGetValue("System Access", out var access);
        var entries = new List<object>();
        var compliant = true;
        foreach (var w in writes.Secedit)
        {
            string? current = null;
            if (access is not null && access.TryGetValue(w.Key, out var v)) current = v.Trim().Trim('"');
            var matches = current is not null && SeceditValueMatches(w, current);
            if (!matches) compliant = false;
            entries.Add(new { key = w.Key, current, expected = w.Value, matches });
        }
        return new ReadResult { State = new { section = "System Access", writes = entries }, IsCompliant = compliant };
    }

    private static RemediateResult ApplyGenericSecedit(Dictionary<string, object>? p)
    {
        var sw = Stopwatch.StartNew();
        var writes = GenericWriteShape.FromParams(p);
        if (writes.Rejected.Count > 0 || writes.Secedit.Count == 0)
        {
            return new RemediateResult
            {
                ExitCode = 2, DurationMs = sw.ElapsedMilliseconds,
                StderrExcerpt = Truncate("rejected: " + string.Join("; ", writes.Rejected.DefaultIfEmpty("no writes")), 1024),
                ChangesApplied = new List<string>(),
            };
        }

        var stamp = Guid.NewGuid().ToString("N");
        var inf = Path.Combine(Path.GetTempPath(), $"trc-fix-{stamp}.inf");
        var db = Path.Combine(Path.GetTempPath(), $"trc-fix-{stamp}.sdb");
        var log = Path.Combine(Path.GetTempPath(), $"trc-fix-{stamp}.log");
        try
        {
            // secedit lee la plantilla como UTF-16 (Unicode=yes).
            File.WriteAllText(inf, GenericWriteShape.RenderSeceditInf(writes.Secedit), Encoding.Unicode);
            var run = RunProcess("secedit.exe", $"/configure /db \"{db}\" /cfg \"{inf}\" /areas SECURITYPOLICY /log \"{log}\" /quiet", 60_000);
            if (run.ExitCode != 0)
            {
                return new RemediateResult
                {
                    ExitCode = run.ExitCode, DurationMs = sw.ElapsedMilliseconds,
                    StderrExcerpt = CombinedExcerpt(run.Stdout, run.Stderr) ?? $"secedit exit {run.ExitCode}",
                    ChangesApplied = new List<string>(),
                };
            }

            // Verificación: lo que dice la directiva después.
            var after = ExportSecedit();
            after.TryGetValue("System Access", out var access);
            var changes = new List<string>();
            var missing = new List<string>();
            foreach (var w in writes.Secedit)
            {
                var ok = access is not null && access.TryGetValue(w.Key, out var v) && SeceditValueMatches(w, v.Trim().Trim('"'));
                if (ok) changes.Add($"[System Access] {w.Key}={w.Value}");
                else missing.Add(w.Key);
            }
            sw.Stop();
            return new RemediateResult
            {
                ExitCode = missing.Count == 0 ? 0 : 4,
                DurationMs = sw.ElapsedMilliseconds,
                StderrExcerpt = missing.Count == 0 ? null : "not applied (domain policy may override): " + string.Join(", ", missing),
                RequiresReboot = false,
                ChangesApplied = changes,
            };
        }
        finally
        {
            foreach (var f in new[] { inf, db, log })
            {
                try { if (File.Exists(f)) File.Delete(f); } catch { /* best effort */ }
            }
        }
    }

    // ── Generic: auditpol subcategories ───────────────────────────
    //
    // Lee con `auditpol /backup` (numérico, estable entre idiomas — ver
    // AuditpolShape) y escribe con `auditpol /set /subcategory:{guid}`.
    // Sin guardas: auditar más no rompe nada. Después vuelve a leer para
    // verificar: en un equipo de dominio una GPO de auditoría avanzada gana
    // en el siguiente refresco, y el `/set` local puede no quedarse.

    private static ReadResult ReadGenericAuditpol(Dictionary<string, object>? p)
    {
        var writes = GenericWriteShape.FromParams(p);
        if (writes.Rejected.Count > 0 || writes.Auditpol.Count == 0)
            throw new InvalidOperationException("invalid writes: " + string.Join("; ", writes.Rejected.DefaultIfEmpty("none")));
        var byGuid = ReadAuditpolByGuid();
        var entries = new List<object>();
        var compliant = true;
        foreach (var w in writes.Auditpol)
        {
            byGuid.TryGetValue(w.Subcategory, out var current);
            var matches = current is not null && string.Equals(current, w.SettingName, StringComparison.Ordinal);
            if (!matches) compliant = false;
            entries.Add(new { subcategory = w.Subcategory, current, expected = w.SettingName, matches });
        }
        return new ReadResult { State = new { writes = entries }, IsCompliant = compliant };
    }

    private static RemediateResult ApplyGenericAuditpol(Dictionary<string, object>? p)
    {
        var sw = Stopwatch.StartNew();
        var writes = GenericWriteShape.FromParams(p);
        if (writes.Rejected.Count > 0 || writes.Auditpol.Count == 0)
        {
            return new RemediateResult
            {
                ExitCode = 2, DurationMs = sw.ElapsedMilliseconds,
                StderrExcerpt = Truncate("rejected: " + string.Join("; ", writes.Rejected.DefaultIfEmpty("no writes")), 1024),
                ChangesApplied = new List<string>(),
            };
        }
        var changes = new List<string>();
        foreach (var w in writes.Auditpol)
        {
            var run = RunProcess("auditpol.exe",
                $"/set /subcategory:\"{{{w.Subcategory}}}\" /success:{(w.Success ? "enable" : "disable")} /failure:{(w.Failure ? "enable" : "disable")}", 30_000);
            if (run.ExitCode != 0)
            {
                return new RemediateResult
                {
                    ExitCode = run.ExitCode, DurationMs = sw.ElapsedMilliseconds,
                    StderrExcerpt = CombinedExcerpt(run.Stdout, run.Stderr) ?? $"auditpol exit {run.ExitCode}",
                    ChangesApplied = changes,
                };
            }
            changes.Add(w.Describe());
        }
        var after = ReadAuditpolByGuid();
        var missing = writes.Auditpol.Where(w => !(after.TryGetValue(w.Subcategory, out var cur) && cur == w.SettingName)).Select(w => w.Subcategory).ToList();
        sw.Stop();
        return new RemediateResult
        {
            ExitCode = missing.Count == 0 ? 0 : 4,
            DurationMs = sw.ElapsedMilliseconds,
            StderrExcerpt = missing.Count == 0 ? null : "not applied (domain audit policy may override): " + string.Join(", ", missing),
            RequiresReboot = false,
            ChangesApplied = changes,
        };
    }

    private static Dictionary<string, string> ReadAuditpolByGuid()
    {
        var csv = Path.Combine(Path.GetTempPath(), $"trc-auditpol-{Guid.NewGuid():N}.csv");
        try
        {
            var run = RunProcess("auditpol.exe", $"/backup /file:\"{csv}\"", 30_000);
            if (run.ExitCode != 0 || !File.Exists(csv))
                throw new InvalidOperationException($"auditpol /backup failed (exit {run.ExitCode}): {CombinedExcerpt(run.Stdout, run.Stderr)}");
            var parsed = AuditpolShape.ParseBackupCsv(File.ReadAllText(csv).Replace("\0", ""));
            var out_ = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (parsed is not null && parsed.TryGetValue("byGuid", out var raw) && raw is Dictionary<string, string> byGuid)
                foreach (var kv in byGuid) out_[kv.Key.Trim('{', '}')] = kv.Value;
            return out_;
        }
        finally
        {
            try { if (File.Exists(csv)) File.Delete(csv); } catch { /* best effort */ }
        }
    }

    private static bool SeceditValueMatches(SeceditWriteSpec w, string current)
    {
        if (w.IsNumeric)
        {
            return long.TryParse(current, NumberStyles.Integer, CultureInfo.InvariantCulture, out var have)
                && long.TryParse(w.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var want)
                && have == want;
        }
        return string.Equals(current, w.Value, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, Dictionary<string, string>> ExportSecedit()
    {
        var cfg = Path.Combine(Path.GetTempPath(), $"trc-secedit-{Guid.NewGuid():N}.cfg");
        try
        {
            var run = RunProcess("secedit.exe", $"/export /cfg \"{cfg}\" /areas SECURITYPOLICY /quiet", 30_000);
            if (run.ExitCode != 0 || !File.Exists(cfg))
                throw new InvalidOperationException($"secedit /export failed (exit {run.ExitCode}): {CombinedExcerpt(run.Stdout, run.Stderr)}");
            // La exportación sale en UTF-16; File.ReadAllText detecta el BOM.
            var text = File.ReadAllText(cfg).Replace("\0", "");
            return SeceditShape.ParseIni(text);
        }
        finally
        {
            try { if (File.Exists(cfg)) File.Delete(cfg); } catch { /* best effort */ }
        }
    }

    private sealed class ProcRun
    {
        public int ExitCode { get; init; }
        public string Stdout { get; init; } = "";
        public string Stderr { get; init; } = "";
    }

    private static ProcRun RunProcess(string file, string args, int timeoutMs)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException($"could not start {file}");
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException($"{file} did not finish within {timeoutMs} ms");
        }
        return new ProcRun { ExitCode = proc.ExitCode, Stdout = stdout.Result, Stderr = stderr.Result };
    }

    // ── Helpers ───────────────────────────────────────────────────

    private static string? CombinedExcerpt(string? stdout, string? stderr)
    {
        var combined = string.Join(" | ", new[] { stdout?.Trim(), stderr?.Trim() }
            .Where(s => !string.IsNullOrEmpty(s)));
        if (string.IsNullOrEmpty(combined)) return null;
        return Truncate(combined, 1024);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s.Substring(0, max);

    private static string? GetString(Dictionary<string, object>? p, string key)
    {
        if (p == null || !p.TryGetValue(key, out var v) || v == null) return null;
        if (v is JsonElement el)
        {
            return el.ValueKind == JsonValueKind.String ? el.GetString() : el.ToString();
        }
        return v.ToString();
    }
}
