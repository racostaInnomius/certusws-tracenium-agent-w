// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SecurityCompliance.cs
using System.Diagnostics;
using System.Text.Json;
using System.Linq;
using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class SecurityCompliance
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            var result = new
            {
                bitlocker = GetBitlockerStatus(),
                defender = GetDefenderStatus(),
                firewall = GetFirewallStatus(),
                smb = GetSmbStatus(),
                shares = GetRiskyShares(),
                antivirus = GetAntivirusStatus(),
                domain = GetDomainAndGpoStatus(),
                ciphers = GetEnabledCiphers(),
                protocols = GetTlsProtocols(),
                patches = GetInstalledSecurityPatches()
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "security_compliance_error", ex.Message)
            );
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

    private static object GetAntivirusStatus()
    {
        try
        {
            var defender = GetDefenderStatus();
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
            return new
            {
                partOfDomain = GetBool(obj, "partOfDomain") ?? false,
                domain = GetString(obj, "domain"),
                appliedComputerGpos = ExtractAppliedGpos(obj, "computer"),
                appliedUserGpos = ExtractAppliedGpos(obj, "user"),
                raw = obj
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
        try
        {
            var output = RunPs(
                "Get-HotFix | Where-Object { $_.HotFixID -match '^KB' -and ($_.Description -match 'Security|Update|Hotfix') } | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledBy, InstalledOn | ConvertTo-Json -Depth 4"
            );

            var items = ParseJsonArray(output);

            return new
            {
                status = items.Count > 0 ? "present" : "unknown",
                count = items.Count,
                items
            };
        }
        catch
        {
            return new { status = "unknown", count = 0, items = Array.Empty<object>() };
        }
    }

    private static string RunPs(string command)
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
        if (proc == null) return "";

        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();

        proc.WaitForExit(15000);

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.WriteLine($"[PrivSvc][SecurityCompliance] PowerShell stderr: {stderr}");
        }

        return stdout;
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

        var lines = je.EnumerateArray().Select(x => x.ToString()).ToList();
        var start = lines.FindIndex(line => line.Contains("Applied Group Policy Objects", StringComparison.OrdinalIgnoreCase));
        if (start < 0) return new List<string>();

        var result = new List<string>();
        for (var i = start + 1; i < lines.Count; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (line.Contains("The following GPOs", StringComparison.OrdinalIgnoreCase)) break;
            if (line.StartsWith("---")) continue;
            if (line.Contains("N/A", StringComparison.OrdinalIgnoreCase)) continue;
            result.Add(line);
        }

        return result.Distinct().ToList();
    }
}
