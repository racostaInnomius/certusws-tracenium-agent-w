// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SecurityPosture.cs
using System.Diagnostics;
using System.Text.Json;
using System.Linq;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class SecurityPosture
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            var result = new
            {
                bitlocker = GetBitlockerStatus(),
                defender = GetDefenderStatus(),
                firewall = GetFirewallStatus()
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "security_error", ex.Message)
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
                "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AMServiceEnabled | ConvertTo-Json"
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

                return new { status = rtEnabled ? "enabled" : "disabled" };
            }

            return new { status = "unknown" };
        }
        catch
        {
            return new { status = "unknown" };
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

    private static string RunPs(string command)
    {
        var psi = new ProcessStartInfo("powershell",
            $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"")
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
            Console.WriteLine($"[PrivSvc][SecurityPosture] PowerShell stderr: {stderr}");
        }

        return stdout;
    }
}