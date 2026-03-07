// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SecurityPosture.cs
using System.Diagnostics;
using System.Text.Json;

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

            var arr = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(output);
            if (arr == null || arr.Count == 0)
                return new { status = "disabled" };

            var enabledDrives = arr
                .Where(v => v.ContainsKey("VolumeStatus") &&
                            v["VolumeStatus"]?.ToString()?.Contains("FullyEncrypted") == true)
                .Select(v => v["MountPoint"]?.ToString())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();

            return new
            {
                status = enabledDrives.Count > 0 ? "enabled" : "disabled",
                drives = enabledDrives
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
                "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { status = "unknown" };

            var obj = JsonSerializer.Deserialize<Dictionary<string, object>>(output);

            if (obj != null &&
                obj.TryGetValue("RealTimeProtectionEnabled", out var val) &&
                bool.TryParse(val?.ToString(), out var enabled))
            {
                return new { status = enabled ? "enabled" : "disabled" };
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
                "Get-NetFirewallProfile | Select-Object Enabled | ConvertTo-Json -Depth 3"
            );

            if (string.IsNullOrWhiteSpace(output))
                return new { status = "unknown" };

            if (output.TrimStart().StartsWith("["))
            {
                var arr = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(output);
                if (arr != null && arr.Any(p =>
                        p.TryGetValue("Enabled", out var v) &&
                        bool.TryParse(v?.ToString(), out var b) && b))
                {
                    return new { status = "enabled" };
                }

                return new { status = "disabled" };
            }

            return new { status = "unknown" };
        }
        catch
        {
            return new { status = "unknown" };
        }
    }

    private static string RunPs(string command)
    {
        var psi = new ProcessStartInfo("powershell",
            $"-NoProfile -Command \"{command}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) return "";

        var stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(15000);

        return stdout;
    }
}