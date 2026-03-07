// src/privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SoftwareInventory.cs
using Microsoft.Win32;
using System.Diagnostics;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class SoftwareInventory
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            bool includeStoreApps = GetBool(req.Params, "includeStoreApps", true);

            var apps = new List<object>();

            // Registry: uninstall keys (HKLM/HKCU + 32/64)
            apps.AddRange(ReadUninstallRegistry(RegistryHive.LocalMachine, RegistryView.Registry64));
            apps.AddRange(ReadUninstallRegistry(RegistryHive.LocalMachine, RegistryView.Registry32));
            apps.AddRange(ReadUninstallRegistry(RegistryHive.CurrentUser, RegistryView.Registry64));
            apps.AddRange(ReadUninstallRegistry(RegistryHive.CurrentUser, RegistryView.Registry32));

            // AppX (Store) via PowerShell (pragmatic v1)
            if (includeStoreApps)
            {
                apps.AddRange(ReadAppxPackagesPowerShell());
            }

            // Optional: dedup basic (Name+Version+Publisher)
            var dedup = apps
                .Select(a => JsonSerializer.Serialize(a))
                .Distinct()
                .Select(s => JsonSerializer.Deserialize<Dictionary<string, object>>(s)!)
                .ToList();

            var result = new
            {
                count = dedup.Count,
                apps = dedup
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "inventory_error", ex.Message));
        }
    }

    private static bool GetBool(Dictionary<string, object>? p, string key, bool def)
    {
        if (p == null) return def;
        if (!p.TryGetValue(key, out var val) || val == null) return def;
        if (val is bool b) return b;
        if (val is string s && bool.TryParse(s, out var bb)) return bb;
        return def;
    }

    private static IEnumerable<object> ReadUninstallRegistry(RegistryHive hive, RegistryView view)
    {
        var list = new List<object>();
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var uninstall = baseKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
        if (uninstall == null) return list;

        foreach (var subName in uninstall.GetSubKeyNames())
        {
            using var sub = uninstall.OpenSubKey(subName);
            if (sub == null) continue;

            var displayName = sub.GetValue("DisplayName") as string;
            if (string.IsNullOrWhiteSpace(displayName)) continue;

            var displayVersion = sub.GetValue("DisplayVersion") as string;
            var publisher = sub.GetValue("Publisher") as string;
            var installLocation = sub.GetValue("InstallLocation") as string;

            list.Add(new Dictionary<string, object?>
            {
                ["name"] = displayName,
                ["version"] = displayVersion,
                ["publisher"] = publisher,
                ["installLocation"] = installLocation,
                ["packageFamilyName"] = null,
                ["source"] = "win32-registry"
            });
        }

        return list;
    }

    private static IEnumerable<object> ReadAppxPackagesPowerShell()
    {
        var list = new List<object>();

        // Output JSON array: Name, Version, Publisher, PackageFamilyName
        var ps = "powershell";
        var args =
            "-NoProfile -Command " +
            "\"Get-AppxPackage -ErrorAction SilentlyContinue | " +
            "Select-Object @{Name='name';Expression={$_.Name}}," +
            "@{Name='version';Expression={$_.Version.ToString()}}," +
            "@{Name='publisher';Expression={$_.Publisher}}," +
            "@{Name='packageFamilyName';Expression={$_.PackageFamilyName}}," +
            "@{Name='installLocation';Expression={$null}}," +
            "@{Name='source';Expression={'ms-store'}} | " +
            "ConvertTo-Json -Depth 4\"";

        var psi = new ProcessStartInfo(ps, args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) return list;

        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(30_000);

        if (proc.ExitCode != 0 || string.IsNullOrWhiteSpace(stdout))
            return list;

        try
        {
            // ConvertTo-Json returns object or array depending on count
            if (stdout.TrimStart().StartsWith("["))
            {
                var arr = JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(stdout);
                if (arr != null) list.AddRange(arr.Where(x => x.ContainsKey("name") && x["name"] != null));
            }
            else
            {
                var obj = JsonSerializer.Deserialize<Dictionary<string, object?>>(stdout);
                if (obj != null && obj.ContainsKey("name") && obj["name"] != null) list.Add(obj);
            }
        }
        catch
        {
            // ignore parse errors (v1)
        }

        return list;
    }
}