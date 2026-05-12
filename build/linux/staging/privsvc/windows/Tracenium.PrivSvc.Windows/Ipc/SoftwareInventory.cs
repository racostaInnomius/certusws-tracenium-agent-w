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
            Console.WriteLine($"[PrivSvc][SoftwareInventory] Starting inventory collection. includeStoreApps={includeStoreApps}");

            var apps = new List<object>();

            // Registry: uninstall keys (HKLM/HKCU + 32/64)
            apps.AddRange(ReadUninstallRegistry(RegistryHive.LocalMachine, RegistryView.Registry64));
            apps.AddRange(ReadUninstallRegistry(RegistryHive.LocalMachine, RegistryView.Registry32));
            apps.AddRange(ReadUninstallRegistry(RegistryHive.CurrentUser, RegistryView.Registry64));
            apps.AddRange(ReadUninstallRegistry(RegistryHive.CurrentUser, RegistryView.Registry32));
            Console.WriteLine($"[PrivSvc][SoftwareInventory] Registry inventory collected. Items={apps.Count}");

            // AppX (Store) via PowerShell (pragmatic v1)
            if (includeStoreApps)
            {
                var before = apps.Count;
                var storeApps = ReadAppxPackagesPowerShell().ToList();
                apps.AddRange(storeApps);
                Console.WriteLine($"[PrivSvc][SoftwareInventory] Store apps collected. Added={storeApps.Count} Total={apps.Count}");
            }

            // Dedup (stable): Name + Version + Publisher (case-insensitive)
            var dedup = apps
                .Cast<Dictionary<string, object?>>()
                .GroupBy(a =>
                {
                    var name = a.ContainsKey("name") ? a["name"]?.ToString()?.ToLowerInvariant() ?? "" : "";
                    var version = a.ContainsKey("version") ? a["version"]?.ToString() ?? "" : "";
                    var publisher = a.ContainsKey("publisher") ? NormalizePublisher(a["publisher"]?.ToString()) : "";

                    return $"{name}|{version}|{publisher}";
                })
                .Select(g => g.First())
                .ToList();

            Console.WriteLine($"[PrivSvc][SoftwareInventory] Deduplicated inventory count={dedup.Count}");

            var result = new
            {
                count = dedup.Count,
                items = dedup
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][SoftwareInventory] ERROR: {ex.Message}");
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

    private static string NormalizePublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return "";

        var p = publisher.Trim().ToLowerInvariant();

        if (p.Contains("microsoft")) return "microsoft";
        if (p.Contains("google")) return "google";
        if (p.Contains("oracle")) return "oracle";
        if (p.Contains("adobe")) return "adobe";

        return p;
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
            displayName = displayName.Trim();

            var displayVersion = (sub.GetValue("DisplayVersion") as string)?.Trim();
            var publisherRaw = (sub.GetValue("Publisher") as string)?.Trim();
            var publisher = NormalizePublisher(publisherRaw);
            var installLocation = sub.GetValue("InstallLocation") as string;

            // --- FILTERING (align with Control Panel behavior) ---

            // Exclude SystemComponent entries
            var systemComponent = sub.GetValue("SystemComponent");
            if (systemComponent is int sc && sc == 1) continue;

            // Exclude updates / hotfix / security entries via ReleaseType
            var releaseType = sub.GetValue("ReleaseType") as string;
            if (!string.IsNullOrEmpty(releaseType))
            {
                var rt = releaseType.ToLowerInvariant();
                if (rt.Contains("update") || rt.Contains("hotfix") || rt.Contains("security"))
                    continue;
            }

            // Exclude KB / update-style names
            if (displayName.StartsWith("Update for", StringComparison.OrdinalIgnoreCase) ||
                displayName.StartsWith("Security Update", StringComparison.OrdinalIgnoreCase) ||
                System.Text.RegularExpressions.Regex.IsMatch(displayName, @"\bKB\d+\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            {
                continue;
            }

            // Exclude entries without meaningful install footprint
            var uninstallString = sub.GetValue("UninstallString") as string;
            if (string.IsNullOrWhiteSpace(uninstallString) && string.IsNullOrWhiteSpace(installLocation))
                continue;

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
            "@{Name='version';Expression={$_.Version.ToString()}}, " +
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
        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.WriteLine($"[PrivSvc][SoftwareInventory] PowerShell stderr: {stderr}");
        }

        if (proc.ExitCode != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            Console.WriteLine($"[PrivSvc][SoftwareInventory] PowerShell returned no results. ExitCode={proc.ExitCode}");
            return list;
        }

        try
        {
            // ConvertTo-Json returns object or array depending on count
            if (stdout.TrimStart().StartsWith("["))
            {
                var arr = JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(stdout);
                if (arr != null)
                {
                    list.AddRange(arr.Where(x =>
                    {
                        if (!x.ContainsKey("name") || x["name"] == null) return false;

                        var name = x["name"]!.ToString()!.Trim();
                        var nameLower = name.ToLowerInvariant();

                        // Exclude GUID-like names (very common noise)
                        if (System.Text.RegularExpressions.Regex.IsMatch(name, @"^[a-f0-9\-]{20,}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                        {
                            return false;
                        }

                        // Exclude most Microsoft system/internal packages
                        if (nameLower.StartsWith("microsoft."))
                        {
                            if (
                                nameLower.Contains("windows") ||
                                nameLower.Contains("store") ||
                                nameLower.Contains("runtime") ||
                                nameLower.Contains("framework") ||
                                nameLower.Contains("host") ||
                                nameLower.Contains("experience") ||
                                nameLower.Contains("ui") ||
                                nameLower.Contains("xaml") ||
                                nameLower.Contains("aad") ||
                                nameLower.Contains("broker") ||
                                nameLower.Contains("cloud") ||
                                nameLower.Contains("contentdelivery") ||
                                nameLower.Contains("webview") ||
                                nameLower.Contains("async") ||
                                nameLower.Contains("bio") ||
                                nameLower.Contains("textservice")
                            )
                            {
                                return false;
                            }
                        }

                        // Exclude entries where publisher is clearly Windows system
                        if (x.ContainsKey("publisher") && x["publisher"] != null)
                        {
                            var pub = x["publisher"]!.ToString()!.ToLowerInvariant();
                            if (pub.Contains("microsoft windows"))
                            {
                                return false;
                            }
                        }

                        return true;
                    }));
                }
            }
            else
            {
                var obj = JsonSerializer.Deserialize<Dictionary<string, object?>>(stdout);
                if (obj != null && obj.ContainsKey("name") && obj["name"] != null)
                {
                    var name = obj["name"]!.ToString()!.Trim();

                    bool isFiltered = false;

                    // GUID-like names
                    if (System.Text.RegularExpressions.Regex.IsMatch(name, @"^[a-f0-9\-]{20,}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    {
                        isFiltered = true;
                    }

                    if (!isFiltered && name.StartsWith("microsoft.", StringComparison.OrdinalIgnoreCase))
                    {
                        var nameLower = name.ToLowerInvariant();

                        if (
                            nameLower.Contains("windows") ||
                            nameLower.Contains("store") ||
                            nameLower.Contains("runtime") ||
                            nameLower.Contains("framework") ||
                            nameLower.Contains("host") ||
                            nameLower.Contains("experience") ||
                            nameLower.Contains("ui") ||
                            nameLower.Contains("xaml") ||
                            nameLower.Contains("aad") ||
                            nameLower.Contains("broker") ||
                            nameLower.Contains("cloud") ||
                            nameLower.Contains("contentdelivery") ||
                            nameLower.Contains("webview") ||
                            nameLower.Contains("async") ||
                            nameLower.Contains("bio") ||
                            nameLower.Contains("textservice")
                        )
                        {
                            isFiltered = true;
                        }
                    }

                    if (!isFiltered && obj.ContainsKey("publisher") && obj["publisher"] != null)
                    {
                        var pub = obj["publisher"]!.ToString()!.ToLowerInvariant();
                        if (pub.Contains("microsoft windows"))
                        {
                            isFiltered = true;
                        }
                    }

                    if (!isFiltered)
                    {
                        list.Add(obj);
                    }
                }
            }
        }
        catch
        {
            // ignore parse errors (v1)
        }

        return list;
    }
}