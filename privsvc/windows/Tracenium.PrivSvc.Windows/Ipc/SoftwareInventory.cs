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

            // ⚠️ HKCU de arriba es el de LocalSystem, NO el de las personas: el
            // PrivSvc corre como SYSTEM. Todo lo instalado por usuario —Chrome
            // per-user, Zoom, Teams, VS Code— era invisible, y la vista de
            // navegadores infracontaba sin decirlo. Mismo defecto y mismo
            // arreglo que las impresoras de red: HKEY_USERS\<SID> de cada perfil
            // con sesión. Un perfil sin sesión no está cargado y no se carga
            // (bloquearía el NTUSER.DAT al propio usuario), así que sus apps
            // siguen sin verse — y se DICE cuáles (userHives.unread), para que
            // el agente no los tome por desinstalados (UserHiveCoverageShape).
            var readSids = new List<string>();
            var perUser = ReadLoadedUserProfiles(readSids);
            apps.AddRange(perUser);
            var unreadSids = UserHiveCoverageShape.Unread(ReadProfileListSids(), readSids);
            Console.WriteLine($"[PrivSvc][SoftwareInventory] Registry inventory collected. Items={apps.Count} perUser={perUser.Count}");

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
                items = dedup,
                userHives = new { read = readSids, unread = unreadSids }
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
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var uninstall = baseKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
        return ReadUninstallKey(uninstall, subName => UninstallIdentity.BuildKeyPath(
            hive == RegistryHive.LocalMachine,
            view == RegistryView.Registry32,
            subName));
    }

    /// <summary>
    /// Las apps instaladas por usuario, de cada perfil con sesión.
    /// Un perfil que falla no tumba a los demás ni al inventario.
    /// <paramref name="readSids"/> recibe los perfiles leídos ENTEROS (sin clave
    /// Uninstall también cuenta: se miró y no había nada); uno que lanza a
    /// medias no entra, y el agente conserva lo que sabía de él.
    /// </summary>
    private static List<object> ReadLoadedUserProfiles(List<string> readSids)
    {
        var list = new List<object>();
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            foreach (var sid in users.GetSubKeyNames())
            {
                // Sólo personas: fuera SYSTEM/servicios, .DEFAULT y los _Classes.
                if (!UserRegistryProbeShape.IsUserProfileHive(sid)) continue;
                try
                {
                    using var uninstall = users.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\Uninstall");
                    list.AddRange(ReadUninstallKey(uninstall, subName => UninstallIdentity.BuildUserKeyPath(sid, subName)));
                    readSids.Add(sid);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PrivSvc][SoftwareInventory] user hive {sid} unreadable: {ex.GetType().Name}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][SoftwareInventory] HKEY_USERS unreadable: {ex.GetType().Name}");
        }
        return list;
    }

    /// Los perfiles que EXISTEN en el equipo, con sesión o sin ella. Si no se
    /// puede leer, lista vacía: el agente vuelve a la regla de antes (lo no
    /// visto se va), nunca inventa perfiles.
    private static List<string> ReadProfileListSids()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var profiles = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            return profiles?.GetSubKeyNames().ToList() ?? new List<string>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][SoftwareInventory] ProfileList unreadable: {ex.GetType().Name}");
            return new List<string>();
        }
    }

    private static List<object> ReadUninstallKey(RegistryKey? uninstall, Func<string, string> keyPathFor)
    {
        var list = new List<object>();
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

            var quietUninstallString = sub.GetValue("QuietUninstallString") as string;

            list.Add(new Dictionary<string, object?>
            {
                ["name"] = displayName,
                ["version"] = displayVersion,
                ["publisher"] = publisher,
                ["installLocation"] = installLocation,
                ["packageFamilyName"] = null,
                ["source"] = "win32-registry",

                // ── ADR-0019 F0: la identidad para poder QUITARLO ──────────
                //
                // ⚠️ `uninstallString` YA SE LEÍA AQUÍ, y sólo para decidir si
                // la fila merecía guardarse (el filtro de arriba). El campo más
                // valioso del inventario se tocaba y se tiraba. Medido en T111:
                // 1.264 de 2.088 filas win32 no tienen installLocation, así que
                // están guardadas PRECISAMENTE porque tenían UninstallString —
                // el único campo que las hacía dignas de guardarse era el que
                // no viajaba.
                //
                // Tercer caso del mismo patrón, después de `uptimeSeconds` y de
                // `antivirus.products`.
                ["uninstallString"] = uninstallString,
                ["quietUninstallString"] = quietUninstallString,

                // El ProductCode del MSI. La clave del registro ES el GUID
                // cuando lo instaló Windows Installer, así que no hay que
                // buscarlo en ningún otro sitio — pero un instalador EXE pone
                // ahí lo que quiere, y por eso sólo se emite cuando de verdad
                // tiene forma de GUID. Inventarse un ProductCode es peor que
                // no tenerlo: `msiexec /x` con basura no falla, desinstala otra
                // cosa o nada.
                ["productCode"] = UninstallIdentity.LooksLikeProductCode(subName) ? subName : null,

                // ⚠️ LA RUTA COMPLETA, CON HIVE Y VISTA, Y NO SÓLO EL NOMBRE.
                //
                // Este colector lee CUATRO sitios: HKLM y HKCU, cada uno en
                // vista de 64 y de 32 bits. Sin el prefijo, dos apps distintas
                // en hives distintos son indistinguibles — y sobre todo, HKCU
                // aquí es el del usuario bajo el que corre el PrivSvc, que es
                // LocalSystem, NO el humano sentado delante. Desinstalar una
                // entrada de HKCU desde LocalSystem es otra operación (y a
                // menudo imposible), así que quien decida tiene que poder verlo
                // sin adivinar.
                ["uninstallKeyPath"] = keyPathFor(subName),

                // El valor CRUDO de InstallDate: casi siempre "yyyyMMdd"
                // (REG_SZ), a veces un DWORD con epoch o lo que el instalador
                // quiso escribir. Se interpreta en el agente
                // (domain/install-date.ts), donde está probado; aquí sólo se
                // lee. Cadena o número, nunca un objeto: JSON lo serializa tal
                // cual.
                ["installDate"] = sub.GetValue("InstallDate") switch
                {
                    string str => str,
                    int dword => (object)dword,
                    _ => null
                }
            });
        }

        return list;
    }

    private static IEnumerable<object> ReadAppxPackagesPowerShell()
    {
        var list = new List<object>();

        // ⚠️ -AllUsers, y no la sesión de quien llama: el PrivSvc es SYSTEM y
        // sin él sólo veía los paquetes de SYSTEM (AppxInventoryShape). Los
        // usuarios viajan como «SID|InstallState» para decidir en C#, donde
        // se prueba. Windows PowerShell 5.1: ahí vive el módulo Appx.
        var ps = "powershell";
        var args =
            "-NoProfile -Command " +
            // UTF-8 en los dos extremos: nombres de apps con acentos. Ver PowerShellUtf8.
            "\"" + PowerShellUtf8.InlinePrelude + "Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | " +
            "Select-Object @{Name='name';Expression={$_.Name}}," +
            "@{Name='version';Expression={$_.Version.ToString()}}, " +
            "@{Name='publisher';Expression={$_.Publisher}}," +
            "@{Name='packageFamilyName';Expression={$_.PackageFamilyName}}," +
            "@{Name='installLocation';Expression={$null}}," +
            // Appx no guarda fecha de instalación; la carpeta del paquete se
            // crea al desplegar cada versión, así que su CreationTime es la
            // fecha de ESTA versión. Formato fijo yyyy-MM-dd en hora local
            // del equipo, que es lo que espera el agente.
            "@{Name='installDate';Expression={try{(Get-Item -LiteralPath $_.InstallLocation -ErrorAction Stop).CreationTime.ToString('yyyy-MM-dd')}catch{$null}}}," +
            // Una CADENA «SID|Estado;SID|Estado», no un array: en 5.1 un array
            // de una propiedad calculada puede salir de ConvertTo-Json como
            // {"value":[…],"Count":n}.
            "@{Name='users';Expression={(@($_.PackageUserInformation | ForEach-Object { [string]$_.UserSecurityId.Sid + '|' + [string]$_.InstallState }) -join ';')}}," +
            "@{Name='source';Expression={'ms-store'}} | " +
            "ConvertTo-Json -Depth 4\"";

        var psi = new ProcessStartInfo(ps, args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        }.ReadAsUtf8();

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

        List<Dictionary<string, object?>> parsed;
        try
        {
            // ConvertTo-Json returns object or array depending on count
            parsed = stdout.TrimStart().StartsWith("[")
                ? JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(stdout) ?? new()
                : JsonSerializer.Deserialize<Dictionary<string, object?>>(stdout) is { } one ? new() { one } : new();
        }
        catch
        {
            // ignore parse errors (v1)
            return list;
        }

        var forPeople = parsed
            .Where(x => x.TryGetValue("name", out var n) && n != null && !IsNoisePackage(x))
            .Where(x => AppxInventoryShape.InstalledForPerson(AppxInventoryShape.ReadUsers(x.GetValueOrDefault("users"))))
            .Select(x =>
            {
                // Los SIDs sólo sirven para decidir aquí; no viajan.
                x.Remove("users");
                return x;
            });
        list.AddRange(AppxInventoryShape.LatestPerFamily(forPeople));
        return list;
    }

    private static bool IsNoisePackage(Dictionary<string, object?> x)
    {
        var name = x["name"]!.ToString()!.Trim();
        var nameLower = name.ToLowerInvariant();

        // Exclude GUID-like names (very common noise)
        if (System.Text.RegularExpressions.Regex.IsMatch(name, @"^[a-f0-9\-]{20,}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
        {
            return true;
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
                return true;
            }
        }

        // Exclude entries where publisher is clearly Windows system
        if (x.TryGetValue("publisher", out var pub) && pub != null &&
            pub.ToString()!.ToLowerInvariant().Contains("microsoft windows"))
        {
            return true;
        }

        return false;
    }
}
