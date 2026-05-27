// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/Sdp.cs
//
// SDP — Phase 1-E (Windows). Privileged primitives for the agent's
// Software Delivery Plugin. Three IPC handlers exposed via Router.cs:
//
//   sdp.detect    — evaluate a DetectionRule. Windows-specific
//                   coverage:
//                     * registry_uninstall — scan
//                       HKLM\Software[\WOW6432Node]\Microsoft\Windows\
//                       CurrentVersion\Uninstall\* by DisplayName.
//                     * file_exists — File.Exists / Directory.Exists.
//                     * command_exit — exec a CLI version probe.
//                     * bundle_version / pkg_receipt — macOS-only;
//                       returned as { matched: false, skipped: true }.
//   sdp.download  — fetch the package binary into a privileged
//                   staging dir and verify sha256.
//   sdp.install   — exec the installer (msi via msiexec, or exe with
//                   the catalog's silent args).
//
// All three are LocalSystem-only — the runtime gate lives in
// Router.cs (we extend the existing `crypto.|grpc.` prefix check to
// include `sdp.`).

using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class Sdp
{
    // ── Staging dir ───────────────────────────────────────────────
    //
    // C:\ProgramData\Tracenium\PrivSvc\sdp-staging\
    //   pkg-<packageId>-<jobNonce>.<format>
    //
    // ProgramData is the canonical location for service-owned per-
    // machine state; ACLs default to Authenticated-Users:Modify so
    // we don't bother locking down further (LocalSystem owns the
    // files we write, and the sha256 verify is the integrity gate).
    private static readonly string StagingDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Tracenium", "PrivSvc", "sdp-staging");

    private const long MaxDownloadBytes = 2L * 1024 * 1024 * 1024; // 2 GB ceiling
    private const int DefaultDownloadTimeoutSeconds = 600;          // 10 min
    private const int DefaultInstallTimeoutSeconds = 1740;          // 29 min
    private const long StagingTtlMs = 24L * 60 * 60 * 1000;

    private static readonly HttpClient HttpClient = new(new HttpClientHandler
    {
        // Follow redirects up to a sane limit. Catalog URLs commonly
        // resolve through one redirect (CDN signed URL) but we don't
        // want a chain that lets a compromised origin loop us.
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 5,
    })
    {
        // Per-call CancellationToken handles per-request timeout;
        // give HttpClient an overall ceiling to defend against
        // unresponsive servers that keep the socket open with no
        // bytes flowing.
        Timeout = TimeSpan.FromSeconds(DefaultDownloadTimeoutSeconds + 30),
    };

    // ── Public entry points ───────────────────────────────────────

    public static Task<PrivSvcResponse> HandleDetect(PrivSvcRequest req)
    {
        try
        {
            var rule = ExtractRule(req);
            if (rule == null)
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "rule required"));
            }

            var ruleType = rule.GetValueOrDefault("type")?.Trim() ?? "";

            DetectionResult result = ruleType switch
            {
                "registry_uninstall" => DetectRegistryUninstall(rule),
                "file_exists"        => DetectFileExists(rule),
                "command_exit"       => DetectCommandExit(rule),
                // Non-Windows native package-manager rules: skip
                // explicitly. The agent's PLATFORM_APPLICABILITY map
                // normally prevents these from arriving here; this is
                // defense in depth so a misrouted call surfaces a
                // clear `skipped` snapshot rather than an
                // `unknown rule type` error.
                "bundle_version" or "pkg_receipt"
                or "dpkg_installed" or "rpm_installed" => new DetectionResult
                {
                    Matched = false,
                    Snapshot = new
                    {
                        skipped = true,
                        reason = $"{ruleType}_not_applicable_on_windows",
                    },
                },
                _ => throw new InvalidOperationException($"unknown detection rule type: {ruleType}"),
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                matched = result.Matched,
                snapshot = result.Snapshot,
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "detect_failed", ex.Message));
        }
    }

    public static async Task<PrivSvcResponse> HandleDownload(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var url = GetString(p, "url") ?? "";
            var expectedSha256 = (GetString(p, "sha256") ?? "").ToLowerInvariant();
            var format = GetString(p, "format") ?? "";
            var packageId = GetInt(p, "packageId") ?? 0;
            var declaredSizeBytes = GetLong(p, "sizeBytes");
            var timeoutSeconds = GetInt(p, "timeoutSeconds") ?? DefaultDownloadTimeoutSeconds;
            timeoutSeconds = Math.Max(60, timeoutSeconds);

            // Pre-flight validation
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return PrivSvcResponse.Fail(req.Id, "url_invalid", "downloadPath must be an https URL");
            }
            if (!Regex.IsMatch(expectedSha256, "^[0-9a-f]{64}$"))
            {
                return PrivSvcResponse.Fail(req.Id, "url_invalid", "sha256 must be a 64-char hex string");
            }
            if (declaredSizeBytes is long s && (s <= 0 || s > MaxDownloadBytes))
            {
                return PrivSvcResponse.Fail(req.Id, "format_unsupported", "sizeBytes outside allowed range");
            }
            if (packageId <= 0)
            {
                return PrivSvcResponse.Fail(req.Id, "bad_request", "packageId required");
            }
            // Whitelist of formats this OS can install. Anything else
            // is a permanent failure — saves the cost of pulling bytes
            // we'd then refuse.
            if (format != "msi" && format != "exe")
            {
                return PrivSvcResponse.Fail(req.Id, "format_unsupported",
                    $"format {format} not supported on windows");
            }

            EnsureStagingDir();
            SweepOldStagingFiles();

            // pkg-<packageId>-<random>.<format>; random suffix avoids
            // collisions across concurrent downloads.
            var nonce = Convert.ToHexString(RandomBytes(8)).ToLowerInvariant();
            var stagingPath = Path.Combine(StagingDir, $"pkg-{packageId}-{nonce}.{format}");

            var downloadStart = Stopwatch.GetTimestamp();
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
            {
                using var resp = await HttpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                if (!resp.IsSuccessStatusCode)
                {
                    return PrivSvcResponse.Fail(req.Id, "download_failed",
                        $"http {(int)resp.StatusCode}: {resp.ReasonPhrase}");
                }

                // Streaming copy with sha256 incremental + size cap.
                using var src = await resp.Content.ReadAsStreamAsync(cts.Token);
                using var dst = new FileStream(stagingPath, FileMode.Create, FileAccess.Write, FileShare.None);
                using var sha = SHA256.Create();

                var buffer = new byte[64 * 1024];
                long total = 0;
                int read;
                while ((read = await src.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token)) > 0)
                {
                    total += read;
                    if (total > MaxDownloadBytes)
                    {
                        // Wipe the partial file so a malicious large
                        // download can't sit on disk forever.
                        TryDeleteFile(stagingPath);
                        return PrivSvcResponse.Fail(req.Id, "download_failed",
                            $"download exceeded MaxDownloadBytes={MaxDownloadBytes}");
                    }
                    sha.TransformBlock(buffer, 0, read, null, 0);
                    await dst.WriteAsync(buffer.AsMemory(0, read), cts.Token);
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                var actualSha256 = Convert.ToHexString(sha.Hash!).ToLowerInvariant();

                if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    // Permanent failure — wipe the file so it can't be
                    // executed accidentally.
                    dst.Close();
                    TryDeleteFile(stagingPath);
                    return PrivSvcResponse.Fail(req.Id, "sha256_mismatch",
                        $"expected sha256 {expectedSha256}, got {actualSha256}");
                }

                var elapsedMs = (Stopwatch.GetTimestamp() - downloadStart) * 1000.0 / Stopwatch.Frequency;
                return PrivSvcResponse.Success(req.Id, new
                {
                    stagingPath,
                    sha256 = actualSha256,
                    sizeBytes = total,
                    durationMs = (long)elapsedMs,
                });
            }
        }
        catch (TaskCanceledException)
        {
            return PrivSvcResponse.Fail(req.Id, "download_failed", "download timed out");
        }
        catch (HttpRequestException ex)
        {
            return PrivSvcResponse.Fail(req.Id, "download_failed", ex.Message);
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "download_failed", ex.Message);
        }
    }

    public static async Task<PrivSvcResponse> HandleInstall(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var stagingPath = GetString(p, "stagingPath") ?? "";
            var format = GetString(p, "format") ?? "";
            var args = GetString(p, "args");
            var timeoutSeconds = GetInt(p, "timeoutSeconds") ?? DefaultInstallTimeoutSeconds;
            timeoutSeconds = Math.Max(60, timeoutSeconds);

            // Defense in depth: stagingPath MUST be inside our staging
            // dir. Defends against a caller that managed to talk us into
            // launching an arbitrary executable.
            var absStaging = Path.GetFullPath(stagingPath);
            var absStagingRoot = Path.GetFullPath(StagingDir) + Path.DirectorySeparatorChar;
            if (!absStaging.StartsWith(absStagingRoot, StringComparison.OrdinalIgnoreCase))
            {
                return PrivSvcResponse.Fail(req.Id, "bad_request",
                    "stagingPath outside privsvc staging dir");
            }
            if (!File.Exists(absStaging))
            {
                return PrivSvcResponse.Fail(req.Id, "bad_request", "stagingPath not found");
            }

            InstallRunResult result;
            try
            {
                result = format switch
                {
                    "msi" => await RunMsiInstaller(absStaging, args, timeoutSeconds),
                    "exe" => await RunExeInstaller(absStaging, args, timeoutSeconds),
                    _     => throw new InvalidOperationException($"format {format} not supported on windows"),
                };
            }
            catch (TimeoutException timeoutEx)
            {
                TryDeleteFile(absStaging);
                return PrivSvcResponse.Fail(req.Id, "install_timeout", timeoutEx.Message);
            }
            catch (Exception ex)
            {
                return PrivSvcResponse.Fail(req.Id, "install_failed", ex.Message);
            }

            // Eager cleanup on success / reboot-required (3010).
            // Failed installers leave the file in place for forensics;
            // the staging-dir TTL sweeper picks them up later.
            if (result.ExitCode == 0 || result.ExitCode == 3010)
            {
                TryDeleteFile(absStaging);
            }

            return PrivSvcResponse.Success(req.Id, new
            {
                exitCode = result.ExitCode,
                stderrExcerpt = result.StderrExcerpt,
                durationMs = result.DurationMs,
            });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "install_failed", ex.Message);
        }
    }

    // ── Detection runners ─────────────────────────────────────────

    private sealed class DetectionResult
    {
        public bool Matched { get; set; }
        public object? Snapshot { get; set; }
    }

    /// <summary>
    /// Scan HKLM Uninstall keys (32-bit + 64-bit) for a DisplayName that
    /// matches the rule's `displayNameLike` pattern. We translate the
    /// SQL-style ILIKE pattern (`Foo App%`) into a case-insensitive regex.
    /// If `minVersion` is set, we additionally semver-compare DisplayVersion
    /// and require >= minVersion to count as matched.
    /// </summary>
    private static DetectionResult DetectRegistryUninstall(Dictionary<string, string> rule)
    {
        rule.TryGetValue("displayNameLike", out var pattern);
        rule.TryGetValue("minVersion", out var minVersion);
        if (string.IsNullOrWhiteSpace(pattern))
        {
            throw new InvalidOperationException("registry_uninstall.displayNameLike required");
        }

        // ILIKE → regex: % → .*, _ → ., escape regex metas, anchor.
        var regex = LikeToRegex(pattern!);

        // Both views — 32-bit installers register under WOW6432Node on
        // 64-bit Windows; 64-bit installers register under the standard
        // path. We scan both so a 32-bit MSI with the same DisplayName
        // gets picked up.
        var roots = new[]
        {
            (RegistryView: RegistryView.Registry64, Path: @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryView: RegistryView.Registry32, Path: @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        };

        var hits = new List<object>();
        string? bestVersion = null;

        foreach (var (view, subPath) in roots)
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var uninstall = hive.OpenSubKey(subPath);
            if (uninstall == null) continue;

            foreach (var name in uninstall.GetSubKeyNames())
            {
                using var entry = uninstall.OpenSubKey(name);
                if (entry == null) continue;

                var displayName = entry.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(displayName)) continue;
                if (!regex.IsMatch(displayName)) continue;

                var displayVersion = entry.GetValue("DisplayVersion") as string ?? "";
                hits.Add(new
                {
                    displayName,
                    displayVersion,
                    publisher = entry.GetValue("Publisher") as string,
                    view = view == RegistryView.Registry64 ? "x64" : "x86",
                });

                if (!string.IsNullOrWhiteSpace(displayVersion) &&
                    (bestVersion == null || CompareSemver(displayVersion, bestVersion) > 0))
                {
                    bestVersion = displayVersion;
                }
            }
        }

        if (hits.Count == 0)
        {
            return new DetectionResult
            {
                Matched = false,
                Snapshot = new { displayNameLike = pattern, found = false },
            };
        }

        var meets = MeetsMinVersion(bestVersion, minVersion);

        return new DetectionResult
        {
            Matched = meets,
            Snapshot = new
            {
                displayNameLike = pattern,
                found = true,
                installedVersion = bestVersion,
                minVersion,
                hits,
            },
        };
    }

    private static DetectionResult DetectFileExists(Dictionary<string, string> rule)
    {
        rule.TryGetValue("path", out var pathStr);
        if (string.IsNullOrWhiteSpace(pathStr))
        {
            throw new InvalidOperationException("file_exists.path required");
        }

        // Accept either a file or a directory — operators commonly put
        // either an exe path or an install dir as the rule.
        if (File.Exists(pathStr))
        {
            var info = new FileInfo(pathStr);
            return new DetectionResult
            {
                Matched = true,
                Snapshot = new { path = pathStr, type = "file", sizeBytes = info.Length },
            };
        }
        if (Directory.Exists(pathStr))
        {
            return new DetectionResult
            {
                Matched = true,
                Snapshot = new { path = pathStr, type = "dir" },
            };
        }
        return new DetectionResult
        {
            Matched = false,
            Snapshot = new { path = pathStr, found = false },
        };
    }

    private static DetectionResult DetectCommandExit(Dictionary<string, string> rule)
    {
        rule.TryGetValue("cmd", out var cmd);
        if (string.IsNullOrWhiteSpace(cmd))
        {
            throw new InvalidOperationException("command_exit.cmd required");
        }
        rule.TryGetValue("args_json", out var argsJson);
        rule.TryGetValue("stdoutMatches", out var stdoutMatches);

        var args = ParseArgsJson(argsJson);

        var psi = new ProcessStartInfo
        {
            FileName = cmd,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        int exitCode = -1;
        var stdout = new System.Text.StringBuilder();
        var stderr = new System.Text.StringBuilder();
        try
        {
            using var proc = Process.Start(psi);
            if (proc == null)
            {
                return new DetectionResult
                {
                    Matched = false,
                    Snapshot = new { cmd, exitCode = -1, error = "process_start_null" },
                };
            }

            // 15s cap mirrors macOS — long enough for a "foo --version"
            // probe, short enough that a hung command can't stall a
            // detection sweep. Capture both streams in parallel because
            // a chatty stderr can deadlock with a large stdout if we
            // serialise.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            if (!proc.WaitForExit(15_000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return new DetectionResult
                {
                    Matched = false,
                    Snapshot = new { cmd, exitCode = -1, error = "command_timeout" },
                };
            }

            stdout.Append(stdoutTask.Result);
            stderr.Append(stderrTask.Result);
            exitCode = proc.ExitCode;
        }
        catch (Exception ex)
        {
            return new DetectionResult
            {
                Matched = false,
                Snapshot = new { cmd, exitCode = -1, error = ex.Message },
            };
        }

        bool? regexMatched = null;
        if (!string.IsNullOrWhiteSpace(stdoutMatches))
        {
            try
            {
                regexMatched = Regex.IsMatch(stdout.ToString(), stdoutMatches);
            }
            catch
            {
                regexMatched = false;
            }
        }

        var matched = exitCode == 0 && (regexMatched ?? true);

        return new DetectionResult
        {
            Matched = matched,
            Snapshot = new
            {
                cmd,
                exitCode,
                stdoutPreview = Truncate(stdout.ToString(), 200),
                stderrPreview = Truncate(stderr.ToString(), 200),
                stdoutMatched = regexMatched,
            },
        };
    }

    // ── Install runners ───────────────────────────────────────────

    private sealed class InstallRunResult
    {
        public int ExitCode { get; set; }
        public string? StderrExcerpt { get; set; }
        public long DurationMs { get; set; }
    }

    private static async Task<InstallRunResult> RunMsiInstaller(
        string stagingPath,
        string? args,
        int timeoutSeconds)
    {
        // msiexec /i <path> /qn /norestart by default. If the catalog
        // operator overrides via silentInstallArgs, we honor that
        // instead (some packages need /norestart explicitly off, or
        // need /l*v for transcript, etc.). The default is the safe
        // unattended install.
        var argList = string.IsNullOrWhiteSpace(args)
            ? new List<string> { "/i", stagingPath, "/qn", "/norestart" }
            : new List<string> { "/i", stagingPath }.Concat(SplitArgs(args!)).ToList();

        return await RunInstallerProcess("msiexec.exe", argList, timeoutSeconds);
    }

    private static async Task<InstallRunResult> RunExeInstaller(
        string stagingPath,
        string? args,
        int timeoutSeconds)
    {
        // Vendor exe installers vary wildly in their silent flags
        // ("/S", "/silent", "--quiet", "/q"). We DON'T default any:
        // the catalog must specify silentInstallArgs explicitly, or
        // the installer runs with no flags (interactive UI), which
        // for a privsvc-launched process means it's invisible and
        // hangs forever. Defensive: if args is empty, fail.
        if (string.IsNullOrWhiteSpace(args))
        {
            throw new InvalidOperationException(
                "exe installer requires explicit silentInstallArgs in catalog");
        }
        var argList = SplitArgs(args);
        return await RunInstallerProcess(stagingPath, argList, timeoutSeconds);
    }

    private static async Task<InstallRunResult> RunInstallerProcess(
        string fileName,
        List<string> args,
        int timeoutSeconds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        var start = Stopwatch.GetTimestamp();
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null");

        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();

        // WaitForExitAsync respects the given CancellationToken. We
        // build one tied to timeoutSeconds; if it fires we kill the
        // process tree (msiexec spawns helpers) and surface a timeout.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"installer timed out after {timeoutSeconds}s");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var elapsedMs = (Stopwatch.GetTimestamp() - start) * 1000.0 / Stopwatch.Frequency;

        return new InstallRunResult
        {
            ExitCode = proc.ExitCode,
            StderrExcerpt = CombinedExcerpt(stdout, stderr),
            DurationMs = (long)elapsedMs,
        };
    }

    // ── Helpers ───────────────────────────────────────────────────

    private static void EnsureStagingDir()
    {
        Directory.CreateDirectory(StagingDir);
    }

    private static void SweepOldStagingFiles()
    {
        try
        {
            var cutoffUtc = DateTime.UtcNow.AddMilliseconds(-StagingTtlMs);
            foreach (var file in Directory.EnumerateFiles(StagingDir))
            {
                try
                {
                    var info = new FileInfo(file);
                    if (info.LastWriteTimeUtc < cutoffUtc)
                    {
                        File.Delete(file);
                    }
                }
                catch
                {
                    // race with a concurrent run / open file lock — ignore
                }
            }
        }
        catch
        {
            // first-time: dir didn't exist; ensured below by EnsureStagingDir
        }
    }

    private static byte[] RandomBytes(int n)
    {
        var buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    private static void TryDeleteFile(string path)
    {
        try { File.Delete(path); } catch { /* best-effort */ }
    }

    private static string? CombinedExcerpt(string? stdout, string? stderr)
    {
        var combined = string.Join(" | ", new[] { stdout?.Trim(), stderr?.Trim() }
            .Where(s => !string.IsNullOrEmpty(s)));
        if (string.IsNullOrEmpty(combined)) return null;
        return Truncate(combined, 1024);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s.Substring(0, max);

    /// <summary>
    /// Translate a SQL-ILIKE pattern (`Foo App%`) into a case-insensitive
    /// anchored regex. Only `%` and `_` are treated as wildcards; other
    /// regex metacharacters in the pattern are escaped.
    /// </summary>
    private static Regex LikeToRegex(string pattern)
    {
        var sb = new System.Text.StringBuilder("^");
        foreach (var ch in pattern)
        {
            switch (ch)
            {
                case '%': sb.Append(".*"); break;
                case '_': sb.Append('.'); break;
                default:
                    sb.Append(Regex.Escape(ch.ToString()));
                    break;
            }
        }
        sb.Append('$');
        return new Regex(sb.ToString(),
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Semver-ish comparison. Same shape as the macOS sibling: split
    /// on `.` and `-`, take the leading digits of each segment, missing
    /// segments default to 0.
    /// </summary>
    private static int CompareSemver(string a, string b)
    {
        var av = ParseVersion(a);
        var bv = ParseVersion(b);
        var n = Math.Max(av.Length, bv.Length);
        for (int i = 0; i < n; i++)
        {
            var ai = i < av.Length ? av[i] : 0;
            var bi = i < bv.Length ? bv[i] : 0;
            if (ai != bi) return ai > bi ? 1 : -1;
        }
        return 0;
    }

    private static int[] ParseVersion(string v)
    {
        return (v ?? "")
            .Split(new[] { '.', '-' })
            .Select(seg =>
            {
                var m = Regex.Match(seg, "^[0-9]+");
                return m.Success && int.TryParse(m.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)
                    ? n
                    : 0;
            })
            .ToArray();
    }

    private static bool MeetsMinVersion(string? installed, string? minVersion)
    {
        if (string.IsNullOrWhiteSpace(installed)) return false;
        if (string.IsNullOrWhiteSpace(minVersion)) return true;
        return CompareSemver(installed, minVersion!) >= 0;
    }

    /// <summary>
    /// Best-effort split of a single command-line args string into a
    /// list. Catalog `silentInstallArgs` are typically simple
    /// `/qn /norestart`-style flags; we don't try to be a full shell
    /// quoter — just split on whitespace, respecting double quotes.
    /// </summary>
    private static List<string> SplitArgs(string raw)
    {
        var result = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (var ch in raw)
        {
            if (ch == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }
            if (!inQuotes && char.IsWhiteSpace(ch))
            {
                if (current.Length > 0)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                continue;
            }
            current.Append(ch);
        }
        if (current.Length > 0) result.Add(current.ToString());
        return result;
    }

    /// <summary>
    /// Pull the rule object out of req.Params["rule"] and flatten its
    /// fields into a string→string dict the detection runners can read.
    /// We avoid pulling the entire Newtonsoft / strongly-typed object
    /// graph because the rule shape is polymorphic and only a couple
    /// of fields per type matter to us.
    /// </summary>
    private static Dictionary<string, string>? ExtractRule(PrivSvcRequest req)
    {
        if (req.Params == null) return null;
        if (!req.Params.TryGetValue("rule", out var raw) || raw == null) return null;

        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (raw is JsonElement el && el.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
            {
                switch (prop.Value.ValueKind)
                {
                    case JsonValueKind.String:
                        dict[prop.Name] = prop.Value.GetString() ?? "";
                        break;
                    case JsonValueKind.Number:
                        dict[prop.Name] = prop.Value.ToString();
                        break;
                    case JsonValueKind.True:
                    case JsonValueKind.False:
                        dict[prop.Name] = prop.Value.GetBoolean() ? "true" : "false";
                        break;
                    case JsonValueKind.Array:
                        // Args list stored separately as raw JSON for
                        // the command_exit runner to parse.
                        if (prop.NameEquals("args"))
                        {
                            dict["args_json"] = prop.Value.GetRawText();
                        }
                        break;
                    default:
                        // null / object — skip
                        break;
                }
            }
            return dict;
        }
        return null;
    }

    private static List<string> ParseArgsJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return new List<string>();
            return doc.RootElement.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString() ?? "")
                .ToList();
        }
        catch
        {
            return new List<string>();
        }
    }

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v == null) return null;
        if (v is JsonElement el)
        {
            return el.ValueKind == JsonValueKind.String ? el.GetString() : el.ToString();
        }
        return v.ToString();
    }

    private static int? GetInt(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v == null) return null;
        if (v is JsonElement el && el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var n))
        {
            return n;
        }
        if (int.TryParse(v.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }
        return null;
    }

    private static long? GetLong(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v == null) return null;
        if (v is JsonElement el && el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out var n))
        {
            return n;
        }
        if (long.TryParse(v.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }
        return null;
    }
}
