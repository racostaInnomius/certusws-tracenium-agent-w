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
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    // Floor for one source's slice of the download budget. Below this an
    // attempt cannot say anything useful — it would expire during the TLS
    // handshake and report a healthy source as broken.
    private const int MinPerSourceTimeoutSeconds = 30;

    // How long we wait to ESTABLISH a connection to a distribution point.
    // A firewalled DP drops the SYN rather than refusing it, so without this
    // the attempt hangs on OS retries and eats the whole download budget that
    // the origin fallback needed. Generous for a LAN, trivial next to 600s.
    private const int DpConnectTimeoutSeconds = 5;
    private const int DefaultInstallTimeoutSeconds = 1740;          // 29 min
    private const long StagingTtlMs = 24L * 60 * 60 * 1000;

    // ── LAN distribution-point client (Distribution Phase B) ──────────
    //
    // Peers fetch from a site's DP over mTLS: the DP REQUIRES a client cert
    // chained to the tenant CA — that mutual auth is the real access gate.
    // We reuse the enrollment identity already sitting in LocalMachine\My
    // (same cert the gRPC bridge authenticates with), so there is nothing new
    // to provision on the endpoint.
    //
    // Server-cert validation is intentionally relaxed for this tier ONLY, and
    // it is the direct analogue of the `-k` the macOS/Linux privsvc passes to
    // curl: the DP's certificate carries its deviceId as CN, but peers dial it
    // by LAN IP, so a hostname check can never pass. This is safe because the
    // bytes are not trusted on transport grounds — every download is verified
    // against the catalog sha256 (and the signature gate) after the fact, so a
    // spoofed DP can only make us fall through to cdn/origin, never install
    // anything. Built lazily and cached; a null cert means the tier is skipped.
    private static readonly object DpClientLock = new();
    private static HttpClient? _dpClient;
    private static bool _dpClientAttempted;

    private static HttpClient? GetDpHttpClient()
    {
        lock (DpClientLock)
        {
            if (_dpClientAttempted) return _dpClient;
            _dpClientAttempted = true;
            try
            {
                var thumbprint = GrpcBridgeSingleton.Instance.ClientCertThumbprint;
                if (string.IsNullOrWhiteSpace(thumbprint)) return null;

                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                var normalized = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
                var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
                if (matches.Count == 0) return null;
                var clientCert = matches[0];
                if (!clientCert.HasPrivateKey) return null;

                // SocketsHttpHandler, not HttpClientHandler, for ONE reason:
                // it exposes ConnectTimeout. A DP on the far side of a firewall
                // does not refuse the connection, it silently DROPS the SYN, so
                // the connect attempt hangs for as long as the OS keeps
                // retrying — and with only the download budget bounding it, the
                // peer sat there instead of falling through to the origin.
                //
                // Production, 2026-08-17: a target on 10.10.17.204 was given a
                // DP on 10.130.130.5 (different VLAN, port closed). The install
                // hung for half an hour and reported nothing. With a short
                // connect timeout the same mistake costs seconds and the
                // download completes from origin.
                //
                // Only the CONNECT phase is bounded here. Transfer time stays
                // governed by the per-source slice of the download budget, so a
                // slow-but-working DP is not cut off mid-download.
                var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false, // a DP serves the blob directly
                    ConnectTimeout = TimeSpan.FromSeconds(DpConnectTimeoutSeconds),
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        ClientCertificates = new X509Certificate2Collection(clientCert),
                        // The DP's cert carries its deviceId as CN while peers
                        // dial it by LAN IP, so hostname validation cannot pass.
                        // Safe: the sha256 gate verifies the BYTES regardless of
                        // transport, so a spoofed DP can only make us fall
                        // through to cdn/origin — never install anything.
                        RemoteCertificateValidationCallback = (_, _, _, _) => true,
                    },
                };
                _dpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
                return _dpClient;
            }
            catch
            {
                // No usable identity → the caller skips the dp tier and the
                // cdn/origin fallbacks carry the download.
                _dpClient = null;
                return null;
            }
        }
    }

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
            // Phase D — per-tenant bandwidth cap (Kbps). 0 = full speed.
            var rateLimitKbps = Math.Max(0, GetInt(p, "rateLimitKbps") ?? 0);

            // Pre-flight validation
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

            // Candidate sources (Distribution Phase A): ordered [{tier,url}]
            // list (dp → cdn → origin). The sha256 gate is the arbiter per
            // source — a failing/corrupt source means "try the next one",
            // never "install its bytes". Absent sources → legacy single `url`.
            var candidates = ExtractSources(p);
            if (candidates.Count == 0)
            {
                if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    return PrivSvcResponse.Fail(req.Id, "url_invalid", "downloadPath must be an https URL");
                }
                candidates.Add(("origin", url));
            }

            EnsureStagingDir();
            SweepOldStagingFiles();

            var sawNetworkFailure = false;
            var sawShaMismatch = false;
            var lastError = "";

            // `timeoutSeconds` is the budget for the WHOLE operation, not for
            // each source.
            //
            // It used to be handed intact to every candidate, so N sources
            // meant N x 600s of worst case while the IPC client waits 700s for
            // sdp.download. One unresponsive source burned the entire budget
            // and the caller gave up before the fallback could finish — the
            // caller-outwaits-handler invariant, broken again, this time by
            // multiplication rather than by a small number.
            //
            // A shared deadline keeps the handler inside what the client will
            // wait for, and dividing the remainder by the sources still to try
            // guarantees every tier gets a turn: a dp that hangs can consume at
            // most its share, and a dp that fails fast hands the whole
            // remainder to origin (sourcesLeft drops to 1).
            var opStart = Stopwatch.GetTimestamp();
            int RemainingSeconds() =>
                timeoutSeconds - (int)((Stopwatch.GetTimestamp() - opStart) / (double)Stopwatch.Frequency);

            for (var i = 0; i < candidates.Count; i++)
            {
                var (tier, candidateUrl) = candidates[i];

                var remaining = RemainingSeconds();
                if (remaining < MinPerSourceTimeoutSeconds)
                {
                    // Out of budget. Transient by nature: the sources may well
                    // be fine and simply slower than this deployment allows.
                    sawNetworkFailure = true;
                    lastError = $"download budget of {timeoutSeconds}s exhausted with " +
                                $"{candidates.Count - i} source(s) untried; last error: " +
                                (lastError.Length > 0 ? lastError : "none");
                    IpcLog.Write($"[sdp.download] budget exhausted packageId={packageId} untried={candidates.Count - i}");
                    break;
                }

                var sourcesLeft = candidates.Count - i;
                var perSourceTimeout = Math.Max(MinPerSourceTimeoutSeconds, remaining / sourcesLeft);
                if (perSourceTimeout > remaining) perSourceTimeout = remaining;

                // pkg-<packageId>-<random>.<format>; random suffix avoids
                // collisions across concurrent downloads and attempts.
                var nonce = Convert.ToHexString(RandomBytes(8)).ToLowerInvariant();
                var stagingPath = Path.Combine(StagingDir, $"pkg-{packageId}-{nonce}.{format}");

                // The LAN distribution point needs the mTLS client identity; every
                // other tier uses the shared client. No usable identity → skip the
                // dp tier rather than burn a doomed TLS handshake.
                var isDpTier = string.Equals(tier, "dp", StringComparison.OrdinalIgnoreCase);
                var client = isDpTier ? GetDpHttpClient() : HttpClient;
                if (client is null)
                {
                    sawNetworkFailure = true;
                    lastError = "dp tier unavailable: no enrollment client certificate";
                    continue;
                }

                var attempt = await DownloadOneAsync(client, candidateUrl, stagingPath, expectedSha256, perSourceTimeout, rateLimitKbps);
                if (attempt.Ok)
                {
                    return PrivSvcResponse.Success(req.Id, new
                    {
                        stagingPath,
                        sha256 = expectedSha256,
                        sizeBytes = attempt.SizeBytes,
                        durationMs = attempt.DurationMs,
                        servedBy = tier,
                    });
                }

                if (attempt.ShaMismatch) sawShaMismatch = true;
                else sawNetworkFailure = true;
                lastError = attempt.Error ?? "download failed";
            }

            // All candidates exhausted. Any network-ish failure → transient
            // (retry may find the source back up); all-sources sha mismatch →
            // permanent (the catalog hash is wrong, retrying cannot help).
            if (sawNetworkFailure)
            {
                return PrivSvcResponse.Fail(req.Id, "download_failed", lastError);
            }
            if (sawShaMismatch)
            {
                return PrivSvcResponse.Fail(req.Id, "sha256_mismatch", lastError);
            }
            return PrivSvcResponse.Fail(req.Id, "download_failed", "no usable source");
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "download_failed", ex.Message);
        }
    }

    /// <summary>
    /// Download a package into the distribution-point cache. Thin wrapper over
    /// the same verified-download primitive the install path uses, so the DP
    /// warms its cache through exactly the tiers, hash gate and rate limit a
    /// normal peer would — it just writes to the DP cache instead of staging.
    /// Never throws; failures come back as (false, reason) so the caller can
    /// move on to the next source.
    /// </summary>
    internal static async Task<(bool ok, string? error)> DownloadForDpAsync(
        string url, string destPath, string expectedSha256, int timeoutSeconds, int rateLimitKbps)
    {
        var attempt = await DownloadOneAsync(HttpClient, url, destPath, expectedSha256, timeoutSeconds, rateLimitKbps);
        return (attempt.Ok, attempt.Error);
    }

    private sealed class DownloadAttempt
    {
        public bool Ok { get; init; }
        public bool ShaMismatch { get; init; }
        public long SizeBytes { get; init; }
        public long DurationMs { get; init; }
        public string? Error { get; init; }
    }

    /// <summary>
    /// One download attempt: stream the URL into stagingPath with incremental
    /// sha256 + size cap, then verify the hash. Never throws — every failure
    /// (network, timeout, oversize, sha mismatch) comes back as a result so the
    /// caller's candidate loop can move on to the next source.
    /// </summary>
    private static async Task<DownloadAttempt> DownloadOneAsync(
        HttpClient client, string url, string stagingPath, string expectedSha256, int timeoutSeconds, int rateLimitKbps = 0)
    {
        var downloadStart = Stopwatch.GetTimestamp();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
            using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!resp.IsSuccessStatusCode)
            {
                return new DownloadAttempt { Error = $"http {(int)resp.StatusCode}: {resp.ReasonPhrase}" };
            }

            // Streaming copy with sha256 incremental + size cap.
            using var src = await resp.Content.ReadAsStreamAsync(cts.Token);
            using var dst = new FileStream(stagingPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var sha = SHA256.Create();

            var buffer = new byte[64 * 1024];
            long total = 0;
            int read;
            var throttleStart = Stopwatch.GetTimestamp();
            while ((read = await src.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token)) > 0)
            {
                total += read;
                if (total > MaxDownloadBytes)
                {
                    // Wipe the partial file so a malicious large download
                    // can't sit on disk forever.
                    dst.Close();
                    TryDeleteFile(stagingPath);
                    return new DownloadAttempt { Error = $"download exceeded MaxDownloadBytes={MaxDownloadBytes}" };
                }
                sha.TransformBlock(buffer, 0, read, null, 0);
                await dst.WriteAsync(buffer.AsMemory(0, read), cts.Token);

                // Phase D — pacing throttle (curl --limit-rate equivalent):
                // if we're ahead of the byte budget for the elapsed time,
                // sleep the difference. Kbps = KB/s (matches curl's k-suffix).
                if (rateLimitKbps > 0)
                {
                    var elapsedSec = (Stopwatch.GetTimestamp() - throttleStart) / (double)Stopwatch.Frequency;
                    var budgetBytes = rateLimitKbps * 1024.0 * elapsedSec;
                    if (total > budgetBytes)
                    {
                        var aheadBytes = total - budgetBytes;
                        var delayMs = (int)Math.Min(2000, aheadBytes / (rateLimitKbps * 1024.0) * 1000.0);
                        if (delayMs > 10) await Task.Delay(delayMs, cts.Token);
                    }
                }
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            var actualSha256 = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
            if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                // Corrupt/tampered bytes from THIS source — wipe; the caller
                // decides whether another source can still serve good bytes.
                dst.Close();
                TryDeleteFile(stagingPath);
                return new DownloadAttempt
                {
                    ShaMismatch = true,
                    Error = $"expected sha256 {expectedSha256}, got {actualSha256}",
                };
            }

            var elapsedMs = (Stopwatch.GetTimestamp() - downloadStart) * 1000.0 / Stopwatch.Frequency;
            return new DownloadAttempt { Ok = true, SizeBytes = total, DurationMs = (long)elapsedMs };
        }
        catch (TaskCanceledException)
        {
            TryDeleteFile(stagingPath);
            return new DownloadAttempt { Error = "download timed out" };
        }
        catch (HttpRequestException ex)
        {
            TryDeleteFile(stagingPath);
            return new DownloadAttempt { Error = ex.Message };
        }
        catch (Exception ex)
        {
            TryDeleteFile(stagingPath);
            return new DownloadAttempt { Error = ex.Message };
        }
    }

    /// <summary>
    /// Flatten the `sources` array (JsonElement) into an ordered (tier, url)
    /// list, dropping malformed / non-https entries. Mirrors ExtractIdentity's
    /// handling of nested JSON.
    /// </summary>
    internal static List<(string tier, string url)> ExtractSources(Dictionary<string, object> p)
    {
        var list = new List<(string, string)>();
        if (!p.TryGetValue("sources", out var raw) || raw is not JsonElement el || el.ValueKind != JsonValueKind.Array)
        {
            return list;
        }
        foreach (var item in el.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            var u = item.TryGetProperty("url", out var uEl) && uEl.ValueKind == JsonValueKind.String
                ? uEl.GetString()
                : null;
            if (string.IsNullOrWhiteSpace(u) || !u!.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var tier = item.TryGetProperty("tier", out var tEl) && tEl.ValueKind == JsonValueKind.String
                ? (tEl.GetString() ?? "origin")
                : "origin";
            if (string.IsNullOrWhiteSpace(tier)) tier = "origin";
            list.Add((tier, u!));
        }
        return list;
    }

    // ── sdp.verifySignature — full Authenticode verification (WinVerifyTrust) ──
    //
    // The authoritative code-signing check the cloud can't do: WinVerifyTrust
    // recomputes the file's Authenticode digest, builds + validates the cert
    // chain against the WINDOWS trust store, and (optionally) honours revocation.
    // Registered SIPs mean the SAME call verifies PE (.exe) AND MSI. Gate before
    // install when the package requires a signature. Returns { trusted, reason }.
    //
    // NOTE: revocation is set to WTD_REVOKE_NONE so the check is deterministic +
    // offline-capable (digest + chain-to-trusted-root is the core trust we need);
    // enabling whole-chain revocation is a hardening option but can false-fail on
    // an endpoint with no CRL/OCSP reachability. A verify EXCEPTION resolves to
    // trusted=false — the caller (plugins/sdp/index.ts) fails closed.
    public static Task<PrivSvcResponse> HandleVerifySignature(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var stagingPath = GetString(p, "stagingPath") ?? "";

            // Verification is READ-ONLY (WinVerifyTrust never executes the file),
            // so — unlike sdp.install — we allow any file under the agent's own
            // ProgramData root, which covers both the SDP staging dir and the
            // self-update download dir (...\Tracenium\updates). Still bounded so a
            // caller can't probe arbitrary paths on disk.
            var absTarget = Path.GetFullPath(stagingPath);
            var traceniumRoot = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Tracenium")) + Path.DirectorySeparatorChar;
            if (!absTarget.StartsWith(traceniumRoot, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request",
                    "path outside the Tracenium data root"));
            }
            if (!File.Exists(absTarget))
            {
                IpcLog.Write($"[verifySignature] file not found path={absTarget}");
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "file not found"));
            }

            // WinVerifyTrust is the step the agent self-update blocks on, and it
            // can stall well past the caller's IPC timeout: on an endpoint with
            // no outbound path to a CRL/OCSP responder the chain build waits on
            // network I/O inside the OS call, which we cannot cancel. Recording
            // entry, size and elapsed time is what distinguishes "the handler
            // never ran" from "the handler ran and took 40s".
            var sizeBytes = new FileInfo(absTarget).Length;
            IpcLog.Write($"[verifySignature] begin file={Path.GetFileName(absTarget)} bytes={sizeBytes}");

            var sw = Stopwatch.StartNew();
            var (trusted, reason) = WinVerifyTrustFile(absTarget);
            sw.Stop();

            IpcLog.Write($"[verifySignature] done trusted={trusted} reason={reason} ({sw.ElapsedMilliseconds}ms)");
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { trusted, reason }));
        }
        catch (Exception ex)
        {
            // Fail closed: an inability to verify is reported as not-trusted.
            IpcLog.Write($"[verifySignature] EXCEPTION {ex.GetType().Name}: {ex.Message}");
            return Task.FromResult(PrivSvcResponse.Success(req.Id,
                new { trusted = false, reason = "verify_error:" + ex.Message }));
        }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;

    // Common WinVerifyTrust HRESULTs → short, stable reason tags for the ACK.
    private static string MapTrustStatus(uint status) => status switch
    {
        0x00000000 => "trusted",
        0x800B0100 => "no_signature",       // TRUST_E_NOSIGNATURE
        0x800B0101 => "cert_expired",       // CERT_E_EXPIRED
        0x800B010C => "cert_revoked",       // CERT_E_REVOKED
        0x800B0109 => "untrusted_root",     // CERT_E_UNTRUSTEDROOT
        0x800B0111 => "explicit_distrust",  // TRUST_E_EXPLICIT_DISTRUST
        0x800B010A => "no_chain_to_trusted",// CERT_E_CHAINING
        0x80092010 => "cert_revoked",       // CRYPT_E_REVOKED
        _ => "untrusted:0x" + status.ToString("X8"),
    };

    private static (bool trusted, string reason) WinVerifyTrustFile(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        IntPtr pAction = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            Marshal.StructureToPtr(action, pAction, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG,
            };

            uint status = WinVerifyTrust(IntPtr.Zero, pAction, ref data);

            // Always release the chain/state WinVerifyTrust allocated.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, pAction, ref data);

            return (status == 0, MapTrustStatus(status));
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(pAction);
        }
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, IntPtr pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // union member for WTD_CHOICE_FILE
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
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

            // Eager cleanup on any Windows Installer SUCCESS code.
            // Failed installers leave the file in place for forensics;
            // the staging-dir TTL sweeper picks them up later.
            if (IsInstallerSuccessExitCode(result.ExitCode))
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

    // ── sdp.uninstall ─────────────────────────────────────────────
    //
    // Uninstall is by IDENTITY, not by the downloaded binary — the orchestrator
    // skips download+staging and hands us the identity from the detection rule:
    //   MSI → productCode GUID → `msiexec /x {GUID} /qn /norestart` (the exact,
    //         reliable removal; no name-pattern guessing).
    //   MSI without a productCode → resolve the registered UninstallString via
    //         displayNameLike and normalise its /I to /X.
    //   EXE → resolve the QuietUninstallString (preferred) or UninstallString
    //         via displayNameLike; run it, appending operator silentUninstallArgs
    //         when only the non-quiet string exists.
    public static async Task<PrivSvcResponse> HandleUninstall(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var format = GetString(p, "format") ?? "";
            var args = GetString(p, "args");
            var timeoutSeconds = Math.Max(60, GetInt(p, "timeoutSeconds") ?? DefaultInstallTimeoutSeconds);

            // identity is a nested object: { productCode?, displayNameLike? }.
            // JSON nested objects arrive as JsonElement (see ExtractRule), so
            // flatten its string fields rather than casting to a dictionary.
            var identity = ExtractIdentity(p);
            identity.TryGetValue("productCode", out var productCode);
            identity.TryGetValue("displayNameLike", out var displayNameLike);

            InstallRunResult result;
            try
            {
                if (format == "msi")
                {
                    result = await RunMsiUninstaller(productCode, displayNameLike, args, timeoutSeconds, req);
                }
                else if (format == "exe")
                {
                    result = await RunExeUninstaller(displayNameLike, args, timeoutSeconds, req);
                }
                else
                {
                    return PrivSvcResponse.Fail(req.Id, "format_unsupported",
                        $"format {format} not supported for uninstall on windows");
                }
            }
            catch (UninstallIdentityException idEx)
            {
                return PrivSvcResponse.Fail(req.Id, "identity_not_found", idEx.Message);
            }
            catch (TimeoutException timeoutEx)
            {
                return PrivSvcResponse.Fail(req.Id, "install_timeout", timeoutEx.Message);
            }
            catch (Exception ex)
            {
                return PrivSvcResponse.Fail(req.Id, "install_failed", ex.Message);
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

    /// <summary>
    /// Did the installer succeed, as Windows Installer defines success?
    ///
    /// Three codes mean the work was done: 0, 3010 (ERROR_SUCCESS_REBOOT_REQUIRED
    /// — finished, needs a restart) and 1641 (ERROR_SUCCESS_REBOOT_INITIATED —
    /// finished, restart already under way). This gate governs only whether we
    /// delete the staged installer; the outcome itself is graded agent-side in
    /// src/plugins/sdp/reboot.ts, which recognises the same three codes.
    ///
    /// 1641 was missing here, so a successful install that restarted the machine
    /// left its installer in the staging directory until the TTL sweeper ran.
    /// </summary>
    private static bool IsInstallerSuccessExitCode(int exitCode) =>
        exitCode == 0 || exitCode == 3010 || exitCode == 1641;

    private sealed class UninstallIdentityException : Exception
    {
        public UninstallIdentityException(string message) : base(message) { }
    }

    /// <summary>
    /// Flatten the nested `identity` object (a JsonElement) into a
    /// case-insensitive string→string dict. Mirrors ExtractRule's handling of
    /// nested JSON objects.
    /// </summary>
    private static Dictionary<string, string> ExtractIdentity(Dictionary<string, object> p)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!p.TryGetValue("identity", out var raw) || raw == null) return dict;
        if (raw is JsonElement el && el.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                {
                    dict[prop.Name] = prop.Value.GetString() ?? "";
                }
            }
        }
        return dict;
    }

    private static async Task<InstallRunResult> RunMsiUninstaller(
        string? productCode,
        string? displayNameLike,
        string? args,
        int timeoutSeconds,
        PrivSvcRequest req)
    {
        // Exact path: msiexec /x {ProductCode} /qn /norestart.
        if (!string.IsNullOrWhiteSpace(productCode))
        {
            var argList = new List<string> { "/x", productCode!, "/qn", "/norestart" };
            if (!string.IsNullOrWhiteSpace(args)) argList.AddRange(SplitArgs(args!));
            return await RunInstallerProcess("msiexec.exe", argList, timeoutSeconds);
        }

        // Fallback: resolve the registered UninstallString and normalise /I → /X.
        var (uninstallString, quiet) = FindUninstallEntry(displayNameLike);
        var chosen = quiet ?? uninstallString;
        if (string.IsNullOrWhiteSpace(chosen))
        {
            throw new UninstallIdentityException(
                "msi uninstall needs a productCode or a resolvable UninstallString");
        }
        var (file, uninstArgs) = ParseUninstallCommand(chosen!);
        // Force silent when we fell back to the non-quiet string.
        if (quiet == null)
        {
            uninstArgs = uninstArgs.Select(a => a.Replace("/I", "/X", StringComparison.OrdinalIgnoreCase)).ToList();
            if (!uninstArgs.Any(a => a.Equals("/qn", StringComparison.OrdinalIgnoreCase))) uninstArgs.Add("/qn");
            if (!uninstArgs.Any(a => a.Equals("/norestart", StringComparison.OrdinalIgnoreCase))) uninstArgs.Add("/norestart");
        }
        return await RunInstallerProcess(file, uninstArgs, timeoutSeconds);
    }

    private static async Task<InstallRunResult> RunExeUninstaller(
        string? displayNameLike,
        string? args,
        int timeoutSeconds,
        PrivSvcRequest req)
    {
        var (uninstallString, quiet) = FindUninstallEntry(displayNameLike);
        // Prefer the vendor-provided silent uninstall string; else fall back to
        // the plain string + operator-supplied silentUninstallArgs.
        if (!string.IsNullOrWhiteSpace(quiet))
        {
            var (qfile, qargs) = ParseUninstallCommand(quiet!);
            return await RunInstallerProcess(qfile, qargs, timeoutSeconds);
        }
        if (string.IsNullOrWhiteSpace(uninstallString))
        {
            throw new UninstallIdentityException(
                "exe uninstall needs a resolvable UninstallString (registry_uninstall rule)");
        }
        var (file, uArgs) = ParseUninstallCommand(uninstallString!);
        if (!string.IsNullOrWhiteSpace(args)) uArgs.AddRange(SplitArgs(args!));
        return await RunInstallerProcess(file, uArgs, timeoutSeconds);
    }

    /// <summary>
    /// Scan HKLM Uninstall keys (both views) for the entry whose DisplayName
    /// matches `displayNameLike`, returning its UninstallString and
    /// QuietUninstallString (either may be null).
    /// </summary>
    private static (string? uninstallString, string? quietUninstallString) FindUninstallEntry(string? displayNameLike)
    {
        if (string.IsNullOrWhiteSpace(displayNameLike)) return (null, null);
        var regex = LikeToRegex(displayNameLike!);
        var roots = new[]
        {
            (View: RegistryView.Registry64, Path: @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (View: RegistryView.Registry32, Path: @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        };
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
                var uninstallString = entry.GetValue("UninstallString") as string;
                var quiet = entry.GetValue("QuietUninstallString") as string;
                return (uninstallString, quiet);
            }
        }
        return (null, null);
    }

    /// <summary>
    /// Split an UninstallString like `"C:\App\uninst.exe" /S` or
    /// `MsiExec.exe /X{GUID}` into an executable + argument list.
    /// </summary>
    private static (string file, List<string> args) ParseUninstallCommand(string command)
    {
        var trimmed = command.Trim();
        string file;
        string rest;
        if (trimmed.StartsWith("\""))
        {
            var end = trimmed.IndexOf('"', 1);
            if (end < 0) { file = trimmed.Trim('"'); rest = ""; }
            else { file = trimmed.Substring(1, end - 1); rest = trimmed.Substring(end + 1).Trim(); }
        }
        else
        {
            var sp = trimmed.IndexOf(' ');
            if (sp < 0) { file = trimmed; rest = ""; }
            else { file = trimmed.Substring(0, sp); rest = trimmed.Substring(sp + 1).Trim(); }
        }
        return (file, rest.Length > 0 ? SplitArgs(rest) : new List<string>());
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

    internal static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v == null) return null;
        if (v is JsonElement el)
        {
            return el.ValueKind == JsonValueKind.String ? el.GetString() : el.ToString();
        }
        return v.ToString();
    }

    internal static int? GetInt(Dictionary<string, object> p, string key)
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

    internal static long? GetLong(Dictionary<string, object> p, string key)
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
