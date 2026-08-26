// Ipc/Dp.cs
//
// Distribution Phase B — the Distribution Point (DP) role on Windows.
// Mirror of privsvc/{macos,linux}/src/dp.ts. Two IPC handlers:
//
//   sdp.dp.prefetch — warm the LAN cache: download the package through the
//                     normal tiers (cdn -> origin), verify sha256, store it
//                     content-addressed, evict LRU, and make sure the blob
//                     server is listening. Reports ready.
//   sdp.dp.status   — cache inventory + server state.
//
// ── Why a hand-rolled HTTP server ────────────────────────────────────────
// This project is `SelfContained=false`, so pulling in Kestrel
// (Microsoft.AspNetCore.App) would require the ASP.NET Core runtime to be
// installed on every managed endpoint — unacceptable deployment friction for
// an agent. HttpListener is in the BCL but needs `netsh http sslcert` to bind
// a certificate, which is external state to configure and clean up. Since the
// served surface is exactly one route (GET/HEAD /sdp/blob/{sha256}, with
// Range), TcpListener + SslStream is both smaller and dependency-free.
//
// ── Security model ───────────────────────────────────────────────────────
//   * INTEGRITY is end-to-end and NOT this server's job: peers verify sha256
//     and the signature gate after downloading, so the DP is an UNTRUSTED
//     cache. A compromised DP can withhold or corrupt bytes (the peer then
//     falls through to cdn/origin) but can never cause an install.
//   * CONFIDENTIALITY is this server's job: mutual TLS. We present the
//     enrollment certificate and REQUIRE a client certificate that chains to
//     the same tenant CA, so only enrolled agents can pull packages.
//   * The served path is validated to a bare 64-hex sha256 and resolved
//     strictly inside the cache directory — no traversal, no directory
//     listing, no writes.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class Dp
{
    // C:\ProgramData\Tracenium\PrivSvc\dp-cache\<sha256>
    private static readonly string CacheDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Tracenium", "PrivSvc", "dp-cache");

    private const int DefaultPort = 47821;
    private const long DefaultCacheMaxBytes = 20L * 1024 * 1024 * 1024; // 20 GB
    private const int DefaultPrefetchTimeoutSeconds = 900;
    private const string FirewallRuleName = "Tracenium SDP Distribution Point";

    // Cap the request head we will buffer: a peer sends a request line plus a
    // couple of headers, nothing more. Bounds a slowloris-style memory abuse.
    private const int MaxRequestHeadBytes = 8 * 1024;
    private const int StreamCopyBufferBytes = 64 * 1024;

    private static readonly Regex BlobPathRegex =
        new(@"^/sdp/blob/([0-9a-fA-F]{64})$", RegexOptions.Compiled);

    private static int Port
    {
        get
        {
            var raw = Environment.GetEnvironmentVariable("TRACENIUM_DP_PORT");
            return int.TryParse(raw, out var p) && p > 0 && p < 65536 ? p : DefaultPort;
        }
    }

    // ── Server lifecycle ─────────────────────────────────────────────────

    private static readonly object ServerLock = new();
    private static TcpListener? _listener;
    private static CancellationTokenSource? _serverCts;
    private static string? _serverError;

    private static bool ServerRunning => _listener != null;

    /// <summary>
    /// Start the blob server if it isn't already listening. Returns null on
    /// success or a short reason tag on failure — the caller reports that to
    /// the control plane, which fails open (peers use cdn/origin instead).
    /// </summary>
    private static string? EnsureServer()
    {
        lock (ServerLock)
        {
            if (_listener != null) return null;

            X509Certificate2 serverCert;
            try
            {
                var thumbprint = GrpcBridgeSingleton.Instance.ClientCertThumbprint;
                if (string.IsNullOrWhiteSpace(thumbprint)) return "identity_unavailable";
                var loaded = LoadCertByThumbprint(StoreName.My, thumbprint!);
                if (loaded == null || !loaded.HasPrivateKey) return "identity_unavailable";
                serverCert = loaded;
            }
            catch (Exception ex)
            {
                return $"identity_error:{ex.GetType().Name}";
            }

            try
            {
                var listener = new TcpListener(IPAddress.Any, Port);
                listener.Start();
                _listener = listener;
                _serverCts = new CancellationTokenSource();
                _serverError = null;

                var token = _serverCts.Token;
                _ = Task.Run(() => AcceptLoopAsync(listener, serverCert, token));

                TryEnsureFirewallRule();
                return null;
            }
            catch (Exception ex)
            {
                _listener = null;
                _serverError = ex.Message;
                return $"listen_failed:{ex.GetType().Name}";
            }
        }
    }

    private static async Task AcceptLoopAsync(
        TcpListener listener, X509Certificate2 serverCert, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                // Listener faulted (adapter down, port stolen). Drop the server
                // so the next prefetch rebuilds it rather than serving nothing
                // forever.
                lock (ServerLock) { _listener = null; }
                return;
            }

            // One task per connection: a large blob transfer must not block
            // other peers on the same site from starting theirs.
            _ = Task.Run(() => ServeClientAsync(client, serverCert, token), token);
        }
    }

    private static async Task ServeClientAsync(
        TcpClient client, X509Certificate2 serverCert, CancellationToken token)
    {
        using (client)
        {
            SslStream? ssl = null;
            try
            {
                client.ReceiveTimeout = 30_000;
                client.SendTimeout = 300_000;

                ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: ValidatePeerCertificate);

                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, token);

                // AuthenticateAsServerAsync succeeds only if the callback
                // approved the peer, so by here the caller is an enrolled agent
                // of this tenant.
                var head = await ReadRequestHeadAsync(ssl, token);
                if (head == null)
                {
                    await WriteStatusAsync(ssl, 400, "Bad Request", token);
                    return;
                }

                await HandleRequestAsync(ssl, head.Value.method, head.Value.target, head.Value.range, token);
            }
            catch
            {
                // Handshake rejected, peer vanished mid-transfer, timeout — all
                // routine on a LAN. The peer's own source fallback covers it.
            }
            finally
            {
                ssl?.Dispose();
            }
        }
    }

    /// <summary>
    /// Accept a peer only when its certificate chains to this tenant's issuing
    /// CA. Without a known CA we refuse rather than serving to anyone.
    /// </summary>
    private static bool ValidatePeerCertificate(
        object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate == null) return false;
        try
        {
            var caThumbprint = GrpcBridgeSingleton.Instance.IssuingCaThumbprint;
            if (string.IsNullOrWhiteSpace(caThumbprint)) return false;

            // Same lookup order the gRPC bridge uses: the issuing CA normally
            // lands in the Intermediate store, with Root as the fallback.
            var expectedCa = LoadCertByThumbprint(StoreName.CertificateAuthority, caThumbprint!)
                             ?? LoadCertByThumbprint(StoreName.Root, caThumbprint!);
            if (expectedCa == null) return false;

            var peerCert = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
            using var customChain = new X509Chain();
            customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            customChain.ChainPolicy.ExtraStore.Add(expectedCa);

            if (!customChain.Build(peerCert)) return false;

            var expected = Normalize(caThumbprint!);
            return customChain.ChainElements
                .Cast<X509ChainElement>()
                .Any(e => Normalize(e.Certificate.Thumbprint ?? "") == expected);
        }
        catch
        {
            return false;
        }
    }

    // ── Minimal HTTP/1.1 ─────────────────────────────────────────────────

    private static async Task<(string method, string target, string? range)?> ReadRequestHeadAsync(
        SslStream ssl, CancellationToken token)
    {
        var buffer = new byte[MaxRequestHeadBytes];
        var used = 0;
        while (used < buffer.Length)
        {
            var read = await ssl.ReadAsync(buffer.AsMemory(used, buffer.Length - used), token);
            if (read <= 0) return null;
            used += read;
            var text = Encoding.ASCII.GetString(buffer, 0, used);
            var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end < 0) continue;

            var lines = text[..end].Split("\r\n");
            var requestLine = lines.Length > 0 ? lines[0].Split(' ') : Array.Empty<string>();
            if (requestLine.Length < 2) return null;

            string? range = null;
            foreach (var line in lines.Skip(1))
            {
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;
                if (line[..colon].Trim().Equals("Range", StringComparison.OrdinalIgnoreCase))
                {
                    range = line[(colon + 1)..].Trim();
                }
            }
            return (requestLine[0], requestLine[1], range);
        }
        return null; // head too large
    }

    private static async Task HandleRequestAsync(
        SslStream ssl, string method, string target, string? rangeHeader, CancellationToken token)
    {
        var isHead = method.Equals("HEAD", StringComparison.OrdinalIgnoreCase);
        if (!isHead && !method.Equals("GET", StringComparison.OrdinalIgnoreCase))
        {
            await WriteStatusAsync(ssl, 405, "Method Not Allowed", token);
            return;
        }

        var path = target.Split('?')[0];
        var match = BlobPathRegex.Match(path);
        if (!match.Success)
        {
            await WriteStatusAsync(ssl, 404, "Not Found", token);
            return;
        }

        var sha = match.Groups[1].Value.ToLowerInvariant();
        var file = Path.Combine(CacheDir, sha);
        // Defence in depth: the regex already forbids traversal, but resolve
        // and re-check that we stay inside the cache root.
        var full = Path.GetFullPath(file);
        var root = Path.GetFullPath(CacheDir) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
        {
            await WriteStatusAsync(ssl, 404, "Not Found", token);
            return;
        }

        var info = new FileInfo(full);
        var total = info.Length;
        var range = ParseRange(rangeHeader, total);

        // Bump last-write so LRU eviction treats a served blob as fresh.
        try { File.SetLastWriteTimeUtc(full, DateTime.UtcNow); } catch { }

        long start = 0, end = total - 1;
        var partial = false;
        if (range.HasValue)
        {
            start = range.Value.start;
            end = range.Value.end;
            partial = true;
        }
        var length = end - start + 1;

        var head = new StringBuilder();
        head.Append(partial ? "HTTP/1.1 206 Partial Content\r\n" : "HTTP/1.1 200 OK\r\n");
        head.Append("Content-Type: application/octet-stream\r\n");
        head.Append("Accept-Ranges: bytes\r\n");
        head.Append($"Content-Length: {length}\r\n");
        if (partial) head.Append($"Content-Range: bytes {start}-{end}/{total}\r\n");
        head.Append("Connection: close\r\n\r\n");
        await ssl.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()), token);

        if (isHead)
        {
            await ssl.FlushAsync(token);
            return;
        }

        using var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read,
            StreamCopyBufferBytes, useAsync: true);
        fs.Seek(start, SeekOrigin.Begin);

        var buffer = new byte[StreamCopyBufferBytes];
        var remaining = length;
        while (remaining > 0)
        {
            var want = (int)Math.Min(buffer.Length, remaining);
            var read = await fs.ReadAsync(buffer.AsMemory(0, want), token);
            if (read <= 0) break;
            await ssl.WriteAsync(buffer.AsMemory(0, read), token);
            remaining -= read;
        }
        await ssl.FlushAsync(token);
    }

    /// <summary>
    /// Parse a single byte range against a known size. Returns null for absent,
    /// malformed, multi-range or unsatisfiable input — the caller then serves
    /// the whole entity, which is always a valid response.
    /// </summary>
    internal static (long start, long end)? ParseRange(string? header, long size)
    {
        if (string.IsNullOrWhiteSpace(header) || size <= 0) return null;
        var m = Regex.Match(header.Trim(), @"^bytes=(\d*)-(\d*)$");
        if (!m.Success) return null;

        var startRaw = m.Groups[1].Value;
        var endRaw = m.Groups[2].Value;

        if (startRaw.Length == 0)
        {
            // Suffix form: last N bytes.
            if (!long.TryParse(endRaw, out var suffix) || suffix <= 0) return null;
            var s = Math.Max(0, size - suffix);
            return (s, size - 1);
        }

        if (!long.TryParse(startRaw, out var start) || start < 0 || start >= size) return null;
        var end = size - 1;
        if (endRaw.Length > 0)
        {
            if (!long.TryParse(endRaw, out var parsedEnd)) return null;
            end = Math.Min(parsedEnd, size - 1);
        }
        return end < start ? null : (start, end);
    }

    private static async Task WriteStatusAsync(SslStream ssl, int code, string reason, CancellationToken token)
    {
        var payload = $"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        await ssl.WriteAsync(Encoding.ASCII.GetBytes(payload), token);
        await ssl.FlushAsync(token);
    }

    // ── IPC handlers ─────────────────────────────────────────────────────

    public static async Task<PrivSvcResponse> HandlePrefetch(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var sha256 = (Sdp.GetString(p, "sha256") ?? "").ToLowerInvariant();
            if (!Regex.IsMatch(sha256, "^[0-9a-f]{64}$"))
            {
                return PrivSvcResponse.Fail(req.Id, "bad_request", "sha256 must be a 64-char hex string");
            }

            var timeoutSeconds = Math.Max(60, Sdp.GetInt(p, "timeoutSeconds") ?? DefaultPrefetchTimeoutSeconds);
            var rateLimitKbps = Math.Max(0, Sdp.GetInt(p, "rateLimitKbps") ?? 0);
            var cacheMaxBytes = Sdp.GetLong(p, "cacheMaxBytes") is long cm && cm > 0
                ? cm
                : DefaultCacheMaxBytes;

            Directory.CreateDirectory(CacheDir);
            var cacheFile = Path.Combine(CacheDir, sha256);

            // Already cached and intact: just make sure we're listening.
            if (File.Exists(cacheFile) && await FileSha256Async(cacheFile) == sha256)
            {
                var warmReason = EnsureServer();
                return PrivSvcResponse.Success(req.Id, new
                {
                    ready = warmReason == null,
                    cached = true,
                    port = Port,
                    serverReason = warmReason,
                });
            }

            var sources = Sdp.ExtractSources(p);
            if (sources.Count == 0)
            {
                return PrivSvcResponse.Fail(req.Id, "bad_request", "no usable sources for prefetch");
            }

            var lastError = "";
            foreach (var (tier, url) in sources)
            {
                // The DP warms itself through the WAN tiers; it never pulls
                // from another DP.
                if (string.Equals(tier, "dp", StringComparison.OrdinalIgnoreCase)) continue;

                var tmp = cacheFile + ".part-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
                var attempt = await Sdp.DownloadForDpAsync(url, tmp, sha256, timeoutSeconds, rateLimitKbps);
                if (!attempt.ok)
                {
                    TryDelete(tmp);
                    lastError = attempt.error ?? "download failed";
                    continue;
                }

                try
                {
                    if (File.Exists(cacheFile)) File.Delete(cacheFile);
                    File.Move(tmp, cacheFile);
                }
                catch (Exception ex)
                {
                    TryDelete(tmp);
                    lastError = ex.Message;
                    continue;
                }

                var evicted = EvictLru(cacheMaxBytes);
                var reason = EnsureServer();
                return PrivSvcResponse.Success(req.Id, new
                {
                    ready = reason == null,
                    cached = false,
                    servedFrom = tier,
                    evicted,
                    port = Port,
                    serverReason = reason,
                });
            }

            return PrivSvcResponse.Fail(req.Id, "download_failed",
                string.IsNullOrEmpty(lastError) ? "all sources failed" : lastError);
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "prefetch_failed", ex.Message);
        }
    }

    public static Task<PrivSvcResponse> HandleStatus(PrivSvcRequest req)
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            var files = new DirectoryInfo(CacheDir)
                .GetFiles()
                .Where(f => Regex.IsMatch(f.Name, "^[0-9a-f]{64}$"))
                .ToList();

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                serverRunning = ServerRunning,
                port = Port,
                cacheDir = CacheDir,
                blobCount = files.Count,
                cacheBytes = files.Sum(f => f.Length),
                serverError = _serverError,
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "status_failed", ex.Message));
        }
    }

    // ── Cache maintenance ────────────────────────────────────────────────

    /// <summary>
    /// Delete oldest-touched blobs until the cache fits under the cap.
    /// Returns how many were evicted.
    /// </summary>
    internal static int EvictLru(long maxBytes)
    {
        try
        {
            var files = new DirectoryInfo(CacheDir)
                .GetFiles()
                .Where(f => Regex.IsMatch(f.Name, "^[0-9a-f]{64}$"))
                .OrderBy(f => f.LastWriteTimeUtc)
                .ToList();

            var total = files.Sum(f => f.Length);
            var evicted = 0;
            foreach (var f in files)
            {
                if (total <= maxBytes) break;
                try
                {
                    var size = f.Length;
                    f.Delete();
                    total -= size;
                    evicted++;
                }
                catch { /* raced with a serve; skip */ }
            }
            return evicted;
        }
        catch
        {
            return 0;
        }
    }

    private static async Task<string> FileSha256Async(string path)
    {
        using var sha = SHA256.Create();
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            StreamCopyBufferBytes, useAsync: true);
        var hash = await sha.ComputeHashAsync(fs);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static string Normalize(string thumbprint) =>
        new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

    private static X509Certificate2? LoadCertByThumbprint(StoreName storeName, string thumbprint)
    {
        using var store = new X509Store(storeName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, Normalize(thumbprint), validOnly: false);
        return matches.Count > 0 ? matches[0] : null;
    }

    /// <summary>
    /// Relight the blob server at service start if this endpoint is a DP.
    ///
    /// ⚠️ THE CACHE SURVIVES A REBOOT; THE LISTENER DOES NOT. EnsureServer runs
    /// only from the two prefetch paths, so after any restart — an agent update,
    /// Windows Update, a power cut — this machine holds every cached blob on
    /// disk and answers on none of them. Nothing notices: the control plane
    /// reads "a prefetch completed recently" as "the DP is warm", which is a
    /// claim about the FILE, not about the port.
    ///
    /// Measured cost of that gap: a DP cached 1.1.53 at 01:41, self-updated at
    /// 01:43, and by 01:47 the endpoints behind it found a warm cache behind a
    /// dead port. 28 of 28 fell back to the internet, and the five with no WAN
    /// route failed outright. Left alone it would have stayed silent until the
    /// 24-hour re-assert prefetch came round.
    ///
    /// Gated on the cache having content, so a plain agent never opens a port
    /// it has no use for — the same rule TryEnsureFirewallRule already follows.
    /// Best effort: a DP that cannot listen is exactly today's behaviour, and
    /// the service must start regardless.
    /// </summary>
    public static void EnsureServerOnStartup(Action<string>? log = null)
    {
        try
        {
            if (!Directory.Exists(CacheDir)) return;
            if (!Directory.EnumerateFiles(CacheDir).Any()) return;

            var reason = EnsureServer();
            log?.Invoke(reason == null
                ? $"DP blob server relit on startup (port {Port})"
                : $"DP blob server could not start: {reason}");
        }
        catch (Exception ex)
        {
            log?.Invoke($"DP blob server startup check failed: {ex.Message}");
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    /// <summary>
    /// Open the LAN port for the DP role. Only runs when this endpoint has
    /// actually been designated (i.e. from EnsureServer), so a plain agent
    /// never gets an inbound rule it doesn't need. Best-effort: if it fails,
    /// peers simply can't reach us and fall through to cdn/origin.
    /// </summary>
    private static void TryEnsureFirewallRule()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            // Idempotent: drop any previous rule (port may have changed) then
            // add the current one.
            psi.ArgumentList.Add("advfirewall");
            psi.ArgumentList.Add("firewall");
            psi.ArgumentList.Add("delete");
            psi.ArgumentList.Add("rule");
            psi.ArgumentList.Add($"name={FirewallRuleName}");
            using (var del = Process.Start(psi)) { del?.WaitForExit(15_000); }

            var add = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            add.ArgumentList.Add("advfirewall");
            add.ArgumentList.Add("firewall");
            add.ArgumentList.Add("add");
            add.ArgumentList.Add("rule");
            add.ArgumentList.Add($"name={FirewallRuleName}");
            add.ArgumentList.Add("dir=in");
            add.ArgumentList.Add("action=allow");
            add.ArgumentList.Add("protocol=TCP");
            add.ArgumentList.Add($"localport={Port}");
            add.ArgumentList.Add("profile=domain,private");
            using var proc = Process.Start(add);
            proc?.WaitForExit(15_000);
        }
        catch
        {
            // Non-fatal by design.
        }
    }
}
