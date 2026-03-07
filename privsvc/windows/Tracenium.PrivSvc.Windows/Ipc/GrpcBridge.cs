// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs
using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using Grpc.Net.Client;
using Grpc.Core;
using Tracenium.Control; // namespace generado por proto

namespace Tracenium.PrivSvc.Windows.Grpc;

public sealed class GrpcBridge : IDisposable
{
    private readonly object _gate = new();

    private GrpcChannel? _channel;
    private ControlPlane.ControlPlaneClient? _client;
    private AsyncDuplexStreamingCall<ControlMessage, ControlMessage>? _call;
    private CancellationTokenSource? _cts;

    // Sender queue (facts)
    private BlockingCollection<ControlMessage> _sendQueue = new(1024);

    // Subscribers (pipe writers) para push -> Node
    private readonly ConcurrentDictionary<string, Action<object>> _pushSinks = new();

    public bool IsConnected { get; private set; }

    public void RegisterPushSink(string sinkId, Action<object> push)
        => _pushSinks[sinkId] = push;

    public void UnregisterPushSink(string sinkId)
        => _pushSinks.TryRemove(sinkId, out _);

    private void PushToAll(object msg)
    {
        foreach (var kv in _pushSinks)
        {
            try { kv.Value(msg); } catch { /* swallow */ }
        }
    }

    public void Connect(GrpcBridgeConnectOptions opt)
    {
        lock (_gate)
        {
            if (IsConnected) return;

            _cts = new CancellationTokenSource();

            // recreate per session to avoid using a Completed/old queue
            _sendQueue = new BlockingCollection<ControlMessage>(1024);

            var handler = new SocketsHttpHandler
            {
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
                KeepAlivePingDelay = TimeSpan.FromSeconds(20),
                KeepAlivePingTimeout = TimeSpan.FromSeconds(10),
                EnableMultipleHttp2Connections = true
            };

            var clientCert = LoadCertFromLocalMachineMyByThumbprint(opt.ClientCertThumbprint);

            handler.SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificates = new X509CertificateCollection
                {
                    clientCert
                },

                LocalCertificateSelectionCallback = (sender, targetHost, localCerts, remoteCert, acceptableIssuers) =>
                {
                    // Force selection of the agent mTLS certificate
                    return clientCert;
                },

                // Server certificate validation uses the OS trust store.
                // PROD: keep strict (SslPolicyErrors.None).
                // DEV: if you're using a private CA, install the Root CA into LocalMachine\\Root.
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    try
                    {
                        // If an issuing CA thumbprint is provided, validate that the server chain
                        // builds and contains that issuing CA (or root) certificate.
                        if (!string.IsNullOrWhiteSpace(opt.IssuingCaThumbprint))
                        {
                            var expectedCa = LoadCaCertFromLocalMachineByThumbprint(opt.IssuingCaThumbprint);

                            using var customChain = new X509Chain();
                            customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            customChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                            customChain.ChainPolicy.VerificationTime = DateTime.UtcNow;
                            customChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(2);

                            // Use OS trust, but also help the chain builder with the expected CA.
                            customChain.ChainPolicy.ExtraStore.Add(expectedCa);

                            var serverCert = cert as X509Certificate2 ?? new X509Certificate2(cert!);
                            var ok = customChain.Build(serverCert);
                            if (!ok) return false;

                            var expected = new string(opt.IssuingCaThumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
                            var found = customChain.ChainElements
                                .Cast<X509ChainElement>()
                                .Any(e => string.Equals(
                                    new string((e.Certificate.Thumbprint ?? "").Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant(),
                                    expected,
                                    StringComparison.OrdinalIgnoreCase));

                            return found;
                        }

                        // Default strict validation (requires server cert chain trusted by OS store)
                        return errors == SslPolicyErrors.None;
                    }
                    catch
                    {
                        return false;
                    }
                }
            };

            // Crear channel
            _channel = GrpcChannel.ForAddress(
                NormalizeTarget(opt.Target),
                new GrpcChannelOptions
                {
                    HttpHandler = handler
                });

            _client = new ControlPlane.ControlPlaneClient(_channel);

            _call = _client.Connect(cancellationToken: _cts.Token);

            // Start sender loop
            _ = Task.Run(() => SenderLoop(_cts.Token));

            // Start receiver loop
            _ = Task.Run(() => ReceiverLoop(opt, _cts.Token));

            // HELLO
            _call.RequestStream.WriteAsync(new ControlMessage
            {
                Hello = new Hello
                {
                    TenantId = opt.TenantId ?? "",
                    DeviceId = opt.DeviceId ?? "",
                    AgentVersion = opt.AgentVersion ?? ""
                }
            }).GetAwaiter().GetResult();

            IsConnected = true;
        }
    }

    public void SendFacts(string eventId, string payloadJson)
    {
        if (!IsConnected || _call is null) throw new InvalidOperationException("gRPC not connected");

        var msg = new ControlMessage
        {
            Facts = new Facts
            {
                EventId = eventId,
                PayloadJson = Google.Protobuf.ByteString.CopyFromUtf8(payloadJson ?? "{}")
            }
        };

        if (_sendQueue.IsAddingCompleted || !_sendQueue.TryAdd(msg))
            throw new InvalidOperationException("send queue full");
    }

    public void Close()
    {
        lock (_gate)
        {
            if (!IsConnected) return;
            IsConnected = false;

            // unblock sender loop
            try { _sendQueue.CompleteAdding(); } catch { }

            try { _cts?.Cancel(); } catch { }

            try { _call?.RequestStream.CompleteAsync().GetAwaiter().GetResult(); } catch { }
            try { _call?.Dispose(); } catch { }

            try { _channel?.Dispose(); } catch { }

            _call = null;
            _client = null;
            _channel = null;

            try { _cts?.Dispose(); } catch { }
            _cts = null;

            // Notify Node that the bridge is disconnected
            PushToAll(new
            {
                v = 1,
                method = "win.grpc.disconnected",
                @params = new { atUtc = DateTime.UtcNow.ToString("o") }
            });
        }
    }

    private async Task SenderLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            ControlMessage msg;
            try
            {
                msg = _sendQueue.Take(ct);
            }
            catch { break; }

            try
            {
                var call = _call;
                if (call is null) continue;
                await call.RequestStream.WriteAsync(msg);
            }
            catch (Exception ex)
            {
                // Si falla write, empuja evento de control para Node
                PushToAll(new
                {
                    v = 1,
                    method = "win.grpc.control.streamError",
                    @params = new { message = ex.Message, atUtc = DateTime.UtcNow.ToString("o") }
                });
            }
        }
    }

    private async Task ReceiverLoop(GrpcBridgeConnectOptions opt, CancellationToken ct)
    {
        try
        {
            var call = _call!;
            while (await call.ResponseStream.MoveNext(ct))
            {
                var msg = call.ResponseStream.Current;

                if (msg.Ack is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "win.grpc.ack",
                        @params = new
                        {
                            eventId = msg.Ack.EventId,
                            status = (int)msg.Ack.Status,
                            message = msg.Ack.Message ?? "",
                            receivedAtUtc = msg.Ack.ReceivedAtUtc ?? DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.RotateCert is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "win.grpc.control.rotateCert",
                        @params = new
                        {
                            reason = msg.RotateCert.Reason ?? "server_request",
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.RunJob is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "win.grpc.control.runJob",
                        @params = new
                        {
                            jobId = msg.RunJob.JobId ?? "",
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }
            }
        }
        catch (Exception ex)
        {
            PushToAll(new
            {
                v = 1,
                method = "win.grpc.control.receiverError",
                @params = new { message = ex.Message, atUtc = DateTime.UtcNow.ToString("o") }
            });
        }
        finally
        {
            // Si el stream termina, notifícalo para que Node reintente
            PushToAll(new
            {
                v = 1,
                method = "win.grpc.disconnected",
                @params = new { atUtc = DateTime.UtcNow.ToString("o") }
            });

            Close();
        }
    }

    private static string NormalizeTarget(string target)
    {
        // Accepts: "host:port", "https://host:port", "http://host:port"
        // GrpcChannel.ForAddress requires an absolute URI.
        var t = (target ?? "").Trim();
        if (t.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            return t;
        }

        // Default to https because we are doing mTLS
        return $"https://{t}";
    }

    private static X509Certificate2 LoadCertFromLocalMachineMyByThumbprint(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
            throw new ArgumentException("thumbprint is required", nameof(thumbprint));

        var normalized = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
        if (matches.Count == 0)
            throw new InvalidOperationException($"Client cert not found in LocalMachine\\My: {normalized}");

        // Prefer a cert that actually has the private key linked.
        // This avoids selecting a "public-only" duplicate that would break mTLS.
        foreach (var c in matches)
        {
            if (c.HasPrivateKey)
                return c;
        }

        throw new InvalidOperationException("Client cert found but has no private key association (HasPrivateKey=false)");
    }

    private static X509Certificate2 LoadCaCertFromLocalMachineByThumbprint(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
            throw new ArgumentException("thumbprint is required", nameof(thumbprint));

        var normalized = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

        // 1) Try Intermediate CA store
        using (var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
            if (matches.Count > 0)
                return matches[0];
        }

        // 2) Try Root store
        using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
            if (matches.Count > 0)
                return matches[0];
        }

        throw new InvalidOperationException($"Issuing/Root CA cert not found in LocalMachine\\CA or LocalMachine\\Root: {normalized}");
    }

    public void Dispose() => Close();
}

public sealed class GrpcBridgeConnectOptions
{
    public required string Target { get; init; }              // "localhost:50051"
    public required string ClientCertThumbprint { get; init; }// del cert en LocalMachine\My
    public string? IssuingCaThumbprint { get; init; }         // CA en LocalMachine\\CA o LocalMachine\\Root
    public string? TenantId { get; init; }
    public string? DeviceId { get; init; }
    public string? AgentVersion { get; init; }
}