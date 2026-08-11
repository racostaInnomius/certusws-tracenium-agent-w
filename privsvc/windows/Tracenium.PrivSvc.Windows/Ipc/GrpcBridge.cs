// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs
using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;
using System.Diagnostics;
using System.Text;
using System.Linq;
using Grpc.Net.Client;
using Grpc.Core;
using Tracenium.Control; // namespace generado por proto

namespace Tracenium.PrivSvc.Windows.Grpc;

public sealed class GrpcBridge : IDisposable
{
    private readonly object _gate = new();
    private readonly object _reconnectGate = new();
    private readonly SemaphoreSlim _connectLock = new(1, 1);
    private Task? _receiverTask;
    private Task? _senderTask;
    private Task? _watchdogTask;
    private Task? _heartbeatTask;
    private DateTime _connectedAtUtc = DateTime.MinValue;
    private DateTime _lastReceiveUtc = DateTime.MinValue;
    private DateTime _lastSendUtc = DateTime.MinValue;
    private DateTime _lastAckUtc = DateTime.MinValue;
    private int _reconnectAttempt = 0;
    private bool _closeRequested = false;
    private bool _reconnectScheduled = false;
    private GrpcBridgeConnectOptions? _lastConnectOptions;
    private long _helloStartTicks = 0;
    private string? _helloEventId = null;
    // HELLO handshake gate: FACTS must not be sent before HELLO ACK
    private volatile bool _helloAcked = false;
    private TaskCompletionSource<bool> _helloAckTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static readonly TimeSpan _deadStreamThreshold = TimeSpan.FromSeconds(150);
    private static readonly TimeSpan _watchdogInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan _minReconnectDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan _maxReconnectDelay = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan _heartbeatInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan _helloAckTimeout = TimeSpan.FromSeconds(30);

    // ── Self-rescue thresholds ────────────────────────────────────────
    //
    // When the bridge can't complete a HELLO ACK handshake across many
    // reconnect cycles, exit the process so the Windows Service Control
    // Manager restarts privsvc with a brand-new socket pool, DNS resolver
    // cache, and gRPC channel. PrivSvc.wxs configures SCM failure
    // actions (restart with 5s delay) so the next process spawns clean.
    //
    // The threshold (10 consecutive failures, ~10 minutes with the
    // backoff cap at 60s) is the trade-off between "tolerate transient
    // network flaps" and "don't leave a host stuck for hours pretending
    // to be online while the agent can't actually process anything".
    // Real-world precedent: device 7d1162d7-...-08c7a62f20b4 stayed in
    // the flap pattern for 30+ minutes during the 1.1.21→1.1.21 rollout,
    // ate an agent_update job that ended in status=timeout, and required
    // a manual `Restart-Service Tracenium*` to recover. The agent must
    // be able to do that for itself.
    //
    // _helloSendStuckThreshold covers the specific failure mode where
    // the HELLO message can't even reach the wire (the gRPC subchannel
    // resolution is stuck): without this, HelloTimeoutLoop just logs
    // "HELLO timeout ignored: HELLO not fully sent yet" forever without
    // escalating. 60s is long enough to skip transient TLS/DNS hiccups
    // and short enough to flip the bridge into a clean reconnect cycle.
    private const int _maxConsecutiveReconnectFailures = 10;
    private static readonly TimeSpan _helloSendStuckThreshold = TimeSpan.FromSeconds(60);
    private bool _exitTriggered = false;

    private enum BridgeState
    {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Closing
    }

private BridgeState _state = BridgeState.Disconnected;

    private static readonly string _logDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium",
            "PrivSvc",
            "logs");

    // Tope de tamaño por archivo. Antes solo había límite por CANTIDAD
    // (5 archivos) sin tope de bytes: un día con tormenta de
    // reconexiones podía escribir un único archivo enorme. Al superarlo
    // se corta y se sigue en un archivo nuevo del mismo día
    // (grpcbridge-YYYYMMDD.2.log), que CleanupOldLogs también recorta.
    // Cota dura resultante: 5 archivos × 5 MB = 25 MB.
    private const long MaxLogBytes = 5 * 1024 * 1024;

    // CleanupOldLogs enumeraba el directorio en CADA línea de log
    // (GetFiles + Select + OrderBy por línea). Con el bridge hablador
    // eso es un montón de I/O innecesario, así que se limita a una
    // pasada cada 5 minutos.
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static DateTime _lastCleanupUtc = DateTime.MinValue;

    private static string GetDailyLogPath()
    {
        var stem = $"grpcbridge-{DateTime.UtcNow:yyyyMMdd}";
        var path = Path.Combine(_logDir, $"{stem}.log");

        try
        {
            // Si el archivo del día ya llegó al tope, seguimos en el
            // siguiente índice libre del mismo día.
            if (new FileInfo(path) is { Exists: true, Length: > MaxLogBytes })
            {
                for (var i = 2; i < 100; i++)
                {
                    var rolled = Path.Combine(_logDir, $"{stem}.{i}.log");
                    var info = new FileInfo(rolled);
                    if (!info.Exists || info.Length <= MaxLogBytes)
                        return rolled;
                }
            }
        }
        catch
        {
            // Ante cualquier duda, escribir en el archivo del día.
        }

        return path;
    }

    private static void CleanupOldLogs()
    {
        try
        {
            if (!Directory.Exists(_logDir))
                return;

            if (DateTime.UtcNow - _lastCleanupUtc < CleanupInterval)
                return;
            _lastCleanupUtc = DateTime.UtcNow;

            var files = Directory.GetFiles(_logDir, "grpcbridge-*.log")
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.CreationTimeUtc)
                .ToList();

            // Keep only last 5 files
            foreach (var file in files.Skip(5))
            {
                try { file.Delete(); } catch { }
            }
        }
        catch
        {
            // never break logging
        }
    }

    private static void Log(string message)
    {
        try
        {
            var dir = _logDir;
            if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            CleanupOldLogs();

            var logPath = GetDailyLogPath();

            var line = $"[{DateTime.UtcNow:O}] {message}{Environment.NewLine}";
            File.AppendAllText(logPath, line);
        }
        catch
        {
            // logging must never break execution
        }
    }

    private static double ElapsedMs(long startTicks)
    {
        if (startTicks <= 0) return 0;
        return (Stopwatch.GetTimestamp() - startTicks) * 1000.0 / Stopwatch.Frequency;
    }

    private static TimeSpan ComputeReconnectDelay(int attempt)
    {
        if (attempt < 0) attempt = 0;
        var seconds = Math.Min(_maxReconnectDelay.TotalSeconds, _minReconnectDelay.TotalSeconds * Math.Pow(2, attempt));
        return TimeSpan.FromSeconds(seconds);
    }

    private void ScheduleReconnect(string reason)
    {
        lock (_reconnectGate)
        {
            if (_closeRequested) return;
            if (_lastConnectOptions == null) return;
            if (_reconnectScheduled) return;
            if (_state == BridgeState.Closing) return;

            _state = BridgeState.Reconnecting;

            _reconnectScheduled = true;

            _reconnectAttempt++;
            var delay = ComputeReconnectDelay(_reconnectAttempt);
            Log($"Scheduling reconnect attempt={_reconnectAttempt} delay={delay.TotalSeconds}s reason={reason}");

            // ── Self-rescue: SCM-mediated process restart ─────────────
            //
            // The counter only grows past 1 when HELLO ACK never lands —
            // _reconnectAttempt resets in the HELLO ACK handler, not here.
            // Crossing the threshold therefore means we've spent ~10
            // minutes of exponential backoff without ever completing a
            // handshake, so an in-process recovery isn't going to help.
            // Exit the service and let SCM (configured by PrivSvc.wxs
            // <util:ServiceConfig>) restart us with fresh OS-level
            // resources (sockets, DNS resolver, gRPC channel pool).
            if (_reconnectAttempt > _maxConsecutiveReconnectFailures && !_exitTriggered)
            {
                _exitTriggered = true;
                Log($"CRITICAL: bridge stuck after {_reconnectAttempt} consecutive failed HELLO ACKs — exiting for SCM restart (reason={reason})");
                try
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.selfRescue",
                        @params = new
                        {
                            consecutiveFailures = _reconnectAttempt,
                            lastReason = reason,
                            atUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }
                catch { /* never let push errors block exit */ }
                // Fire-and-forget so we release the reconnect lock before
                // the runtime tears the process down. 250ms gives the
                // last log line time to flush.
                _ = Task.Run(async () =>
                {
                    await Task.Delay(250);
                    Environment.Exit(2);
                });
                return;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(delay);
                    if (_closeRequested) return;
                    if (IsConnected)
                    {
                        Log("Reconnect skipped: already connected");
                        return;
                    }
                    var opt = _lastConnectOptions;
                    if (opt == null) return;
                    try
                    {
                        await Connect(opt);
                    }
                    finally
                    {
                        lock (_reconnectGate)
                        {
                            _reconnectScheduled = false;
                            if (_state == BridgeState.Reconnecting)
                                _state = BridgeState.Disconnected;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log($"Reconnect task error {ex}");
                }
            });
        }
    }

    private async Task WatchdogLoop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(_watchdogInterval, ct);

                if (!IsConnected || _call is null)
                    continue;

                var now = DateTime.UtcNow;
                var lastActivity = new[]
                {
                    _lastReceiveUtc,
                    _lastSendUtc,
                    _lastAckUtc
                }.Max();

                if (lastActivity == DateTime.MinValue)
                    lastActivity = _connectedAtUtc;

                if (lastActivity != DateTime.MinValue && (now - lastActivity) > _deadStreamThreshold)
                {
                    Log($"Dead stream detected. connectedAt={_connectedAtUtc:O} lastSend={_lastSendUtc:O} lastReceive={_lastReceiveUtc:O} lastAck={_lastAckUtc:O}");
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.deadStream",
                        @params = new
                        {
                            connectedAtUtc = _connectedAtUtc == DateTime.MinValue ? null : _connectedAtUtc.ToString("o"),
                            lastSendUtc = _lastSendUtc == DateTime.MinValue ? null : _lastSendUtc.ToString("o"),
                            lastReceiveUtc = _lastReceiveUtc == DateTime.MinValue ? null : _lastReceiveUtc.ToString("o"),
                            lastAckUtc = _lastAckUtc == DateTime.MinValue ? null : _lastAckUtc.ToString("o")
                        }
                    });
                    Close();
                    ScheduleReconnect("dead_stream_watchdog");
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            Log("WatchdogLoop canceled");
        }
        catch (Exception ex)
        {
            Log($"WatchdogLoop error {ex}");
        }
    }

    private GrpcChannel? _channel;
    private ControlPlane.ControlPlaneClient? _client;
    private AsyncDuplexStreamingCall<ControlMessage, ControlMessage>? _call;
    private CancellationTokenSource? _cts;

    // Sender queue (facts)
    private BlockingCollection<ControlMessage> _sendQueue = new(1024);
    // Deduplication guard to avoid sending the same event repeatedly
    private readonly ConcurrentDictionary<string, DateTime> _recentEventIds = new();
    private static readonly TimeSpan _dedupWindow = TimeSpan.FromMinutes(2);
    // gRPC write lock: ensures only one WriteAsync happens at a time
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // Centralized safe write helper to guarantee serialization of all gRPC writes
    private async Task SafeWriteAsync(ControlMessage message, CancellationToken ct)
    {
        var call = _call;
        // Allow HELLO to be sent even if IsConnected == false (handshake phase)
        var isHello = message.Hello != null;

        if (call is null || (_closeRequested) || _cts == null || _cts.IsCancellationRequested)
        {
            Log("SafeWriteAsync skipped: stream not available");
            return;
        }

        // Do not block writes based on IsConnected; rely on actual stream availability
        // (HELLO/ACK/CONTROL messages must be allowed during transient state transitions)

        await _writeLock.WaitAsync(ct);
        try
        {
            try
            {
                await call.RequestStream.WriteAsync(message).WaitAsync(TimeSpan.FromSeconds(30), ct);
            }
            catch (TimeoutException)
            {
                Log("SafeWriteAsync timeout — triggering reconnect");
                Close();
                ScheduleReconnect("write_timeout");
                return;
            }
            catch (ObjectDisposedException)
            {
                Log("SafeWriteAsync disposed during shutdown");
            }
            catch (RpcException ex) when (ex.StatusCode == StatusCode.Cancelled)
            {
                Log("SafeWriteAsync cancelled due to stream shutdown");
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // Subscribers (pipe writers) para push -> Node
private readonly ConcurrentDictionary<string, Action<object>> _pushSinks = new();
// Last connection notification so it can be replayed to late subscribers
private object? _lastConnectionPush;

// Buffer for push events when no sinks are available
private readonly ConcurrentQueue<object> _pendingPushEvents = new();
private const int MaxPendingPushEvents = 50;

    private volatile bool _isConnected;
    public bool IsConnected
    {
        get => _isConnected;
        private set => _isConnected = value;
    }

    public bool IsReady => IsConnected && _helloAcked && _state == BridgeState.Connected;

    public async Task<bool> WaitForReadyAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        if (IsReady)
            return true;

        var effectiveTimeout = timeout ?? _helloAckTimeout;

        try
        {
            await _helloAckTcs.Task.WaitAsync(effectiveTimeout, cancellationToken);
            return IsReady;
        }
        catch (TimeoutException)
        {
            Log($"WaitForReadyAsync timeout after {effectiveTimeout.TotalSeconds}s");
            return false;
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
                throw;

            Log("WaitForReadyAsync canceled");
            return false;
        }
    }

    public void RegisterPushSink(string sinkId, Action<object> push)
    {
        _pushSinks[sinkId] = push;

        Log($"RegisterPushSink: sinkId={sinkId} totalSinks={_pushSinks.Count}");

        // Always attempt replay if we already have a connection event
        if (_lastConnectionPush != null)
        {
            try
            {
                Log($"Replaying cached grpc.connected to new sink sinkId={sinkId}");
                push(_lastConnectionPush);
            }
            catch (Exception ex)
            {
                Log($"Push sink replay error {ex}");
            }

            // Replay buffered events (e.g., runJob that arrived before Node was ready)
            while (_pendingPushEvents.TryDequeue(out var pending))
            {
                try
                {
                    Log($"Replaying buffered event to sink sinkId={sinkId}");
                    push(pending);
                }
                catch (Exception ex)
                {
                    Log($"Buffered push replay error {ex}");
                    break; // stop replay if sink is failing
                }
            }
            return;
        }

        // Fallback: if HELLO already ACKed but cache somehow not set
        if (_helloAcked && _lastConnectOptions != null)
        {
            var evt = new
            {
                v = 1,
                method = "grpc.connected",
                @params = new
                {
                    target = _lastConnectOptions.Target,
                    atUtc = DateTime.UtcNow.ToString("o"),
                    replay = true,
                    fallback = true
                }
            };

            _lastConnectionPush = evt;

            try
            {
                Log($"Replaying synthesized grpc.connected (fallback) sinkId={sinkId}");
                push(evt);
            }
            catch (Exception ex)
            {
                Log($"Push sink replay error {ex}");
            }
        }

        // Replay buffered events (e.g., runJob that arrived before Node was ready)
        while (_pendingPushEvents.TryDequeue(out var pending))
        {
            try
            {
                Log($"Replaying buffered event to sink sinkId={sinkId}");
                push(pending);
            }
            catch (Exception ex)
            {
                Log($"Buffered push replay error {ex}");
                break; // stop replay if sink is failing
            }
        }
    }

    public void UnregisterPushSink(string sinkId)
        => _pushSinks.TryRemove(sinkId, out _);

    public void ReplayPendingEvents(string sinkId)
    {
        if (string.IsNullOrWhiteSpace(sinkId)) return;

        if (!_pushSinks.TryGetValue(sinkId, out var push))
        {
            Log($"ReplayPendingEvents: sink not found sinkId={sinkId}");
            return;
        }

        Log($"ReplayPendingEvents: starting replay sinkId={sinkId}");

        while (_pendingPushEvents.TryDequeue(out var pending))
        {
            try
            {
                Log($"Replaying buffered event to sink sinkId={sinkId}");
                push(pending);
            }
            catch (Exception ex)
            {
                Log($"Buffered push replay error {ex}");
                break;
            }
        }
    }

    private void PushToAll(object msg)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(msg);
            Log($"PushToAll dispatching message: {json}");
        }
        catch { }

        Log($"PushToAll sinks count={_pushSinks.Count}");

        if (_pushSinks.IsEmpty)
        {
            Log("No push sinks registered — buffering event");

            _pendingPushEvents.Enqueue(msg);

            while (_pendingPushEvents.Count > MaxPendingPushEvents && _pendingPushEvents.TryDequeue(out _))
            {
                // drop oldest
            }

            return;
        }

        foreach (var kv in _pushSinks)
        {
            try
            {
                Log($"PushToAll invoking sinkId={kv.Key}");
                Task.Run(() =>
                {
                    try
                    {
                        kv.Value(msg);
                        Log($"PushToAll delivered sinkId={kv.Key}");
                    }
                    catch (Exception ex)
                    {
                        Log($"Push sink error sinkId={kv.Key} {ex}");
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"Push sink error sinkId={kv.Key} {ex}");
            }
        }
    }

    public async Task Connect(GrpcBridgeConnectOptions opt)
    {
        await _connectLock.WaitAsync();
        try
        {
            lock (_gate)
            {
                if (_state == BridgeState.Connected || _state == BridgeState.Connecting)
                    return;

                _state = BridgeState.Connecting;

                _lastConnectOptions = opt;
                _closeRequested = false;
                Log($"Connect requested. Target={opt.Target} DeviceId={opt.DeviceId} ReconnectAttempt={_reconnectAttempt}");

                _cts = new CancellationTokenSource();
                _connectedAtUtc = DateTime.UtcNow;
                _lastReceiveUtc = DateTime.MinValue;
                _lastSendUtc = DateTime.MinValue;
                _lastAckUtc = DateTime.MinValue;
                _helloStartTicks = 0;
                _helloEventId = null;
                _helloAcked = false;

                // recreate HELLO ACK gate per connection to avoid stale completed tasks
                _helloAckTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

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

                Log($"Client certificate loaded Thumbprint={clientCert.Thumbprint} HasPrivateKey={clientCert.HasPrivateKey}");

                handler.SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificates = new X509CertificateCollection
                    {
                        clientCert
                    },

                    LocalCertificateSelectionCallback = (sender, targetHost, localCerts, remoteCert, acceptableIssuers) =>
                    {
                        return clientCert;
                    },

                    RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                    {
                        try
                        {
                            Log($"Server certificate validation invoked Errors={errors}");

                            // SslStream properties like SslProtocol are not available until authentication
                            // completes, so only log basic certificate information here.

                            if (!string.IsNullOrWhiteSpace(opt.IssuingCaThumbprint))
                            {
                                var expectedCa = LoadCaCertFromLocalMachineByThumbprint(opt.IssuingCaThumbprint);

                                using var customChain = new X509Chain();
                                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                                customChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                                customChain.ChainPolicy.VerificationTime = DateTime.UtcNow;
                                customChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(2);

                                customChain.ChainPolicy.ExtraStore.Add(expectedCa);

                                var serverCert = cert as X509Certificate2 ?? new X509Certificate2(cert!);

                                Log($"Server cert subject={serverCert.Subject}");
                                Log($"Server cert issuer={serverCert.Issuer}");
                                Log($"Server cert thumbprint={serverCert.Thumbprint}");

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

                            if (errors == SslPolicyErrors.None)
                            {
                                return true;
                            }

                            Log($"Server certificate validation failed with policy errors={errors}");
                            return false;
                        }
                        catch (Exception ex)
                        {
                            Log($"Server certificate validation error {ex}");
                            return false;
                        }
                    }
                };

                _channel = GrpcChannel.ForAddress(
                    NormalizeTarget(opt.Target),
                    new GrpcChannelOptions
                    {
                        HttpHandler = handler
                    });

                Log("gRPC channel created");

                _client = new ControlPlane.ControlPlaneClient(_channel);

                _call = _client.Connect(cancellationToken: _cts.Token);

                Log("gRPC streaming call started");

                _receiverTask = Task.Run(() => ReceiverLoop(opt, _cts.Token));

                _ = Task.Run(async () =>
                {
                    try
                    {
                        // Harden HELLO send task against race
                        if (_call == null || _cts == null || _closeRequested || _cts.IsCancellationRequested)
                        {
                            Log("HELLO skipped: connection no longer valid");
                            return;
                        }
                        var call = _call;
                        if (call != null)
                        {
                            _helloStartTicks = Stopwatch.GetTimestamp();
                            _helloEventId = Guid.NewGuid().ToString("N");
                            var helloMsg = new ControlMessage
                            {
                                Hello = new Hello
                                {
                                    EventId = _helloEventId,
                                    TenantId = opt.TenantId ?? string.Empty,
                                    DeviceId = opt.DeviceId ?? string.Empty,
                                    AgentVersion = opt.AgentVersion ?? string.Empty,
                                    ProtocolVersion = opt.ProtocolVersion ?? string.Empty,
                                    PolicyVersion = opt.PolicyVersion ?? string.Empty
                                }
                            };

                            helloMsg.Hello.Capabilities.AddRange(
                                (opt.Capabilities ?? Enumerable.Empty<string>())
                                    .Where(capability => !string.IsNullOrWhiteSpace(capability))
                                    .Select(capability => capability.Trim())
                                    .Distinct()
                            );

                            await SafeWriteAsync(helloMsg, _cts.Token);
                            _lastSendUtc = DateTime.UtcNow;
                            Log("HELLO message sent");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"HELLO send error {ex}");

                        if (ex is TaskCanceledException)
                        {
                            Log("HELLO send canceled during connect race — ignoring");
                            return;
                        }

                        PushToAll(new
                        {
                            v = 1,
                            method = "grpc.control.helloError",
                            @params = new { message = ex.Message, atUtc = DateTime.UtcNow.ToString("o") }
                        });
                    }      
                });

                _senderTask = Task.Run(() => SenderLoop(_cts.Token));
                _watchdogTask = Task.Run(() => WatchdogLoop(_cts.Token));
                _heartbeatTask = Task.Run(() => HeartbeatLoop(_cts.Token));
                _ = Task.Run(() => HelloTimeoutLoop(_cts.Token));

                IsConnected = false; // will be set to true upon HELLO ACK
                _state = BridgeState.Connecting;
                _reconnectScheduled = false;

                // _reconnectAttempt is INTENTIONALLY NOT reset here.
                //
                // Before the self-rescue work, the counter was zeroed as
                // soon as the gRPC channel was created — but channel
                // creation is cheap and happens even when the host's
                // network can't actually complete a HELLO. The result:
                // bridge could flap forever with attempt=1 because every
                // failed-handshake cycle reset the counter on the next
                // attempt. The threshold-based self-rescue couldn't ever
                // trigger.
                //
                // Reset moved to the HELLO ACK handler (~L1000) — the
                // only point where we KNOW the handshake actually
                // completed end-to-end.

                Log($"GrpcBridge connected connectedAt={_connectedAtUtc:O}");

                // DO NOT emit connected here — wait for HELLO ACK to confirm readiness
                _lastConnectionPush = null;
            }
        }
        finally
        {
            _connectLock.Release();
        }
    }

    public void SendFacts(string eventId, string payloadJson, string? factNamespace = null, IEnumerable<string>? namespaces = null)
    {
        if (!IsConnected || _call is null)
            throw new InvalidOperationException("gRPC not connected");

        // Deduplicate same eventId within short window
        if (_recentEventIds.TryGetValue(eventId, out var lastSent))
        {
            if (DateTime.UtcNow - lastSent < _dedupWindow)
            {
                Log($"Duplicate FACTS suppressed eventId={eventId}");
                return;
            }
        }

        if (!_helloAcked)
        {
            Log($"FACTS queued before HELLO ACK (will wait in sender) eventId={eventId}");
        }
        else
        {
            Log($"Queueing FACTS event {eventId}");
        }

        var msg = new ControlMessage
        {
            Facts = new Facts
            {
                EventId = eventId,
                PayloadJson = Google.Protobuf.ByteString.CopyFromUtf8(payloadJson ?? "{}"),
                Namespace = factNamespace ?? string.Empty
            }
        };

        if (namespaces != null)
        {
            msg.Facts.Namespaces.AddRange(
                namespaces
                    .Where(ns => !string.IsNullOrWhiteSpace(ns))
                    .Select(ns => ns.Trim())
                    .Distinct()
            );
        }

        if (_sendQueue.IsAddingCompleted)
            throw new InvalidOperationException("send queue closed");

        if (!_sendQueue.TryAdd(msg))
        {
            Log($"FACTS dropped because send queue is full eventId={eventId}");
            PushToAll(new
            {
                v = 1,
                method = "grpc.control.queueFull",
                @params = new
                {
                    eventId,
                    atUtc = DateTime.UtcNow.ToString("o")
                }
            });
            return;
        }
        _recentEventIds[eventId] = DateTime.UtcNow;
    }

    public void Close()
    {
        lock (_gate)
        {
            if (_call == null && !IsConnected)
            {
                Log("Close skipped: already closed");
                return;
            }

            if (_state == BridgeState.Closing || _state == BridgeState.Disconnected)
                return;

            // Prevent premature close during handshake
            if (!_helloAcked && !_closeRequested)
            {
                Log("Close during handshake — forcing shutdown");
            }

            _state = BridgeState.Closing;
            _closeRequested = true;

            Log("GrpcBridge closing connection");
            _lastConnectionPush = null;

            try
            {
                Log("Push sinks retained across reconnect");
            }
            catch (Exception ex)
            {
                Log($"Error clearing push sinks {ex}");
            }

            IsConnected = false;
            _state = BridgeState.Disconnected;

            try { _cts?.Cancel(); } catch { }
            try { _sendQueue.CompleteAdding(); } catch { }
            Log("Send queue closed");
            try
            {
                var call = _call;
                if (call != null)
                {
                    _ = call.RequestStream.CompleteAsync();
                }
            }
            catch { }

            var callRef = _call;
            var channelRef = _channel;  

            _call = null;
            _client = null;
            _channel = null;

            try { callRef?.Dispose(); } catch { }
            try { channelRef?.Dispose(); } catch { }

            try { _cts?.Dispose(); } catch { }
            _cts = null;

            _receiverTask = null;
            _senderTask = null;
            _watchdogTask = null;
            _heartbeatTask = null;

            PushToAll(new
            {
                v = 1,
                method = "grpc.disconnected",
                @params = new { atUtc = DateTime.UtcNow.ToString("o") }
            });
        }
    }

    private async Task SenderLoop(CancellationToken ct)
    {
        try
        {
            foreach (var msg in _sendQueue.GetConsumingEnumerable(ct))
            {
                try
                {
                    var call = _call;
                    if (call is null || !IsConnected || _cts == null || _cts.IsCancellationRequested)
                    {
                        Log("SenderLoop skip: stream not available");
                        continue;
                    }

                    // Do not send FACTS until HELLO handshake is acknowledged
                    if (!_helloAcked)
                    {
                        if (!IsConnected || _call == null)
                        {
                            Log("SenderLoop abort: not connected while waiting HELLO ACK");
                            return;
                        }

                        try
                        {
                            Log("SenderLoop waiting for HELLO ACK before sending FACTS");

                            var acked = await _helloAckTcs.Task.WaitAsync(TimeSpan.FromSeconds(30), ct);

                            if (!acked)
                            {
                                Log("SenderLoop HELLO ACK wait returned false");
                                continue;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            Log("SenderLoop canceled during HELLO ACK wait");
                            return;
                        }
                        catch (Exception)
                        {
                            if (ct.IsCancellationRequested || !IsConnected)
                            {
                                Log("SenderLoop canceled during HELLO ACK wait");
                                return;
                            }

                            Log("SenderLoop HELLO ACK wait timeout");
                            continue;
                        }
                    }

                    var sendStart = Stopwatch.GetTimestamp();
                    await SafeWriteAsync(msg, ct);
                    _lastSendUtc = DateTime.UtcNow;
                    var factsEventId = msg.Facts?.EventId ?? "hello_or_unknown";
                    Log($"SenderLoop wrote message eventId={factsEventId} latencyMs={ElapsedMs(sendStart):F2}");

                    // Cleanup old dedup entries
                    foreach (var kv in _recentEventIds)
                    {
                        if (DateTime.UtcNow - kv.Value > _dedupWindow)
                        {
                            _recentEventIds.TryRemove(kv.Key, out _);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log($"SenderLoop error {ex}");

                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.streamError",
                        @params = new { message = ex.Message, atUtc = DateTime.UtcNow.ToString("o") }
                    });

                    // Do NOT immediately close the stream for message-level errors.
                    // Only terminate if the cancellation token was requested (real shutdown).
                    if (ct.IsCancellationRequested)
                    {
                        Close();
                        return;
                    }

                    Log("SenderLoop continuing after send error (message ignored)");
                    continue;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
            // queue completed during shutdown or non‑fatal termination
        }
    }

    private async Task ReceiverLoop(GrpcBridgeConnectOptions opt, CancellationToken ct)
    {
        try
        {
            var call = _call;
            if (call == null)
                return;
            var responseStream = call.ResponseStream;

            while (await responseStream.MoveNext(ct))
            {
                var msg = responseStream.Current;
                _lastReceiveUtc = DateTime.UtcNow;

                if (msg.Ack is not null)
                {
                    _lastAckUtc = DateTime.UtcNow;
                    if (_helloEventId != null && string.Equals(msg.Ack.EventId, _helloEventId, StringComparison.OrdinalIgnoreCase))
                    {
                        _helloStartTicks = 0;
                        _helloAcked = true;
                        IsConnected = true;
                        _state = BridgeState.Connected;

                        if (!_helloAckTcs.Task.IsCompleted)
                        {
                            _helloAckTcs.TrySetResult(true);
                        }

                        // True handshake-complete moment: NOW it's safe
                        // to clear the consecutive-failure counter. See
                        // the comment in Connect() (~L693) for the
                        // history on why this lives here and not there.
                        _reconnectAttempt = 0;

                        Log($"HELLO ACK received — stream ready state={_state} isConnected={IsConnected} helloAcked={_helloAcked}");

                        // EMITIR CONNECTED SOLO AQUÍ (READY REAL)
                        var connectedPush = new
                        {
                            v = 1,
                            method = "grpc.connected",
                            @params = new
                            {
                                target = _lastConnectOptions?.Target,
                                atUtc = DateTime.UtcNow.ToString("o"),
                                handshake = "hello_ack"
                            }
                        };

                        _lastConnectionPush = connectedPush;

                        Log("Sending push: grpc.connected (HELLO ACK confirmed)");

                        PushToAll(connectedPush);
                    }
                    var helloLatency = (_helloEventId != null && msg.Ack.EventId == _helloEventId) ? ElapsedMs(_helloStartTicks) : 0;
                    Log($"ACK received eventId={msg.Ack.EventId} status={(int)msg.Ack.Status} helloLatencyMs={helloLatency:F2}");
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.ack",
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
                        method = "grpc.control.rotateCert",
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
                        method = "grpc.control.runJob",
                        @params = new
                        {
                            jobId = msg.RunJob.JobId ?? "",
                            jobType = msg.RunJob.JobType ?? "",
                            payloadJson = msg.RunJob.PayloadJson.ToStringUtf8(),
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.PolicyUpdate is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.policyUpdate",
                        @params = new
                        {
                            eventId = msg.PolicyUpdate.EventId ?? string.Empty,
                            policyVersion = msg.PolicyUpdate.PolicyVersion ?? string.Empty,
                            policyJson = msg.PolicyUpdate.PolicyJson?.ToByteArray() is byte[] bytes
                                ? System.Text.Encoding.UTF8.GetString(bytes)
                                : string.Empty,
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.Disconnect is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.disconnect",
                        @params = new
                        {
                            reason = msg.Disconnect.Reason ?? "server_request",
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.AgentUpdate is not null)
                {
                    var version = msg.AgentUpdate.Version ?? string.Empty;
                    var jobId = msg.AgentUpdate.JobId ?? string.Empty;

                    Log($"AgentUpdate received version={version} jobId={jobId}");

                    if (string.IsNullOrWhiteSpace(version))
                    {
                        Log("AgentUpdate received without version (agent will resolve latest)");
                    }

                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.agentUpdate",
                        @params = new
                        {
                            jobId,
                            version,
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                // ── RCP M1.S1 signaling: server → agent ────────────
                // Four message types from the new RCP oneof variants
                // (proto fields 20-24). PrivSvc just forwards the
                // shape to AgentCore; the RCP SessionManager owns
                // the WebRTC peer state.

                if (msg.RemoteSessionOffer is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.remoteSessionOffer",
                        @params = new
                        {
                            sessionId = msg.RemoteSessionOffer.SessionId ?? "",
                            sdp = msg.RemoteSessionOffer.Sdp ?? "",
                            capability = msg.RemoteSessionOffer.Capability ?? "",
                            sessionTimeoutSeconds = msg.RemoteSessionOffer.SessionTimeoutSeconds,
                            // ICE servers forwarded from the backend (Cloudflare TURN
                            // creds, minted per-session, same ones the operator's
                            // browser got). AgentCore needs them so the WebRTC peer
                            // emits relay candidates of its own; without them the
                            // peer only emits host candidates from its local NIC and
                            // ICE deterministically fails behind any NAT. This field
                            // was added with proto bump (iceServersJson = 5) on
                            // 2026-06-10 — before that we silently dropped it here
                            // because the anonymous object literal didn't list it,
                            // making the previous backend deploy a no-op end-to-end.
                            iceServersJson = msg.RemoteSessionOffer.IceServersJson ?? "",
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.RemoteSessionIce is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.remoteSessionIce",
                        @params = new
                        {
                            sessionId = msg.RemoteSessionIce.SessionId ?? "",
                            candidate = msg.RemoteSessionIce.Candidate ?? "",
                            sdpMid = msg.RemoteSessionIce.SdpMid ?? "",
                            sdpMLineIndex = msg.RemoteSessionIce.SdpMLineIndex,
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.RemoteSessionClose is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.remoteSessionClose",
                        @params = new
                        {
                            sessionId = msg.RemoteSessionClose.SessionId ?? "",
                            reason = msg.RemoteSessionClose.Reason ?? "",
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.RemoteSessionError is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.remoteSessionError",
                        @params = new
                        {
                            sessionId = msg.RemoteSessionError.SessionId ?? "",
                            code = msg.RemoteSessionError.Code ?? "",
                            message = msg.RemoteSessionError.Message ?? "",
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }
            }
        }
            catch (Exception ex)
            {
                if (ex is ObjectDisposedException || ct.IsCancellationRequested)
                {
                    Log("ReceiverLoop disposed during shutdown");
                    return;
                }

                Log($"ReceiverLoop error {ex}");

                PushToAll(new
                {
                    v = 1,
                    method = "grpc.control.receiverError",
                    @params = new { message = ex.Message, atUtc = DateTime.UtcNow.ToString("o") }
                });

            Log("ReceiverLoop will reconnect via finally");
            }
        finally
        {
            Log($"ReceiverLoop ended state={_state} closeRequested={_closeRequested} isConnected={IsConnected}");

            if (_closeRequested || _state == BridgeState.Closing)
            {
                Log("ReceiverLoop exit due to local close");
            }
            else
            {
                // NO cerrar inmediatamente — deja que watchdog o error real lo decidan
                Log("ReceiverLoop ended unexpectedly — scheduling reconnect WITHOUT force close");
                ScheduleReconnect("receiver_loop_end");
            }
        }
    }

    private async Task HelloTimeoutLoop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct);

                if (_call is null || _cts == null || _cts.IsCancellationRequested)
                    continue;

                    // HELLO ya fue ACK → terminar el loop
                    if (_helloStartTicks == 0)
                        return;

                    var elapsed = ElapsedMs(_helloStartTicks);

                    if (_lastSendUtc == DateTime.MinValue)
                    {
                        // HELLO never made it onto the wire.
                        //
                        // Previously this branch logged "ignored" and
                        // `continue`d forever. That left the bridge in a
                        // half-up state when the gRPC subchannel got
                        // stuck (e.g., transient TLS/socket failure
                        // during connect): channel "created", streaming
                        // call "started", but no actual byte ever sent.
                        // The watchdog couldn't kick in because the
                        // dead-stream threshold only fires after we
                        // observe activity; HelloAckTimeout couldn't
                        // fire because it skipped this branch entirely.
                        //
                        // Escalate after _helloSendStuckThreshold (60s)
                        // by closing the channel and scheduling a fresh
                        // reconnect. ScheduleReconnect increments
                        // _reconnectAttempt — repeated stuck-sends will
                        // eventually hit the self-rescue threshold and
                        // SCM-restart the service.
                        if (elapsed > _helloSendStuckThreshold.TotalMilliseconds)
                        {
                            Log($"HELLO send stuck — never reached wire after {elapsed:F0}ms — closing + reconnecting");
                            PushToAll(new
                            {
                                v = 1,
                                method = "grpc.control.helloSendStuck",
                                @params = new
                                {
                                    stuckMs = elapsed,
                                    thresholdSeconds = _helloSendStuckThreshold.TotalSeconds
                                }
                            });
                            Close();
                            ScheduleReconnect("hello_send_stuck");
                            return;
                        }

                        Log($"HELLO timeout ignored: HELLO not fully sent yet (stuckMs={elapsed:F0})");
                        continue;
                    }

                if (elapsed > _helloAckTimeout.TotalMilliseconds)
                {
                    Log($"HELLO ACK timeout after {elapsed:F2}ms");
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.helloTimeout",
                        @params = new
                        {
                            timeoutSeconds = _helloAckTimeout.TotalSeconds,
                            elapsedMs = elapsed
                        }
                    });
                    Close();
                    ScheduleReconnect("hello_ack_timeout");
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            Log("HelloTimeoutLoop canceled");
        }
        catch (Exception ex)
        {
            Log($"HelloTimeoutLoop error {ex}");
        }
    }

    private async Task HeartbeatLoop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(_heartbeatInterval, ct);

                if (!IsConnected || _call is null)
                    continue;

                try
                {
                    var heartbeat = new ControlMessage
                    {
                        Heartbeat = new Heartbeat
                        {
                            DeviceId = _lastConnectOptions?.DeviceId ?? string.Empty,
                            UptimeSeconds = (long)TimeSpan.FromMilliseconds(Environment.TickCount64).TotalSeconds,
                            AgentVersion = _lastConnectOptions?.AgentVersion ?? string.Empty,
                            PolicyVersion = _lastConnectOptions?.PolicyVersion ?? string.Empty
                        }
                    };

                    await SafeWriteAsync(heartbeat, ct);
                    _lastSendUtc = DateTime.UtcNow;
                    Log("HEARTBEAT message sent");
                }
                catch (Exception ex)
                {
                    Log($"HEARTBEAT send error {ex}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            Log("HeartbeatLoop canceled");
        }
        catch (Exception ex)
        {
            Log($"HeartbeatLoop error {ex}");
        }
    }

    private static string NormalizeTarget(string target)
    {
        var t = (target ?? "").Trim();

        if (t.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            return t;
        }

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
        {
            Log($"Client certificate NOT found {normalized}");
            throw new InvalidOperationException($"Client cert not found in LocalMachine\\My: {normalized}");
        }

        foreach (var c in matches)
        {
            if (c.HasPrivateKey)
            {
                Log($"Client certificate selected {c.Thumbprint} Subject={c.Subject} HasPrivateKey={c.HasPrivateKey}");
                return c;
            }
        }

        Log("Client certificate found but without private key association");

        throw new InvalidOperationException("Client cert found but has no private key association (HasPrivateKey=false)");
    }

    private static X509Certificate2 LoadCaCertFromLocalMachineByThumbprint(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
            throw new ArgumentException("thumbprint is required", nameof(thumbprint));

        var normalized = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

        using (var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);

            if (matches.Count > 0)
            {
                Log("CA certificate loaded from Intermediate store");
                return matches[0];
            }
        }

        using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);

            if (matches.Count > 0)
            {
                Log("CA certificate loaded from Root store");
                return matches[0];
            }
        }

        Log($"CA certificate not found {normalized}");

        throw new InvalidOperationException($"Issuing/Root CA cert not found in LocalMachine\\CA or LocalMachine\\Root: {normalized}");
    }

    /// <summary>
    /// Forward an agent heartbeat onto the open gRPC control-plane stream.
    ///
    /// Agent-core fires this every HEARTBEAT_INTERVAL_MS so the server can
    /// refresh device_sessions.last_heartbeat. Without this the backend's
    /// "online now" derivation (last_heartbeat within 90s) decays to
    /// false and the device drops out of the Overview's online count even
    /// when the agent is running fine.
    ///
    /// Mirrors SendAck in ordering: log + validate + build ControlMessage
    /// + direct RequestStream.WriteAsync. If the stream disappeared mid-
    /// send we swallow (the agent's IPC-level "no active call" response
    /// already triggered its own reconnect path).
    /// </summary>
    public async Task SendHeartbeat(
        string deviceId,
        long uptimeSeconds,
        string agentVersion,
        string policyVersion,
        CancellationToken ct = default)
    {
        if (_call is null)
        {
            Log($"SendHeartbeat skipped: no active call deviceId={deviceId}");
            return;
        }

        if (string.IsNullOrWhiteSpace(deviceId))
        {
            Log("SendHeartbeat skipped: empty deviceId");
            return;
        }

        try
        {
            var hbMsg = new ControlMessage
            {
                Heartbeat = new Heartbeat
                {
                    DeviceId = deviceId,
                    UptimeSeconds = uptimeSeconds,
                    AgentVersion = agentVersion ?? "",
                    PolicyVersion = policyVersion ?? ""
                }
            };

            var call = _call;
            if (call != null)
            {
                await call.RequestStream.WriteAsync(hbMsg);
            }
            else
            {
                Log($"SendHeartbeat aborted: call became null during send deviceId={deviceId}");
                return;
            }

            _lastSendUtc = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            Log($"SendHeartbeat error deviceId={deviceId} {ex}");
            // Re-throw so HandleHeartbeat can surface the failure to the
            // IPC caller — agent-core uses this signal to tear down and
            // reconnect. Silencing would mask a broken stream.
            throw;
        }
    }

    public async Task SendAck(string eventId, int status = 0, string? message = null, CancellationToken ct = default)
    {
        if (_call is null)
        {
            Log($"SendAck skipped: no active call eventId={eventId}");
            return;
        }

        if (string.IsNullOrWhiteSpace(eventId))
        {
            Log("SendAck skipped: empty eventId");
            return;
        }

        try
        {
            var ackMsg = new ControlMessage
            {
                Ack = new Ack
                {
                    EventId = eventId,
                    Status = (AckStatus)status,
                    Message = message ?? "OK",
                    ReceivedAtUtc = DateTime.UtcNow.ToString("o")
                }
            };

            // Use direct write to reduce chances of ACK being dropped by transient state checks
            var call = _call;
            if (call != null)
            {
                await call.RequestStream.WriteAsync(ackMsg);
            }
            else
            {
                Log($"SendAck aborted: call became null during send eventId={eventId}");
                return;
            }

            _lastSendUtc = DateTime.UtcNow;

            Log($"ACK sent to backend eventId={eventId} status={status}");
        }
        catch (Exception ex)
        {
            Log($"SendAck error eventId={eventId} {ex}");
        }
    }

    // ── RCP M1.S1 — outbound signaling (agent → server) ──────────────
    //
    // Four direct-write methods, mirroring SendAck's pattern. They
    // bypass _sendQueue because RCP signaling is latency-sensitive
    // (the operator's browser is waiting) and the queue is sized
    // for FACTS throughput, not interactive sessions.
    //
    // If _call is null (bridge not connected), we drop with a log —
    // the agent-side SessionManager already treats a failed forward
    // as a teardown signal.

    public async Task SendRemoteSessionAnswer(string sessionId, string sdp, CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteSessionAnswer skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) { Log("SendRemoteSessionAnswer skipped: empty sessionId"); return; }
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteSessionAnswer = new RemoteSessionAnswer
                {
                    SessionId = sessionId,
                    Sdp = sdp ?? string.Empty
                }
            });
            _lastSendUtc = DateTime.UtcNow;
            Log($"RemoteSessionAnswer sent sessionId={sessionId} sdpBytes={(sdp?.Length ?? 0)}");
        }
        catch (Exception ex) { Log($"SendRemoteSessionAnswer error sessionId={sessionId} {ex}"); }
    }

    public async Task SendRemoteSessionIce(string sessionId, string candidate, string sdpMid, int sdpMLineIndex, CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteSessionIce skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) { Log("SendRemoteSessionIce skipped: empty sessionId"); return; }
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteSessionIce = new RemoteSessionIce
                {
                    SessionId = sessionId,
                    Candidate = candidate ?? string.Empty,
                    SdpMid = sdpMid ?? string.Empty,
                    SdpMLineIndex = sdpMLineIndex
                }
            });
            _lastSendUtc = DateTime.UtcNow;
        }
        catch (Exception ex) { Log($"SendRemoteSessionIce error sessionId={sessionId} {ex}"); }
    }

    public async Task SendRemoteSessionClose(string sessionId, string reason, CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteSessionClose skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) { Log("SendRemoteSessionClose skipped: empty sessionId"); return; }
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteSessionClose = new RemoteSessionClose
                {
                    SessionId = sessionId,
                    Reason = reason ?? string.Empty
                }
            });
            _lastSendUtc = DateTime.UtcNow;
            Log($"RemoteSessionClose sent sessionId={sessionId} reason={reason}");
        }
        catch (Exception ex) { Log($"SendRemoteSessionClose error sessionId={sessionId} {ex}"); }
    }

    public async Task SendRemoteSessionError(string sessionId, string code, string message, CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteSessionError skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) { Log("SendRemoteSessionError skipped: empty sessionId"); return; }
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteSessionError = new RemoteSessionError
                {
                    SessionId = sessionId,
                    Code = code ?? string.Empty,
                    Message = message ?? string.Empty
                }
            });
            _lastSendUtc = DateTime.UtcNow;
            Log($"RemoteSessionError sent sessionId={sessionId} code={code}");
        }
        catch (Exception ex) { Log($"SendRemoteSessionError error sessionId={sessionId} {ex}"); }
    }

    // RCP M1.S3 — agent → backend transcript chunks. Same direct-
    // write pattern as Ack/Answer but transcript can be many KB at
    // a time so we don't log per-send (would flood the privsvc log).
    public async Task SendRemoteSessionTranscript(string sessionId, string stream, double tsDeltaSeconds, string data, int bytesCount, CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteSessionTranscript skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) return;
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteSessionTranscript = new RemoteSessionTranscript
                {
                    SessionId = sessionId,
                    Stream = stream ?? "stdout",
                    TsDeltaSeconds = tsDeltaSeconds,
                    Data = data ?? string.Empty,
                    BytesCount = bytesCount
                }
            });
            _lastSendUtc = DateTime.UtcNow;
        }
        catch (Exception ex) { Log($"SendRemoteSessionTranscript error sessionId={sessionId} {ex}"); }
    }

    // M2.S1 — file transfer audit (agent → server).
    public async Task SendRemoteFileTransferAudit(
        string sessionId, string transferId, string direction,
        string remotePath, string filename,
        long sizeBytes, long transferredBytes,
        string status, string errorMessage,
        CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteFileTransferAudit skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) return;
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteFileTransferAudit = new RemoteFileTransferAudit
                {
                    SessionId        = sessionId,
                    TransferId       = transferId       ?? string.Empty,
                    Direction        = direction        ?? string.Empty,
                    RemotePath       = remotePath       ?? string.Empty,
                    Filename         = filename         ?? string.Empty,
                    SizeBytes        = sizeBytes,
                    TransferredBytes = transferredBytes,
                    Status           = status           ?? string.Empty,
                    ErrorMessage     = errorMessage     ?? string.Empty
                }
            });
            _lastSendUtc = DateTime.UtcNow;
            Log($"RemoteFileTransferAudit sent sessionId={sessionId} transferId={transferId} status={status}");
        }
        catch (Exception ex) { Log($"SendRemoteFileTransferAudit error sessionId={sessionId} {ex}"); }
    }

    // M3.S1 — screen share audit (agent → server).
    public async Task SendRemoteScreenAudit(
        string sessionId, string evt,
        int width, int height, int fps,
        string errorMessage,
        CancellationToken ct = default)
    {
        if (_call is null) { Log($"SendRemoteScreenAudit skipped: no active call sessionId={sessionId}"); return; }
        if (string.IsNullOrWhiteSpace(sessionId)) return;
        try
        {
            await _call.RequestStream.WriteAsync(new ControlMessage
            {
                RemoteScreenAudit = new RemoteScreenAudit
                {
                    SessionId    = sessionId,
                    Event        = evt          ?? string.Empty,
                    Width        = width,
                    Height       = height,
                    Fps          = fps,
                    ErrorMessage = errorMessage ?? string.Empty
                }
            });
            _lastSendUtc = DateTime.UtcNow;
            Log($"RemoteScreenAudit sent sessionId={sessionId} event={evt} {width}x{height}@{fps}fps");
        }
        catch (Exception ex) { Log($"SendRemoteScreenAudit error sessionId={sessionId} {ex}"); }
    }

    public void Dispose() => Close();
}

public sealed class GrpcBridgeConnectOptions
{
    public required string Target { get; init; }
    public required string ClientCertThumbprint { get; init; }
    public string? IssuingCaThumbprint { get; init; }
    public string? TenantId { get; init; }
    public string? DeviceId { get; init; }
    public string? AgentVersion { get; init; }
    public string? ProtocolVersion { get; init; }
    public string? PolicyVersion { get; init; }
    public IEnumerable<string>? Capabilities { get; init; }
}
