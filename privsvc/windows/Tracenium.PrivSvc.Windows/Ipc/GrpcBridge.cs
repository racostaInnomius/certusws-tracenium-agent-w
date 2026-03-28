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

    private static string GetDailyLogPath()
    {
        var fileName = $"grpcbridge-{DateTime.UtcNow:yyyyMMdd}.log";
        return Path.Combine(_logDir, fileName);
    }

    private static void CleanupOldLogs()
    {
        try
        {
            if (!Directory.Exists(_logDir))
                return;

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

        if (!IsConnected && !isHello)
        {
            Log("SafeWriteAsync skipped: not connected (non-HELLO message)");
            return;
        }

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
                            await SafeWriteAsync(new ControlMessage
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
                            }, _cts.Token);
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
                _reconnectAttempt = 0;
                _reconnectScheduled = false;

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

    public void SendFacts(string eventId, string payloadJson)
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
                PayloadJson = Google.Protobuf.ByteString.CopyFromUtf8(payloadJson ?? "{}")
            }
        };

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
                            policyVersion = msg.PolicyUpdate.PolicyVersion ?? string.Empty,
                            policyJson = msg.PolicyUpdate.PolicyJson?.ToByteArray() is byte[] bytes
                                ? System.Text.Encoding.UTF8.GetString(bytes)
                                : string.Empty,
                            receivedAtUtc = DateTime.UtcNow.ToString("o")
                        }
                    });
                }

                if (msg.RequestFacts is not null)
                {
                    PushToAll(new
                    {
                        v = 1,
                        method = "grpc.control.requestFacts",
                        @params = new
                        {
                            factType = msg.RequestFacts.FactType ?? "inventory",
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
                    if (_lastSendUtc == DateTime.MinValue)
                    {
                        Log("HELLO timeout ignored: HELLO not fully sent yet");
                        continue;
                    }

                var elapsed = ElapsedMs(_helloStartTicks);
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
}