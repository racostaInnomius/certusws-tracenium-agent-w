// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/IpcGrpcHandlers.cs
using System.Runtime.CompilerServices;
using System.Collections.Concurrent;
using Tracenium.PrivSvc.Windows.Grpc;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class IpcGrpcHandlers
{
    // Chunk buffer: eventId -> (chunkIndex -> payloadChunk)
    private class ChunkState
    {
        public int TotalChunks { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public SortedDictionary<int, string> Chunks { get; set; } = new();
        public string? Namespace { get; set; }
        public List<string> Namespaces { get; set; } = new();
    }

    private static readonly Dictionary<string, ChunkState> _chunkBuffer = new();
    private static readonly Dictionary<string, object> _chunkLocks = new();
    private static readonly Dictionary<int, string> _pushSinkByDelegateKey = new();
    private const int MaxBufferedPushEventsPerSink = 32;
    private static readonly ConcurrentDictionary<string, ConcurrentQueue<object>> _pendingPushBySink = new();
    public static async Task<PrivSvcResponse> HandleConnect(PrivSvcRequest req, Action<object> push)
    {
        // Session-mode: returns a connectionId that the caller must use for close/unregister.
        string? connectionId = null;

        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            // Align with Node bridge payload:
            // - grpcEndpoint OR target
            // - mtls.clientCertThumbprint (preferred) OR clientCertThumbprint
            string? target = GetString(p, "grpcEndpoint") ?? GetString(p, "target");
            if (string.IsNullOrWhiteSpace(target))
                throw new Exception("grpcEndpoint/target required");

            // Support nested mtls object: { mtls: { clientCertThumbprint: "..." } }
            string? clientTp = null;
            if (p.TryGetValue("mtls", out var mtlsObj) && mtlsObj != null)
            {
                var mtlsDict = ToDict(mtlsObj);
                clientTp = GetString(mtlsDict, "clientCertThumbprint") ?? GetString(mtlsDict, "clientTp");
            }
            clientTp ??= GetString(p, "clientCertThumbprint") ?? GetString(p, "clientTp");

            // Optional issuing CA thumbprint (sent by Node bridge)
            string? issuingCaTp = null;
            if (p.TryGetValue("mtls", out var mtlsObj2) && mtlsObj2 != null)
            {
                var mtlsDict2 = ToDict(mtlsObj2);
                issuingCaTp = GetString(mtlsDict2, "issuingCaThumbprint");
            }
            issuingCaTp ??= GetString(p, "issuingCaThumbprint");

            if (string.IsNullOrWhiteSpace(clientTp))
                throw new Exception("clientCertThumbprint required");

            var tenantId = GetString(p, "tenantId") ?? req.Meta?.TenantId ?? "";
            var deviceId = GetString(p, "deviceId") ?? req.Meta?.DeviceId ?? "";
            var agentVersion = GetString(p, "agentVersion");
            var capabilities = GetStringList(p, "capabilities");

            var protocolVersion = GetString(p, "protocolVersion") ?? "1";
            var policyVersion = GetString(p, "policyVersion");

            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(deviceId))
                throw new Exception("tenantId/deviceId required");

            // Reuse a caller-provided connection id when available; otherwise allocate one.
            connectionId =
                GetString(p, "connectionId") ??
                GetString(p, "sinkId") ??
                Guid.NewGuid().ToString("N");

            try
            {
                // Only connect if the bridge is not already connected
                if (!GrpcBridgeSingleton.Instance.IsConnected)
                {
                    await GrpcBridgeSingleton.Instance.Connect(new GrpcBridgeConnectOptions
                    {
                        Target = target,
                        ClientCertThumbprint = clientTp,
                        IssuingCaThumbprint = issuingCaTp,
                        TenantId = tenantId,
                        DeviceId = deviceId,
                        AgentVersion = agentVersion,
                        ProtocolVersion = protocolVersion,
                        PolicyVersion = policyVersion,
                        Capabilities = capabilities
                    });
                }

                var pushDelegateKey = GetPushDelegateKey(push);
                string? previousSinkId = null;

                lock (_pushSinkByDelegateKey)
                {
                    if (_pushSinkByDelegateKey.TryGetValue(pushDelegateKey, out var existingSinkId))
                    {
                        previousSinkId = existingSinkId;
                    }
                }

                if (!string.IsNullOrWhiteSpace(previousSinkId) &&
                    !string.Equals(previousSinkId, connectionId, StringComparison.Ordinal))
                {
                    try
                    {
                        Console.WriteLine($"[IpcGrpcHandlers] Replacing prior push sink delegateKey={pushDelegateKey} oldSinkId={previousSinkId} newSinkId={connectionId}");
                        GrpcBridgeSingleton.Instance.UnregisterPushSink(previousSinkId);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[IpcGrpcHandlers] Failed to unregister prior push sink oldSinkId={previousSinkId} error={ex}");
                    }
                }

                try
                {
                    GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId);
                }
                catch
                {
                    // Best effort: avoid duplicate registration for the same sink id.
                }

                // Register this pipe as a push sink for this session AFTER connect succeeds
                GrpcBridgeSingleton.Instance.RegisterPushSink(connectionId, msg =>
                {
                    DeliverOrBufferPush(connectionId, push, msg);
                });

                // DEBUG: ensure push path is working end-to-end (can be removed after validation)
                try
                {
                    var testEvt = new
                    {
                        v = 1,
                        method = "grpc.debug.push_test",
                        @params = new
                        {
                            connectionId = connectionId,
                            atUtc = DateTime.UtcNow.ToString("o")
                        }
                    };

                    Console.WriteLine($"[IpcGrpcHandlers] DEBUG PUSH TEST connectionId={connectionId}");
                    DeliverOrBufferPush(connectionId, push, testEvt);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[IpcGrpcHandlers] DEBUG PUSH TEST failed connectionId={connectionId} error={ex}");
                }

                // NOTE: ReplayPendingEvents removed due to incompatibility with current bridge contract

                lock (_pushSinkByDelegateKey)
                {
                    _pushSinkByDelegateKey[pushDelegateKey] = connectionId;
                }
                ReplayBufferedPushes(connectionId, push);

                // Wait explicitly for bridge readiness (HELLO ACK) instead of relying only on push delivery
                var ready = await GrpcBridgeSingleton.Instance.WaitForReadyAsync(TimeSpan.FromSeconds(35));
                Console.WriteLine($"[IpcGrpcHandlers] Bridge ready={ready} connectionId={connectionId}");

                // As a safety net: emit grpc.connected directly via IPC delegate
                if (ready && push != null)
                {
                    try
                    {
                        var evt = new
                        {
                            v = 1,
                            method = "grpc.connected",
                            @params = new
                            {
                                target = target,
                                atUtc = DateTime.UtcNow.ToString("o"),
                                source = "ipc-handler"
                            }
                        };

                        var json = System.Text.Json.JsonSerializer.Serialize(evt);
                        Console.WriteLine($"[IpcGrpcHandlers] DIRECT PUSH grpc.connected payload={json}");

                        DeliverOrBufferPush(connectionId, push, evt);

                        Console.WriteLine($"[IpcGrpcHandlers] DIRECT PUSH delivered connectionId={connectionId}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[IpcGrpcHandlers] DIRECT PUSH failed connectionId={connectionId} error={ex}");
                    }
                }

                return PrivSvcResponse.Success(req.Id, new { connected = ready, ready, connectionId });
            }
            catch
            {
                // Ensure we don't leak a push sink if connect fails.
                try { GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId); } catch { }
                lock (_pushSinkByDelegateKey)
                {
                    var staleKeys = _pushSinkByDelegateKey
                        .Where(kv => string.Equals(kv.Value, connectionId, StringComparison.Ordinal))
                        .Select(kv => kv.Key)
                        .ToList();

                    foreach (var key in staleKeys)
                        _pushSinkByDelegateKey.Remove(key);
                }
                throw;
            }
        }
        catch (Exception ex)
        {
            // Best-effort cleanup if we allocated a connectionId.
            if (!string.IsNullOrWhiteSpace(connectionId))
            {
                try { GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId); } catch { }
                lock (_pushSinkByDelegateKey)
                {
                    var staleKeys = _pushSinkByDelegateKey
                        .Where(kv => string.Equals(kv.Value, connectionId, StringComparison.Ordinal))
                        .Select(kv => kv.Key)
                        .ToList();

                    foreach (var key in staleKeys)
                        _pushSinkByDelegateKey.Remove(key);
                }
            }
            return PrivSvcResponse.Fail(req.Id, "grpc_connect_error", ex.Message);
        }
    }


    public static Task<PrivSvcResponse> HandleFactsSend(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            // Accept either { eventId, payloadJson } OR { facts: { eventId, payloadJson } }
            string? eventId = GetString(p, "eventId");
            string? payloadJson = GetString(p, "payloadJson");
            string? factNamespace = GetString(p, "namespace");
            var namespaces = GetStringList(p, "namespaces");

            if (p.TryGetValue("facts", out var factsObj) && factsObj != null)
            {
                var factsDict = ToDict(factsObj);
                eventId ??= GetString(factsDict, "eventId");
                payloadJson ??= GetString(factsDict, "payloadJson");
                factNamespace ??= GetString(factsDict, "namespace");
                if (namespaces.Count == 0)
                    namespaces = GetStringList(factsDict, "namespaces");
            }

            if (string.IsNullOrWhiteSpace(eventId))
                throw new Exception("eventId required");
            payloadJson ??= "{}";
            var safePayload = payloadJson!;
            var payloadSize = safePayload.Length;
            Console.WriteLine($"[IpcGrpcHandlers] SendFacts eventId={eventId} namespace={factNamespace} namespaces={string.Join(",", namespaces)} connected={GrpcBridgeSingleton.Instance.IsConnected} payloadSize={payloadSize}");
            GrpcBridgeSingleton.Instance.SendFacts(eventId, safePayload, factNamespace, namespaces);

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { queued = true, connected = GrpcBridgeSingleton.Instance.IsConnected }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "grpc_facts_send_error", ex.Message));
        }
    }

    public static Task<PrivSvcResponse> HandleFactsChunk(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            var eventId = GetString(p, "eventId");
            var chunkIndexStr = GetString(p, "chunkIndex");
            var totalChunksStr = GetString(p, "totalChunks");
            var payloadChunk = GetString(p, "payloadChunk") ?? "";
            var factNamespace = GetString(p, "namespace");
            var namespaces = GetStringList(p, "namespaces");

            if (string.IsNullOrWhiteSpace(eventId))
                throw new Exception("eventId required");

            if (!int.TryParse(chunkIndexStr, out var chunkIndex))
                throw new Exception("invalid chunkIndex");

            if (!int.TryParse(totalChunksStr, out var totalChunks))
                throw new Exception("invalid totalChunks");

            if (totalChunks <= 0)
                throw new Exception("totalChunks must be > 0");

            if (chunkIndex < 0 || chunkIndex >= totalChunks)
                throw new Exception("chunkIndex out of range");

            // Cleanup stale chunks
            var now = DateTime.UtcNow;
            var staleKeys = _chunkBuffer
                .Where(kv => now - kv.Value.CreatedAt > TimeSpan.FromMinutes(2))
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in staleKeys)
            {
                Console.WriteLine($"[IpcGrpcHandlers] Cleaning stale chunk eventId={key}");
                _chunkBuffer.Remove(key);
                _chunkLocks.Remove(key);
            }

            Console.WriteLine($"[IpcGrpcHandlers] FACTS chunk received eventId={eventId} chunk={chunkIndex + 1}/{totalChunks} size={payloadChunk.Length}");

            bool isComplete = false;
            string? fullPayload = null;
            string? completeNamespace = null;
            List<string> completeNamespaces = new();
            object lockObj;

            lock (_chunkLocks)
            {
                if (!_chunkLocks.TryGetValue(eventId, out lockObj!))
                {
                    lockObj = new object();
                    _chunkLocks[eventId] = lockObj;
                }
            }

            lock (lockObj)
            {
                if (!_chunkBuffer.ContainsKey(eventId))
                {
                    _chunkBuffer[eventId] = new ChunkState
                    {
                        TotalChunks = totalChunks,
                        Namespace = factNamespace,
                        Namespaces = namespaces
                    };
                }
                else
                {
                    if (_chunkBuffer[eventId].TotalChunks != totalChunks)
                        throw new Exception("inconsistent totalChunks for eventId");
                }

                var state = _chunkBuffer[eventId];

                // Ignore duplicates instead of overwriting silently
                if (!state.Chunks.ContainsKey(chunkIndex))
                {
                    state.Chunks[chunkIndex] = payloadChunk;
                }
                else
                {
                    Console.WriteLine($"[IpcGrpcHandlers] FACTS duplicate chunk ignored eventId={eventId} chunk={chunkIndex + 1}/{totalChunks}");
                }

                if (state.Chunks.Count == state.TotalChunks)
                {
                    fullPayload = string.Concat(state.Chunks.Values);
                    completeNamespace = state.Namespace;
                    completeNamespaces = state.Namespaces;
                    _chunkBuffer.Remove(eventId);
                    isComplete = true;
                }
            }

            if (isComplete && fullPayload != null)
            {
                Console.WriteLine($"[IpcGrpcHandlers] FACTS COMPLETE eventId={eventId} chunks={totalChunks} size={fullPayload.Length}");

                const int MAX_FACTS_SIZE = 512 * 1024;
                if (fullPayload.Length > MAX_FACTS_SIZE)
                    throw new Exception("payload too large");

                GrpcBridgeSingleton.Instance.SendFacts(eventId, fullPayload, completeNamespace, completeNamespaces);

                lock (_chunkLocks)
                {
                    _chunkLocks.Remove(eventId);
                }
            }

            return Task.FromResult(
                PrivSvcResponse.Success(req.Id, new { received = true, complete = isComplete })
            );
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "grpc_facts_chunk_error", ex.Message));
        }
    }

    public static Task<PrivSvcResponse> HandleClose(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            // connectionId returned by HandleConnect (preferred)
            var connectionId =
                GetString(p, "connectionId") ??
                GetString(p, "sinkId");

            // Always unregister the push sink first (if provided) so we do not keep
            // stale pipe writers in the bridge when the agent reconnects.
            if (!string.IsNullOrWhiteSpace(connectionId))
            {
                Console.WriteLine($"[IpcGrpcHandlers] HandleClose connectionId={connectionId}");
                try
                {
                    GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId);
                }
                catch { /* best-effort cleanup */ }

                lock (_pushSinkByDelegateKey)
                {
                    var staleKeys = _pushSinkByDelegateKey
                        .Where(kv => string.Equals(kv.Value, connectionId, StringComparison.Ordinal))
                        .Select(kv => kv.Key)
                        .ToList();

                    foreach (var key in staleKeys)
                        _pushSinkByDelegateKey.Remove(key);
                }
                _pendingPushBySink.TryRemove(connectionId, out _);
            }

            // Close the underlying gRPC bridge
            try
            {
                GrpcBridgeSingleton.Instance.Close();
            }
            catch { /* bridge may already be closed */ }

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { closed = true }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "grpc_close_error", ex.Message));
        }
    }

    private static void DeliverOrBufferPush(string? connectionId, Action<object>? push, object msg)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(msg);
            Console.WriteLine($"[IpcGrpcHandlers] PUSH sinkId={connectionId} payload={json}");
        }
        catch
        {
            // best effort logging only
        }

        if (string.IsNullOrWhiteSpace(connectionId))
        {
            Console.WriteLine("[IpcGrpcHandlers] PUSH skipped (missing connectionId)");
            return;
        }

        if (push == null)
        {
            Console.WriteLine($"[IpcGrpcHandlers] PUSH skipped (null delegate) sinkId={connectionId}");
            BufferPush(connectionId, msg);
            return;
        }

        try
        {
            push(msg);
            Console.WriteLine($"[IpcGrpcHandlers] PUSH delivered sinkId={connectionId} type={msg?.GetType().Name}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[IpcGrpcHandlers] PUSH failed sinkId={connectionId} error={ex}");
            BufferPush(connectionId, msg);
            // Do NOT rethrow — avoid breaking PushToAll loop or killing sink
        }
    }

    private static void BufferPush(string connectionId, object msg)
    {
        var queue = _pendingPushBySink.GetOrAdd(connectionId, _ => new ConcurrentQueue<object>());
        queue.Enqueue(msg);

        while (queue.Count > MaxBufferedPushEventsPerSink && queue.TryDequeue(out _))
        {
            // drop oldest buffered event to keep memory bounded
        }

        Console.WriteLine($"[IpcGrpcHandlers] PUSH buffered sinkId={connectionId} bufferedCount={queue.Count}");
    }

    private static void ReplayBufferedPushes(string connectionId, Action<object>? push)
    {
        if (push == null) return;
        if (!_pendingPushBySink.TryGetValue(connectionId, out var queue)) return;

        var replayed = 0;

        while (queue.TryDequeue(out var pending))
        {
            try
            {
                push(pending);
                replayed++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[IpcGrpcHandlers] PUSH replay failed sinkId={connectionId} error={ex}");
                queue.Enqueue(pending);
                break;
            }
        }

        if (queue.IsEmpty)
        {
            _pendingPushBySink.TryRemove(connectionId, out _);
        }

        if (replayed > 0)
        {
            Console.WriteLine($"[IpcGrpcHandlers] PUSH replayed sinkId={connectionId} count={replayed}");
        }
    }

    private static int GetPushDelegateKey(Action<object> push)
    {
        var targetHash = push.Target != null ? RuntimeHelpers.GetHashCode(push.Target) : 0;
        var methodHash = push.Method.MetadataToken;
        return HashCode.Combine(targetHash, methodHash);
    }

    private static Dictionary<string, object> ToDict(object obj)
    {
        if (obj is Dictionary<string, object> d) return d;

        if (obj is System.Text.Json.JsonElement je)
        {
            // Convert JsonElement object -> Dictionary<string, object>
            if (je.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in je.EnumerateObject())
                {
                    dict[prop.Name] = prop.Value;
                }
                return dict;
            }
        }

        // Fallback: empty dict
        return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
    }

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return null;
        return val switch
        {
            string s => s,
            System.Text.Json.JsonElement je => je.ValueKind == System.Text.Json.JsonValueKind.String ? je.GetString() : je.ToString(),
            _ => val.ToString()
        };
    }

    private static List<string> GetStringList(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return new List<string>();

        if (val is IEnumerable<string> strings)
        {
            return strings
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .Distinct()
                .ToList();
        }

        if (val is System.Text.Json.JsonElement je)
        {
            if (je.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                return je.EnumerateArray()
                    .Select(item => item.ValueKind == System.Text.Json.JsonValueKind.String ? item.GetString() : item.ToString())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Select(s => s!.Trim())
                    .Distinct()
                    .ToList();
            }

            if (je.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                return (je.GetString() ?? "")
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Distinct()
                    .ToList();
            }
        }

        return val.ToString()?
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct()
            .ToList() ?? new List<string>();
    }

    public static async Task<PrivSvcResponse> HandleAck(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            var eventId = GetString(p, "eventId");
            var statusStr = GetString(p, "status");

            if (string.IsNullOrWhiteSpace(eventId))
                throw new Exception("eventId required");

            int status = 0;
            if (!string.IsNullOrWhiteSpace(statusStr))
                int.TryParse(statusStr, out status);

            Console.WriteLine($"[IpcGrpcHandlers] ACK forwarding eventId={eventId} status={status}");

            await GrpcBridgeSingleton.Instance.SendAck(eventId, status);
            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_ack_error", ex.Message);
        }
    }

    /// <summary>
    /// IPC entry-point for agent-core's periodic heartbeat. Parses the
    /// shape the TS client sends (`grpc-client.ts:~430`):
    ///   { deviceId, uptimeSeconds, agentVersion, policyVersion }
    /// and forwards to the gRPC bridge. Errors bubble up as a
    /// not_supported / grpc_heartbeat_error response so agent-core can
    /// trigger its own reconnect loop.
    /// </summary>
    public static async Task<PrivSvcResponse> HandleHeartbeat(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            var deviceId = GetString(p, "deviceId");
            if (string.IsNullOrWhiteSpace(deviceId))
                throw new Exception("deviceId required");

            long uptimeSeconds = 0;
            var uptimeStr = GetString(p, "uptimeSeconds");
            if (!string.IsNullOrWhiteSpace(uptimeStr))
                long.TryParse(uptimeStr, out uptimeSeconds);

            var agentVersion = GetString(p, "agentVersion") ?? "";
            var policyVersion = GetString(p, "policyVersion") ?? "";

            await GrpcBridgeSingleton.Instance.SendHeartbeat(
                deviceId, uptimeSeconds, agentVersion, policyVersion);

            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_heartbeat_error", ex.Message);
        }
    }

    // ── RCP M1.S1 — outbound signaling handlers ───────────────────────
    //
    // Each handler unpacks the params dict from agent-core and calls
    // the corresponding Send* method on GrpcBridgeSingleton. Error
    // shape matches HandleAck above so the TS client sees consistent
    // {ok}/{error,code,message} envelopes.

    public static async Task<PrivSvcResponse> HandleRemoteSessionAnswer(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var sessionId = GetString(p, "sessionId");
            var sdp = GetString(p, "sdp");
            if (string.IsNullOrWhiteSpace(sessionId)) throw new Exception("sessionId required");
            await GrpcBridgeSingleton.Instance.SendRemoteSessionAnswer(sessionId, sdp ?? "");
            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_remote_answer_error", ex.Message);
        }
    }

    public static async Task<PrivSvcResponse> HandleRemoteSessionIce(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var sessionId = GetString(p, "sessionId");
            var candidate = GetString(p, "candidate");
            var sdpMid = GetString(p, "sdpMid");
            var sdpMLineIndexStr = GetString(p, "sdpMLineIndex");
            int sdpMLineIndex = 0;
            if (!string.IsNullOrWhiteSpace(sdpMLineIndexStr)) int.TryParse(sdpMLineIndexStr, out sdpMLineIndex);
            if (string.IsNullOrWhiteSpace(sessionId)) throw new Exception("sessionId required");
            await GrpcBridgeSingleton.Instance.SendRemoteSessionIce(sessionId, candidate ?? "", sdpMid ?? "", sdpMLineIndex);
            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_remote_ice_error", ex.Message);
        }
    }

    public static async Task<PrivSvcResponse> HandleRemoteSessionClose(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var sessionId = GetString(p, "sessionId");
            var reason = GetString(p, "reason");
            if (string.IsNullOrWhiteSpace(sessionId)) throw new Exception("sessionId required");
            await GrpcBridgeSingleton.Instance.SendRemoteSessionClose(sessionId, reason ?? "");
            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_remote_close_error", ex.Message);
        }
    }

    public static async Task<PrivSvcResponse> HandleRemoteSessionError(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var sessionId = GetString(p, "sessionId");
            var code = GetString(p, "code");
            var message = GetString(p, "message");
            if (string.IsNullOrWhiteSpace(sessionId)) throw new Exception("sessionId required");
            await GrpcBridgeSingleton.Instance.SendRemoteSessionError(sessionId, code ?? "", message ?? "");
            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_remote_error_error", ex.Message);
        }
    }

    // RCP M1.S3 — agent → backend transcript chunks. Latency-tolerant
    // (these are buffered every ~5s) so we don't need the
    // direct-write fast path that Answer/Ice use.
    public static async Task<PrivSvcResponse> HandleRemoteSessionTranscript(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var sessionId = GetString(p, "sessionId");
            var stream = GetString(p, "stream");
            var data = GetString(p, "data");
            var tsStr = GetString(p, "tsDeltaSeconds");
            var bytesStr = GetString(p, "bytesCount");
            double tsDeltaSeconds = 0;
            int bytesCount = 0;
            if (!string.IsNullOrWhiteSpace(tsStr)) double.TryParse(tsStr, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out tsDeltaSeconds);
            if (!string.IsNullOrWhiteSpace(bytesStr)) int.TryParse(bytesStr, out bytesCount);
            if (string.IsNullOrWhiteSpace(sessionId)) throw new Exception("sessionId required");
            await GrpcBridgeSingleton.Instance.SendRemoteSessionTranscript(sessionId, stream ?? "stdout", tsDeltaSeconds, data ?? "", bytesCount);
            return PrivSvcResponse.Success(req.Id, new { ok = true });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "grpc_remote_transcript_error", ex.Message);
        }
    }
}
