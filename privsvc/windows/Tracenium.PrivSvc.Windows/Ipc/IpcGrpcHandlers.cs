using Tracenium.PrivSvc.Windows.Grpc;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class IpcGrpcHandlers
{
    public static Task<PrivSvcResponse> HandleConnect(PrivSvcRequest req, Action<object> push)
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

            if (string.IsNullOrWhiteSpace(clientTp))
                throw new Exception("clientCertThumbprint required");

            var tenantId = GetString(p, "tenantId") ?? req.Meta?.TenantId ?? "";
            var deviceId = GetString(p, "deviceId") ?? req.Meta?.DeviceId ?? "";
            var agentVersion = GetString(p, "agentVersion");

            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(deviceId))
                throw new Exception("tenantId/deviceId required");

            // Generate a stable session id for this connection.
            connectionId = Guid.NewGuid().ToString("N");

            // Register this pipe as a push sink for this session.
            GrpcBridgeSingleton.Instance.RegisterPushSink(connectionId, push);

            try
            {
                GrpcBridgeSingleton.Instance.Connect(new GrpcBridgeConnectOptions
                {
                    Target = target,
                    ClientCertThumbprint = clientTp,
                    TenantId = tenantId,
                    DeviceId = deviceId,
                    AgentVersion = agentVersion
                });
            }
            catch
            {
                // Ensure we don't leak a push sink if connect fails.
                try { GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId); } catch { }
                throw;
            }

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { connected = true, connectionId }));
        }
        catch (Exception ex)
        {
            // Best-effort cleanup if we allocated a connectionId.
            if (!string.IsNullOrWhiteSpace(connectionId))
            {
                try { GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId); } catch { }
            }
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "grpc_connect_error", ex.Message));
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

            if (p.TryGetValue("facts", out var factsObj) && factsObj != null)
            {
                var factsDict = ToDict(factsObj);
                eventId ??= GetString(factsDict, "eventId");
                payloadJson ??= GetString(factsDict, "payloadJson");
            }

            if (string.IsNullOrWhiteSpace(eventId))
                throw new Exception("eventId required");
            payloadJson ??= "{}";

            GrpcBridgeSingleton.Instance.SendFacts(eventId, payloadJson);

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { queued = true }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "grpc_facts_send_error", ex.Message));
        }
    }

    public static Task<PrivSvcResponse> HandleClose(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var connectionId = GetString(p, "connectionId") ?? GetString(p, "sinkId");

            if (!string.IsNullOrWhiteSpace(connectionId))
            {
                try { GrpcBridgeSingleton.Instance.UnregisterPushSink(connectionId); } catch { }
            }

            GrpcBridgeSingleton.Instance.Close();
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { closed = true }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "grpc_close_error", ex.Message));
        }
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
}