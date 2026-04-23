using System.Security.Principal;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using Tracenium.PrivSvc.Windows.Grpc;
using Tracenium.PrivSvc.Windows.Ipc;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class Router
{
    private readonly ILogger _logger;

    public Router(ILogger logger)
    {
        _logger = logger;
    }

    private static bool IsLocalSystem()
    {
        var id = WindowsIdentity.GetCurrent();
        return id != null && id.IsSystem;
    }

    public Task<PrivSvcResponse> HandleAsync(PrivSvcRequest req, Action<object> push, CancellationToken ct)
    {
        // Basic validation
        if (req.Version != 1)
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_version", "Unsupported protocol version."));

        if (string.IsNullOrWhiteSpace(req.Id))
            return Task.FromResult(PrivSvcResponse.Fail("unknown", "bad_request", "Missing id."));

        if (string.IsNullOrWhiteSpace(req.Method))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "Missing method."));

        if (ct.IsCancellationRequested)
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "cancelled", "Request cancelled."));

        // Minimal audit log (do not log full Params to avoid leaking secrets/certs)
        _logger.LogInformation("[IPC] {Method} id={Id} tenant={Tenant} device={Device}",
            req.Method,
            req.Id,
            req.Meta?.TenantId,
            req.Meta?.DeviceId);

        // Enforce LocalSystem for sensitive operations (crypto + gRPC bridge)
        if (req.Method.StartsWith("grpc.", StringComparison.OrdinalIgnoreCase) ||
            req.Method.StartsWith("crypto.", StringComparison.OrdinalIgnoreCase))
        {
            if (!IsLocalSystem())
            {
                _logger.LogWarning("[IPC] Forbidden: LocalSystem required for {Method} id={Id}", req.Method, req.Id);
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "forbidden", "LocalSystem required"));
            }
        }

        // Route
        return req.Method switch
        {
            "ping" => Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                service = "TraceniumPrivSvc",
                version = "1.1.0",
                utc = DateTime.UtcNow.ToString("O")
            })),

            "identity" => Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                user = WindowsIdentity.GetCurrent().Name,
                isSystem = WindowsIdentity.GetCurrent().IsSystem,
                utc = DateTime.UtcNow.ToString("O")
            })),

            // Inventory / compliance
            "software.inventory" => SoftwareInventory.Handle(req),
            "security.compliance" => SecurityCompliance.Handle(req),
            "patch.scan" => PatchManagement.HandleScan(req),
            "patch.install" => PatchManagement.HandleInstall(req),

            // Crypto
            "crypto.csr.generate" => CryptoCsr.HandleGenerateCsr(req),
            "crypto.cert.install" => CryptoCertInstall.HandleInstallCert(req),
            "crypto.cert.renew" => CryptoCertRenew.HandleRenewCert(req),

            // gRPC bridge (session mode)
            // NOTE: These handlers should enforce LocalSystem if required.
            "grpc.connect" => IpcGrpcHandlers.HandleConnect(req, push),
            "grpc.facts.send" => IpcGrpcHandlers.HandleFactsSend(req),
            "grpc.facts.chunk" => IpcGrpcHandlers.HandleFactsChunk(req),
            "grpc.close" => IpcGrpcHandlers.HandleClose(req),
            "grpc.ack" => IpcGrpcHandlers.HandleAck(req),
            "grpc.heartbeat" => IpcGrpcHandlers.HandleHeartbeat(req),

            _ => Task.FromResult(PrivSvcResponse.Fail(req.Id, "not_supported", $"Unsupported method: {req.Method}"))
        };
    }
}
