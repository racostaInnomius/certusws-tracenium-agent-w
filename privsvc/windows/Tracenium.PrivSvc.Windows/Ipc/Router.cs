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

        // Enforce LocalSystem for sensitive operations (crypto + gRPC bridge + sdp + pmp).
        // sdp.* (download / detect / install) all run privileged work
        // — even sdp.detect's command_exit runs arbitrary commands the
        // catalog operator specified, which is a privileged operation
        // by definition. Same gate as crypto/grpc.
        //
        // pmp.* covers the Patch Management v2 remediation primitives
        // (read_check_state + remediate). Both touch privileged
        // surface — registry edits, powershell cmdlets, optional-
        // feature toggles — and there is no unprivileged subset.
        if (req.Method.StartsWith("grpc.", StringComparison.OrdinalIgnoreCase) ||
            req.Method.StartsWith("crypto.", StringComparison.OrdinalIgnoreCase) ||
            req.Method.StartsWith("sdp.", StringComparison.OrdinalIgnoreCase) ||
            req.Method.StartsWith("pmp.", StringComparison.OrdinalIgnoreCase))
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
                version = "1.1.16",
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

            // SDP — Phase 1-E. See Ipc/Sdp.cs.
            "sdp.detect" => Sdp.HandleDetect(req),
            "sdp.download" => Sdp.HandleDownload(req),
            "sdp.install" => Sdp.HandleInstall(req),

            // PMv2 — Phase 1-E remediation primitives. See Ipc/PmpRemediation.cs.
            // Phase 1 dispatch table covers 4 Windows checkIds:
            // legacy_tls_disabled / weak_ciphers_disabled /
            // smbv1_disabled / firewall.profiles_enabled.
            "pmp.read_check_state" => PmpRemediation.HandleReadCheckState(req),
            "pmp.remediate" => PmpRemediation.HandleRemediate(req),

            _ => Task.FromResult(PrivSvcResponse.Fail(req.Id, "not_supported", $"Unsupported method: {req.Method}"))
        };
    }
}
