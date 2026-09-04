using System.Diagnostics;
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

    // Methods the gRPC bridge drives continuously. Logging every one of these
    // would bury the diagnostics we actually care about and churn the disk, so
    // they are recorded only when they FAIL (see HandleAsync).
    private static readonly HashSet<string> HighFrequencyMethods =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "ping",
            "identity",
            "grpc.ack",
            "grpc.heartbeat",
            "grpc.facts.send",
            "grpc.facts.chunk",
        };

    /// <summary>
    /// Entry point with diagnostics. Wraps the dispatch so every privileged
    /// call leaves a trace of "arrived → how long → what it answered".
    ///
    /// This exists because a failed agent self-update surfaced on the Node side
    /// as nothing but `PrivSvc timeout`: the PrivSvc only ever wrote the gRPC
    /// bridge log, so there was no way to tell whether the IPC call reached a
    /// handler, which one, or where it hung. An unanswered call is now visible
    /// as a start line with no matching completion.
    /// </summary>
    public async Task<PrivSvcResponse> HandleAsync(PrivSvcRequest req, Action<object> push, CancellationToken ct)
    {
        var method = req.Method ?? "(none)";
        var noisy = HighFrequencyMethods.Contains(method);
        var startTicks = Stopwatch.GetTimestamp();

        // Traffic on the pipe is the only honest proof that AgentCore's event
        // loop is still turning. GrpcBridge's heartbeat loop reads this to
        // decide whether it may keep telling the control plane this device is
        // online — see AgentLiveness for why that gate exists.
        AgentLiveness.Touch();

        if (!noisy)
        {
            IpcLog.Write($"--> {method} id={req.Id} tenant={req.Meta?.TenantId} device={req.Meta?.DeviceId}");
        }

        try
        {
            var resp = await DispatchAsync(req, push, ct);
            var ms = (Stopwatch.GetTimestamp() - startTicks) * 1000.0 / Stopwatch.Frequency;
            var failed = resp?.Error != null;

            // Always log failures, even for the chatty methods — a failing
            // heartbeat is exactly the kind of thing worth seeing.
            if (!noisy || failed)
            {
                IpcLog.Write(failed
                    ? $"<-- {method} id={req.Id} FAILED code={resp?.Error?.Code} msg={Truncate(resp?.Error?.Message, 200)} ({ms:F0}ms)"
                    : $"<-- {method} id={req.Id} ok ({ms:F0}ms)");
            }
            return resp!;
        }
        catch (Exception ex)
        {
            // A throw here means the caller gets no response at all and will
            // sit until ITS timeout fires — precisely the invisible failure
            // mode this instrumentation was added to expose.
            var ms = (Stopwatch.GetTimestamp() - startTicks) * 1000.0 / Stopwatch.Frequency;
            IpcLog.Write($"<-- {method} id={req.Id} THREW {ex.GetType().Name}: {Truncate(ex.Message, 300)} ({ms:F0}ms)");
            throw;
        }
    }

    private static string Truncate(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s!.Length <= max ? s : s[..max];
    }

    private Task<PrivSvcResponse> DispatchAsync(PrivSvcRequest req, Action<object> push, CancellationToken ct)
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
            req.Method.StartsWith("pmp.", StringComparison.OrdinalIgnoreCase) ||
            // cdp.* faltaba en las TRES plataformas. Aqui alcanza tanto a
            // los metodos nuevos de la fase 2 de ADR-0011 como a
            // `cdp.anchor.distrust`, que ya escribia en el store
            // Disallowed de LocalMachine sin pasar por este gate.
            req.Method.StartsWith("cdp.", StringComparison.OrdinalIgnoreCase))
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
                version = "1.1.57",
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
            "printer.inventory" => PrinterInventory.Handle(req),
            "security.compliance" => SecurityCompliance.Handle(req),
            // CDP — read-only LocalMachine cert store enumeration
            // (metadata + public DER only; never key material).
            "cdp.certs.read" => CdpCertificates.Handle(req),
            // Metodo NUEVO, no una extension del anterior: cdp.certs.read
            // esta en produccion y alimenta todo el plugin. Un agente
            // contra un PrivSvc antiguo recibe `not_supported` y sigue
            // con los stores de maquina.
            "cdp.certs.readUser" => CdpUserCertificates.Handle(req),
            // ADR-0011 decision 10. DESCONFIAR, no borrar: se anade a
            // Disallowed y NO se quita de Root, porque el trust store de
            // Windows se repuebla bajo demanda y un borrado se desharia
            // solo.
            "cdp.anchor.distrust" => CdpAnchorDistrust.Handle(req),
            "patch.scan" => PatchManagement.HandleScan(req),
            "patch.install" => PatchManagement.HandleInstall(req),

            // Crypto
            // Infrastructure Gateway credential custody (ADR-0001). PrivSvc holds
            // the enrollment private key, so it is the only component that can
            // open a credential sealed against this device's certificate.
            "credential.provision" => CredentialStore.HandleProvision(req),
            "credential.retrieve" => CredentialStore.HandleRetrieve(req),
            "credential.remove" => CredentialStore.HandleRemove(req),

            // ADR-0011 fase 2 — emision para certificados AJENOS al
            // agente. Metodos NUEVOS, y no por gusto: `crypto.csr.generate`
            // acepta un `keyName` del llamante sin validar, asi que
            // reutilizarlo permitiria borrar la clave de enrolamiento del
            // propio agente. Ver la cabecera de CdpKeys.cs.
            "cdp.csr.generate" => CdpKeys.HandleCsrGenerate(req),
            "cdp.key.destroy" => CdpKeys.HandleKeyDestroy(req),
            "cdp.key.list" => CdpKeys.HandleKeyList(req),
            // ADR-0011 fase 3. Aqui CdpWriteGuard deja de estar sin
            // cablear: allowlist {My, WebHosting} + cadena validada
            // contra el trust store LOCAL. NO reutiliza
            // CryptoCertInstall, que escribe en Root y es fontaneria de
            // enrolamiento.
            "cdp.cert.install" => CdpCertInstall.Handle(req),

            // Fase 4 — conector AD CS: la base de emisiones de una CA, cruda.
            "cdp.adcs.read" => CdpAdcs.Handle(req),

            "crypto.csr.generate" => CryptoCsr.HandleGenerateCsr(req),
            "crypto.cert.install" => CryptoCertInstall.HandleInstallCert(req),
            "crypto.cert.renew" => CryptoCertRenew.HandleRenewCert(req),
            // ADR-0013 — la clave que abre la credencial de vCenter. Nace y
            // muere con el rol de gateway; ninguna otra ruta la nombra.
            "crypto.gwkey.ensure" => CryptoGatewayKey.HandleEnsure(req),
            "crypto.gwkey.destroy" => CryptoGatewayKey.HandleDestroy(req),

            // gRPC bridge (session mode)
            // NOTE: These handlers should enforce LocalSystem if required.
            "grpc.connect" => IpcGrpcHandlers.HandleConnect(req, push),
            "grpc.facts.send" => IpcGrpcHandlers.HandleFactsSend(req),
            "grpc.facts.chunk" => IpcGrpcHandlers.HandleFactsChunk(req),
            "grpc.close" => IpcGrpcHandlers.HandleClose(req),
            "grpc.ack" => IpcGrpcHandlers.HandleAck(req),
            "grpc.heartbeat" => IpcGrpcHandlers.HandleHeartbeat(req),
            "grpc.catalog.request" => IpcGrpcHandlers.HandleCatalogRequest(req),
            "grpc.selfInstall.request" => IpcGrpcHandlers.HandleSelfInstallRequest(req),

            // RCP M1.S1 — agent-side outbound signaling. The
            // Node.js plugin sends these when the WebRTC peer
            // generates an answer / discovers a candidate / closes.
            "grpc.send.remoteSessionAnswer" => IpcGrpcHandlers.HandleRemoteSessionAnswer(req),
            "grpc.send.remoteSessionIce" => IpcGrpcHandlers.HandleRemoteSessionIce(req),
            "grpc.send.remoteSessionClose" => IpcGrpcHandlers.HandleRemoteSessionClose(req),
            "grpc.send.remoteSessionError" => IpcGrpcHandlers.HandleRemoteSessionError(req),
            "grpc.send.remoteSessionTranscript" => IpcGrpcHandlers.HandleRemoteSessionTranscript(req),

            // RCP M2.S1 — file transfer audit (agent → server).
            "grpc.send.remoteFileTransferAudit" => IpcGrpcHandlers.HandleRemoteFileTransferAudit(req),
            // RCP M3.S1 — screen share audit (agent → server).
            "grpc.send.remoteScreenAudit" => IpcGrpcHandlers.HandleRemoteScreenAudit(req),
            // RCP M3.S1 — screen capture IPC (Node.js → PrivSvc).
            // PrivSvc owns the GDI+ BitBlt call; result is base64 JPEG.
            "screen.capture" => IpcGrpcHandlers.HandleScreenCapture(req),
            // RCP M3.S4 — synthetic input injection (mouse + keyboard)
            // forwarded from the operator's browser via the agent.
            "input.inject" => IpcGrpcHandlers.HandleInputInject(req),

            // Relanza la bandeja si el usuario de consola se quedó sin ella.
            // Tras cada auto-actualización el MSI la cierra —tiene que, para
            // reemplazar su .exe— y nadie la reabre hasta el siguiente inicio
            // de sesión. Desde ADR-0012 eso apaga el indicador de "te están
            // viendo" y el diálogo de consentimiento. Ver TrayPresence.cs.
            "tray.ensure" => Task.FromResult(TrayPresence.Ensure(req)),

            // SDP — Phase 1-E. See Ipc/Sdp.cs.
            "sdp.detect" => Sdp.HandleDetect(req),
            "sdp.download" => Sdp.HandleDownload(req),
            "sdp.install" => Sdp.HandleInstall(req),
            "sdp.uninstall" => Sdp.HandleUninstall(req),
            "sdp.verifySignature" => Sdp.HandleVerifySignature(req),

            // Distribution Phase B — DP role: warm the LAN cache and serve
            // peers over mTLS. Covered by the same `sdp.` LocalSystem gate.
            "sdp.dp.prefetch" => Dp.HandlePrefetch(req),
            "sdp.dp.status" => Dp.HandleStatus(req),

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
