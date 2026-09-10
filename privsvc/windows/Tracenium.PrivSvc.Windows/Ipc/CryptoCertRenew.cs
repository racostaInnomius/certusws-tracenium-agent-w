using Grpc.Core;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoCertRenew
{
    public static async Task<PrivSvcResponse> HandleRenewCert(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            string serverBaseUrl = GetString(p, "serverBaseUrl")?.TrimEnd('/') ?? "";
            string tenantId = GetString(p, "tenantId") ?? req.Meta?.TenantId ?? "";
            string deviceId = GetString(p, "deviceId") ?? req.Meta?.DeviceId ?? "";
            string currentThumbprint = GetString(p, "clientCertThumbprint") ?? "";

            if (string.IsNullOrWhiteSpace(serverBaseUrl))
                return PrivSvcResponse.Fail(req.Id, "bad_request", "serverBaseUrl required");

            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(deviceId))
                return PrivSvcResponse.Fail(req.Id, "bad_request", "tenantId/deviceId required");

            if (string.IsNullOrWhiteSpace(currentThumbprint))
                return PrivSvcResponse.Fail(req.Id, "bad_request", "clientCertThumbprint required");

            var currentCert = LoadCertFromLocalMachineMyByThumbprint(currentThumbprint);
            var pendingKeyName = $"tracenium-{deviceId}-renew-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";

            // ── ADR-0015: la renovación CONSERVA la forma del equipo ──────
            //
            // ⚠️ AQUÍ NO SE REENVIABA NI `keyAlgorithm` NI
            // `altKeyAlgorithm`, y ése era el agujero.
            //
            // Windows tiene la buena arquitectura de los tres —la
            // renovación DELEGA en el mismo generador que el
            // enrolamiento, así que no hay dos caminos que migrar— pero
            // le pasaba cuatro parámetros y ninguno decía qué forma
            // producir. Resultado idéntico al de macOS y Linux, donde el
            // fallo era un camino viejo sin migrar: un equipo enrolado en
            // híbrido se volvía CLÁSICO en su primera renovación, en
            // silencio y para siempre. Y la renovación es justo la vía
            // por la que rota la flota.
            //
            // Se conserva lo que el equipo YA tiene en vez de esperar que
            // el control plane lo diga en cada rotación: no hace falta
            // protocolo nuevo, y una renovación no puede DEGRADAR por
            // omisión. Lo explícito manda sobre lo heredado.
            var csrParams = new Dictionary<string, object>
            {
                ["tenantId"] = tenantId,
                ["deviceId"] = deviceId,
                ["reuseExistingKey"] = false,
                ["keyName"] = pendingKeyName,
                ["keyAlgorithm"] = GetString(req.Params, "keyAlgorithm")
                    ?? ClassicAlgorithmOf(currentCert)
            };

            // Ausente significa clásico, así que sólo se manda la clave si
            // el equipo ya la tiene o si alguien la pide a propósito.
            var altPedido = GetString(req.Params, "altKeyAlgorithm")
                ?? (AltKeyStore.Exists() ? "ML_DSA_65" : null);
            if (!string.IsNullOrWhiteSpace(altPedido))
            {
                csrParams["altKeyAlgorithm"] = altPedido;
            }

            var csrResponse = await CryptoCsr.HandleGenerateCsr(new PrivSvcRequest
            {
                Version = 1,
                Id = $"{req.Id}_csr",
                Method = "crypto.csr.generate",
                Params = csrParams,
                Meta = req.Meta ?? new PrivSvcMeta { TenantId = tenantId, DeviceId = deviceId }
            });

            if (!csrResponse.Ok)
                return PrivSvcResponse.Fail(req.Id, "csr_error", csrResponse.Error?.Message ?? "CSR generation failed");

            var csrPem = GetStringFromObject(csrResponse.Result, "csrPem");
            if (string.IsNullOrWhiteSpace(csrPem))
                return PrivSvcResponse.Fail(req.Id, "csr_error", "CSR response missing csrPem");

            // ── ADR-0015: la renovación va por gRPC, no por REST ──────────
            //
            // ⚠️ AQUÍ VIVÍA UN POST mTLS que llevaba devolviendo 401 para
            // TODA la flota desde el 2026-09-01: se puso
            // `clientCertificateMode: Ignore` en el Container App —para que
            // Chrome dejara de pedir certificado a los usuarios del
            // portal— y el ingress dejó de pedir el certificado de cliente
            // y de reenviarlo en `x-forwarded-client-cert`. Nadie pudo
            // notarlo durante nueve días: no caduca ningún certificado
            // hasta abril de 2027, así que esa ruta no se ejercita sola.
            //
            // Ahora la identidad es el certificado de par del canal que el
            // privsvc ya tiene abierto y que el servidor validó en el
            // handshake. Sin cabecera intermedia, sin conexión nueva.
            string clientCertPem;
            string caBundlePem;
            string renewStatus;
            try
            {
                var renovado = await GrpcBridgeSingleton.Instance.RenewCertAsync(csrPem);
                clientCertPem = renovado.ClientCertPem;
                caBundlePem = renovado.CaBundlePem;
                renewStatus = renovado.Status;
            }
            catch (RpcException rpc)
            {
                // El código viaja en el error para que el llamante pueda
                // distinguir «reintenta» de «no insistas»: un certificado
                // revocado no mejora reintentando.
                return PrivSvcResponse.Fail(
                    req.Id,
                    "renew_grpc_error",
                    $"{rpc.StatusCode}: {rpc.Status.Detail}");
            }
            catch (InvalidOperationException ex)
            {
                return PrivSvcResponse.Fail(req.Id, "renew_grpc_error", ex.Message);
            }

            if (string.IsNullOrWhiteSpace(clientCertPem))
                return PrivSvcResponse.Fail(req.Id, "renew_response_error", "clientCertPem missing");

            if (string.IsNullOrWhiteSpace(caBundlePem))
                return PrivSvcResponse.Fail(req.Id, "renew_response_error", "caBundlePem missing");

            var installResponse = await CryptoCertInstall.HandleInstallCert(new PrivSvcRequest
            {
                Version = 1,
                Id = $"{req.Id}_install",
                Method = "crypto.cert.install",
                Params = new Dictionary<string, object>
                {
                    ["deviceId"] = deviceId,
                    ["clientCertPem"] = clientCertPem,
                    ["caBundlePem"] = caBundlePem,
                    ["keyName"] = pendingKeyName,
                    // ADR-0011 fase 0, paso 1. La renovacion entra por el
                    // mismo handler que el enrolamiento, asi que sin esto
                    // la telemetria del pin no podria distinguir la
                    // linea base de una repeticion — y esa distincion es
                    // justo la que hace accionable un ancla no fijada.
                    ["pinSource"] = "renew"
                },
                Meta = req.Meta ?? new PrivSvcMeta { TenantId = tenantId, DeviceId = deviceId }
            });

            if (!installResponse.Ok)
                return PrivSvcResponse.Fail(req.Id, "cert_install_error", installResponse.Error?.Message ?? "Certificate install failed");

            var result = new
            {
                deviceId,
                clientCertPem,
                caBundlePem,
                previousClientCertThumbprint = currentCert.Thumbprint,
                clientCertThumbprint = GetStringFromObject(installResponse.Result, "clientCertThumbprint"),
                issuingCaThumbprint = GetStringFromObject(installResponse.Result, "issuingCaThumbprint"),
                notAfter = GetStringFromObject(installResponse.Result, "notAfter"),
                status = string.IsNullOrWhiteSpace(renewStatus) ? "pending" : renewStatus
            };

            return PrivSvcResponse.Success(req.Id, result);
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "cert_renew_error", ex.ToString());
        }
    }

    private static X509Certificate2 LoadCertFromLocalMachineMyByThumbprint(string thumbprint)
    {
        var normalized = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var certs = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
        if (certs.Count == 0)
            throw new Exception($"Client certificate not found: {normalized}");

        var cert = certs[0];
        if (!cert.HasPrivateKey)
            throw new Exception($"Client certificate has no private key: {normalized}");

        return cert;
    }

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return null;
        if (val is string s) return s;
        if (val is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.String) return je.GetString();
            return je.ToString();
        }
        return val.ToString();
    }

    /// <summary>
    /// Qué algoritmo clásico usa HOY este equipo, leído de su propio
    /// certificado.
    ///
    /// ⚠️ Se deduce del certificado y no de una preferencia guardada: el
    /// certificado es lo que el backend aceptó, y una preferencia que
    /// discrepe de él produciría una renovación que cambia de algoritmo
    /// sin que nadie lo haya pedido. Ante la duda, `RSA_2048`, que es lo
    /// que tiene la flota entera hoy.
    /// </summary>
    internal static string ClassicAlgorithmOf(X509Certificate2? cert)
    {
        try
        {
            if (cert?.GetECDsaPublicKey() is not null) return "ECDSA_P256";
        }
        catch
        {
            // Un certificado ilegible no debe impedir renovar: se cae al
            // default, que es lo que el equipo tenía antes de todo esto.
        }
        return "RSA_2048";
    }

    private static string? GetStringFromObject(object? value, string key)
    {
        if (value == null) return null;

        if (value is JsonElement je && je.ValueKind == JsonValueKind.Object)
        {
            if (!je.TryGetProperty(key, out var prop)) return null;
            return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
        }

        var propInfo = value.GetType().GetProperty(key);
        return propInfo?.GetValue(value)?.ToString();
    }
}
