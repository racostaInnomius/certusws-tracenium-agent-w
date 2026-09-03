using System.Net.Http.Json;
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

            var csrResponse = await CryptoCsr.HandleGenerateCsr(new PrivSvcRequest
            {
                Version = 1,
                Id = $"{req.Id}_csr",
                Method = "crypto.csr.generate",
                Params = new Dictionary<string, object>
                {
                    ["tenantId"] = tenantId,
                    ["deviceId"] = deviceId,
                    ["reuseExistingKey"] = false,
                    ["keyName"] = pendingKeyName
                },
                Meta = req.Meta ?? new PrivSvcMeta { TenantId = tenantId, DeviceId = deviceId }
            });

            if (!csrResponse.Ok)
                return PrivSvcResponse.Fail(req.Id, "csr_error", csrResponse.Error?.Message ?? "CSR generation failed");

            var csrPem = GetStringFromObject(csrResponse.Result, "csrPem");
            if (string.IsNullOrWhiteSpace(csrPem))
                return PrivSvcResponse.Fail(req.Id, "csr_error", "CSR response missing csrPem");

            using var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(currentCert);
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;

            using var http = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };

            var renewUrl = $"{serverBaseUrl}/api/v1/security/certificates/renew";
            using var response = await http.PostAsJsonAsync(renewUrl, new { csrPem });
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                return PrivSvcResponse.Fail(req.Id, "renew_http_error", $"HTTP {(int)response.StatusCode}: {body}");

            using var json = JsonDocument.Parse(body);
            var root = json.RootElement;

            if (!root.TryGetProperty("clientCertPem", out var certProp))
                return PrivSvcResponse.Fail(req.Id, "renew_response_error", "clientCertPem missing");

            if (!root.TryGetProperty("caBundlePem", out var caProp))
                return PrivSvcResponse.Fail(req.Id, "renew_response_error", "caBundlePem missing");

            var clientCertPem = certProp.GetString() ?? "";
            var caBundlePem = caProp.GetString() ?? "";

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
                status = root.TryGetProperty("status", out var statusProp) ? statusProp.GetString() : "pending"
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
