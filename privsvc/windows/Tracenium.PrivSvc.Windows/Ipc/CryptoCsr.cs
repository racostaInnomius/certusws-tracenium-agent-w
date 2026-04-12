// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCsr.cs
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoCsr
{
    // Clave persistente en CNG - LocalMachine (Machine Keyset)
    // Nota: con MachineKeySet el key material se guarda en el equipo.

    public static Task<PrivSvcResponse> HandleGenerateCsr(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            string tenantId = GetString(p, "tenantId") ?? req.Meta?.TenantId ?? "";
            string deviceId = GetString(p, "deviceId") ?? req.Meta?.DeviceId ?? "";
            string? dnsName = GetString(p, "dnsName");
            string? requestedKeyName = GetString(p, "keyName");
            bool reuse = GetBool(p, "reuseExistingKey", true);

            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(deviceId))
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "tenantId/deviceId required"));

            dnsName ??= Environment.MachineName;

            // 1) Abrir/crear key persistente (CNG) - one key per device
            string keyName = string.IsNullOrWhiteSpace(requestedKeyName)
                ? $"tracenium-{deviceId}"
                : requestedKeyName;
            bool created;
            using var ecdsa = OpenOrCreateMachineKey(keyName, reuse, out created);

            // Diagnostic logging (helps identify key reuse vs creation)
            try
            {
                Console.WriteLine($"[PrivSvc][Crypto] CNG key '{keyName}' created: {created}");
            }
            catch { }

            // 2) Construir CSR
            // Subject minimal (CN=dnsName)
            var subject = new X500DistinguishedName($"CN={EscapeDn(dnsName)}");

            var reqCsr = new CertificateRequest(
                subject,
                ecdsa,
                HashAlgorithmName.SHA256
            );

            // Key usage y EKU clientAuth
            reqCsr.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature,
                    critical: true
                )
            );

            var eku = new OidCollection();
            eku.Add(new Oid("1.3.6.1.5.5.7.3.2")); // clientAuth
            reqCsr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, critical: true));

            // SAN: DNS hostname
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(dnsName);

            // Opcional: URI que el backend también mete en cert final
            // (no es obligatorio en CSR, pero ayuda a consistencia)
            san.AddUri(new Uri($"tracenium://tenant/{tenantId}/device/{deviceId}"));

            reqCsr.CertificateExtensions.Add(san.Build(critical: false));

            // 3) Export CSR DER -> PEM
            var csrDer = reqCsr.CreateSigningRequest();
            var csrPem = PemEncode("CERTIFICATE REQUEST", csrDer);

            var result = new
            {
                keyId = keyName,
                deviceId,
                dnsName,
                csrPem,
                algo = "ECDSA_P256",
                created
            };

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "csr_error", ex.Message));
        }
    }

    // ===== Helpers =====

    private static ECDsa OpenOrCreateMachineKey(string keyName, bool reuseExisting, out bool created)
    {
        created = false;

        // First attempt: open existing key if reuse is allowed.
        if (reuseExisting)
        {
        try
        {
            var existing = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey
            );
            return new ECDsaCng(existing);
        }
        catch
        {
            // Ignore and continue to creation path.
        }
        }
        else
        {
        // If reuse is disabled, delete the key if it exists.
        try
        {
            if (CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                var toDelete = CngKey.Open(
                    keyName,
                    CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    CngKeyOpenOptions.MachineKey
                );
                toDelete.Delete();
            }
        }
        catch
        {
            // Ignore delete errors.
        }
        }

        var creationParams = new CngKeyCreationParameters
        {
        Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
        ExportPolicy = CngExportPolicies.None, // NO exportable
        KeyUsage = CngKeyUsages.Signing,
        KeyCreationOptions = CngKeyCreationOptions.MachineKey
        };

        creationParams.Parameters.Add(
            new CngProperty("Length", BitConverter.GetBytes(256), CngPropertyOptions.None)
        );

        try
        {
        // Try to create the key.
        var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParams);
        created = true;
        return new ECDsaCng(key);
        }
        catch (CryptographicException ex)
        {
        // If creation fails because the key already exists, open it.
        if (ex.Message.Contains("exists", StringComparison.OrdinalIgnoreCase))
        {
            var existing = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey
            );
            return new ECDsaCng(existing);
        }

        throw;
        }
    }
    private static string PemEncode(string label, byte[] der)
    {
        var b64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n";
    }

    private static string EscapeDn(string s) => s.Replace("\"", "\\\"");

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

    private static bool GetBool(Dictionary<string, object> p, string key, bool def)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return def;
        if (val is bool b) return b;

        if (val is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.True) return true;
            if (je.ValueKind == JsonValueKind.False) return false;
            if (je.ValueKind == JsonValueKind.String && bool.TryParse(je.GetString(), out var bb)) return bb;
            return def;
        }

        if (val is string s && bool.TryParse(s, out var b2)) return b2;
        return def;
    }
}
