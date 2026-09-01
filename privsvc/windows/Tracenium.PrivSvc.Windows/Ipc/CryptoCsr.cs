// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCsr.cs
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoCsr
{
    // Clave persistente en CNG - LocalMachine (Machine Keyset)
    // Nota: con MachineKeySet el key material se guarda en el equipo.

    // Cross-platform contract (driven by agent-core):
    //
    //   Default algorithm: RSA_2048
    //
    // The backend's CSR validator checks the DER public key OID and
    // rejects anything that isn't rsaEncryption (1.2.840.113549.1.1.1).
    // This used to default to ECDSA_P256 via CngAlgorithm.ECDsaP256,
    // which silently broke Windows enrollment once the backend's
    // validator tightened — macOS kept working because its openssl
    // flow already used RSA.
    //
    // We keep the algorithm negotiable via the `keyAlgorithm` param so
    // the day the backend accepts ECDSA we only have to change one
    // caller (agent-core) rather than tracking down every PrivSvc.
    private const string DefaultKeyAlgorithm = "RSA_2048";
    private const int RsaKeyBits = 2048;

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
            string keyAlgorithm = GetString(p, "keyAlgorithm") ?? DefaultKeyAlgorithm;

            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(deviceId))
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "tenantId/deviceId required"));

            dnsName ??= Environment.MachineName;

            // 1) Abrir/crear key persistente (CNG) - one key per device
            //
            // ADR-0011 action item 9. El nombre se DERIVA: antes se usaba
            // el del llamante tal cual, lo que permitia (a) borrar la
            // identidad mTLS viva del agente pidiendo su nombre con
            // reuseExistingKey:false —caida de flota sin arreglo remoto— y
            // (b) apuntar a un contenedor CNG de otra aplicacion del
            // equipo, sacando el daño fuera del producto. Ver CryptoKeyNames.
            string keyName;
            try
            {
                keyName = CryptoKeyNames.Resolve(requestedKeyName, deviceId);
            }
            catch (ArgumentException ex)
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", ex.Message));
            }

            if (CryptoKeyNames.WouldDestroyLiveIdentity(keyName, deviceId, reuse))
            {
                // La rotacion NO pasa por aqui: crea una clave pendiente
                // aparte precisamente para no tocar la que esta en uso.
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "refused",
                    "no se destruye la identidad mTLS viva por peticion; " +
                    "la rotacion usa una clave pendiente"));
            }

            bool created;

            CertificateRequest reqCsr;
            AsymmetricAlgorithm cngKeyWrapper;

            // Dispatch to the algorithm-specific key factory. Both
            // branches return an AsymmetricAlgorithm that the
            // CertificateRequest constructor can consume directly.
            switch (keyAlgorithm.ToUpperInvariant())
            {
                case "RSA_2048":
                {
                    var rsa = OpenOrCreateMachineRsaKey(keyName, reuse, out created);
                    cngKeyWrapper = rsa;
                    reqCsr = new CertificateRequest(
                        new X500DistinguishedName($"CN={EscapeDn(dnsName)}"),
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1
                    );
                    break;
                }
                case "ECDSA_P256":
                {
                    // Legacy path — kept so existing deployments that
                    // already have ECDSA keys in CNG can still rotate
                    // without us having to purge their key store.
                    var ecdsa = OpenOrCreateMachineEcdsaKey(keyName, reuse, out created);
                    cngKeyWrapper = ecdsa;
                    reqCsr = new CertificateRequest(
                        new X500DistinguishedName($"CN={EscapeDn(dnsName)}"),
                        ecdsa,
                        HashAlgorithmName.SHA256
                    );
                    break;
                }
                default:
                    return Task.FromResult(
                        PrivSvcResponse.Fail(req.Id, "bad_request",
                            $"unsupported keyAlgorithm: {keyAlgorithm}"));
            }

            // Diagnostic logging (helps identify key reuse vs creation)
            try
            {
                Console.WriteLine($"[PrivSvc][Crypto] CNG key '{keyName}' ({keyAlgorithm}) created: {created}");
            }
            catch { }

            try
            {
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
                    algo = keyAlgorithm,
                    keyAlgorithm,
                    created
                };

                return Task.FromResult(PrivSvcResponse.Success(req.Id, result));
            }
            finally
            {
                // Both RSACng and ECDsaCng implement IDisposable — release
                // the CNG handle once the CSR is built.
                (cngKeyWrapper as IDisposable)?.Dispose();
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "csr_error", ex.Message));
        }
    }

    // ===== Helpers =====

    /// <summary>
    /// Open or create a persistent RSA 2048 key in the Microsoft Software
    /// Key Storage Provider at the machine scope.
    ///
    /// If a key with <paramref name="keyName"/> already exists and its
    /// algorithm matches RSA, we reuse it (unless <c>reuseExisting</c>
    /// is false). If the stored key is a different algorithm (e.g. an
    /// ECDSA key from the pre-contract era on an already-deployed host),
    /// we delete it and re-create as RSA — otherwise CertificateRequest
    /// would later throw an InvalidCastException when we wrap it in
    /// RSACng.
    /// </summary>
    private static RSA OpenOrCreateMachineRsaKey(string keyName, bool reuseExisting, out bool created)
    {
        created = false;

        // Probe the existing key's algorithm before deciding reuse.
        bool exists = CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider,
            CngKeyOpenOptions.MachineKey);

        if (exists)
        {
            try
            {
                var existingKey = CngKey.Open(
                    keyName,
                    CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    CngKeyOpenOptions.MachineKey
                );

                bool algoMatches = string.Equals(
                    existingKey.Algorithm.Algorithm,
                    CngAlgorithm.Rsa.Algorithm,
                    StringComparison.OrdinalIgnoreCase);

                if (algoMatches && reuseExisting)
                {
                    return new RSACng(existingKey);
                }

                // Either the caller wants a fresh key, or the existing
                // key is the wrong algorithm (e.g. a lingering ECDSA key
                // from before we pinned RSA). Either way, delete + recreate.
                existingKey.Delete();
            }
            catch
            {
                // Fall through to creation path.
            }
        }

        var creationParams = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey
        };

        creationParams.Parameters.Add(
            new CngProperty("Length", BitConverter.GetBytes(RsaKeyBits), CngPropertyOptions.None)
        );

        try
        {
            var key = CngKey.Create(CngAlgorithm.Rsa, keyName, creationParams);
            created = true;
            return new RSACng(key);
        }
        catch (CryptographicException ex) when (ex.Message.Contains("exists", StringComparison.OrdinalIgnoreCase))
        {
            // Race with another process that created the key between
            // our Exists check and Create call — just open and return.
            var existing = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey
            );
            return new RSACng(existing);
        }
    }

    private static ECDsa OpenOrCreateMachineEcdsaKey(string keyName, bool reuseExisting, out bool created)
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
