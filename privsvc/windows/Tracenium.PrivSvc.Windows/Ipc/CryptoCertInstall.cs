// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCertInstall.cs
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Reflection;
using System.IO;
using System.Linq;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoCertInstall
{

    public static Task<PrivSvcResponse> HandleInstallCert(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            string? rootCaPem = GetString(p, "rootCaPem");
            string? issuingCaPem = GetString(p, "issuingCaPem");
            string? certPem = GetString(p, "clientCertPem");
            string? caBundlePem = GetString(p, "caBundlePem");

            // Backend sends clientCertPem + caBundlePem (may contain issuing + root chain)
            List<X509Certificate2>? bundleCerts = null;

            if (!string.IsNullOrWhiteSpace(caBundlePem))
            {
                bundleCerts = ParsePemBundle(caBundlePem);
            }

            string? deviceId = GetString(p, "deviceId");
            if (string.IsNullOrWhiteSpace(deviceId))
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "bad_request", "deviceId required"));

            string keyName = $"tracenium-{deviceId}";

            if (string.IsNullOrWhiteSpace(certPem))
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "bad_request", "clientCertPem required"));

            // -----------------------------
            // Install Root CA
            // -----------------------------
            X509Certificate2? rootCert = null;

            if (bundleCerts != null && bundleCerts.Count > 0)
            {
                // Only accept a self‑signed certificate as Root CA.
                // Do NOT infer root from bundle topology because the backend
                // usually sends only the issuing CA in caBundlePem.
                rootCert = bundleCerts.FirstOrDefault(c => c.Subject == c.Issuer);
            }

            if (rootCert == null && !string.IsNullOrWhiteSpace(rootCaPem))
            {
                rootCert = X509Certificate2.CreateFromPem(rootCaPem);
            }

            if (rootCert == null)
            {
                try
                {
                    var baseDir = AppContext.BaseDirectory;
                    var rootPath = Path.Combine(baseDir, "assets", "root-ca.crt");

                    if (File.Exists(rootPath))
                    {
                        Console.WriteLine($"[PrivSvc][Crypto] Loading root CA from {rootPath}");
                        var pem = File.ReadAllText(rootPath);
                        rootCert = X509Certificate2.CreateFromPem(pem);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PrivSvc][Crypto] Failed loading root CA: {ex.Message}");
                }
            }

            if (rootCert != null)
            {
                Console.WriteLine($"[PrivSvc][Crypto] Installing Root CA: {rootCert.Subject}");
                using var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                rootStore.Open(OpenFlags.ReadWrite);

                if (!rootStore.Certificates
                    .Find(X509FindType.FindByThumbprint, rootCert.Thumbprint, false)
                    .Any())
                {
                    rootStore.Add(rootCert);
                }

                rootStore.Close();
            }

            // -----------------------------
            // Install Issuing CA
            // -----------------------------
            if (bundleCerts != null)
            {
                foreach (var caCert in bundleCerts.Where(c =>
                    (rootCert == null || c.Thumbprint != rootCert.Thumbprint) &&
                    c.Subject != c.Issuer)) // never treat self‑signed certs as issuing
                {
                    using var caStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                    caStore.Open(OpenFlags.ReadWrite);

                    if (!caStore.Certificates
                        .Find(X509FindType.FindByThumbprint, caCert.Thumbprint, false)
                        .Any())
                    {
                        caStore.Add(caCert);
                    }

                    caStore.Close();
                }
            }

            // -----------------------------
            // Install Client Certificate
            // -----------------------------
            var certTmp = X509Certificate2.CreateFromPem(certPem);

            Console.WriteLine($"[PrivSvc][Crypto] Installing cert using key: {keyName}");

            // Open previously generated key container
            var key = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey
            );

            using var ecdsa = new ECDsaCng(key);

            // Associate certificate with private key
            var certWithKey = certTmp.CopyWithPrivateKey(ecdsa);

            // Validate EKU (Client Authentication required for mTLS)
            var ekuExt = certWithKey.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .FirstOrDefault();

            if (ekuExt == null || !ekuExt.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(o => o.Value == "1.3.6.1.5.5.7.3.2")) // Client Authentication
            {
                throw new Exception("Client certificate missing required EKU: Client Authentication");
            }

            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            // Avoid duplicate install
            var existing = store.Certificates
                .Find(X509FindType.FindByThumbprint, certWithKey.Thumbprint, false);

            X509Certificate2 finalCert;

            if (existing.Count > 0)
            {
                finalCert = existing[0];
                Console.WriteLine("[PrivSvc][Crypto] Client certificate already installed.");
            }
            else
            {
                store.Add(certWithKey);
                finalCert = certWithKey;
                Console.WriteLine("[PrivSvc][Crypto] Client certificate installed.");
            }

            finalCert.FriendlyName = "Tracenium Agent mTLS Client Certificate";

            store.Close();

            string? issuingThumbprint = null;

            if (bundleCerts != null)
            {
                var issuing = bundleCerts.FirstOrDefault(c => c.Subject != c.Issuer);
                if (issuing != null)
                    issuingThumbprint = issuing.Thumbprint;
            }

            var result = new
            {
                deviceId = deviceId,
                clientCertThumbprint = finalCert.Thumbprint,
                issuingCaThumbprint = issuingThumbprint,
                subject = finalCert.Subject,
                notAfter = finalCert.NotAfter
            };

            return Task.FromResult(
                PrivSvcResponse.Success(req.Id, result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "cert_install_error", ex.ToString()));
        }
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

    private static List<X509Certificate2> ParsePemBundle(string pem)
    {
        var certs = new List<X509Certificate2>();

        var blocks = pem.Split("-----END CERTIFICATE-----");

        foreach (var block in blocks)
        {
            if (block.Contains("BEGIN CERTIFICATE"))
            {
                var certPem = block + "-----END CERTIFICATE-----";
                certs.Add(X509Certificate2.CreateFromPem(certPem));
            }
        }

        return certs;
    }
}