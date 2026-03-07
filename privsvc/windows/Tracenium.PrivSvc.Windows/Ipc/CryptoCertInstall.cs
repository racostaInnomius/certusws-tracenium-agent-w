// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCertInstall.cs
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Reflection;
using System.IO;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoCertInstall
{
    private const string KeyName = "tracenium-agentcore-p256";

    public static Task<PrivSvcResponse> HandleInstallCert(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();

            string? rootCaPem = GetString(p, "rootCaPem");
            string? issuingCaPem = GetString(p, "issuingCaPem");
            string? certPem = GetString(p, "clientCertPem");

            if (string.IsNullOrWhiteSpace(certPem))
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "bad_request", "clientCertPem required"));

            // -----------------------------
            // Install Root CA
            // -----------------------------
            X509Certificate2? rootCert = null;

            if (!string.IsNullOrWhiteSpace(rootCaPem))
            {
                rootCert = X509Certificate2.CreateFromPem(rootCaPem);
            }
            else
            {
                // fallback: load embedded root CA bundled with the agent
                var asm = Assembly.GetExecutingAssembly();
                var resName = asm.GetManifestResourceNames()
                    .FirstOrDefault(n => n.EndsWith("root-ca.crt", StringComparison.OrdinalIgnoreCase));

                if (resName != null)
                {
                    using var stream = asm.GetManifestResourceStream(resName);
                    if (stream != null)
                    {
                        using var ms = new MemoryStream();
                        stream.CopyTo(ms);
                        rootCert = new X509Certificate2(ms.ToArray());
                    }
                }
            }

            if (rootCert != null)
            {
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
            if (!string.IsNullOrWhiteSpace(issuingCaPem))
            {
                var issuingCert = X509Certificate2.CreateFromPem(issuingCaPem);

                using var caStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                caStore.Open(OpenFlags.ReadWrite);

                if (!caStore.Certificates
                    .Find(X509FindType.FindByThumbprint, issuingCert.Thumbprint, false)
                    .Any())
                {
                    caStore.Add(issuingCert);
                }

                caStore.Close();
            }

            // -----------------------------
            // Install Client Certificate
            // -----------------------------
            var certTmp = X509Certificate2.CreateFromPem(certPem);

            var key = CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
            var ecdsa = new ECDsaCng(key);

            var cert = certTmp.CopyWithPrivateKey(ecdsa);

            cert = new X509Certificate2(
                cert.RawData,
                (string?)null,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet
            );

            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            store.Add(cert);

            cert.FriendlyName = "Tracenium Agent mTLS Client Certificate";

            store.Close();

            var result = new
            {
                clientThumbprint = cert.Thumbprint,
                subject = cert.Subject,
                notAfter = cert.NotAfter
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
}