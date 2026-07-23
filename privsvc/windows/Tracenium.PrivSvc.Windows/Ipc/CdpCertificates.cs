// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpCertificates.cs
//
// CDP (Crypto Discovery Plugin) — read-only enumeration of the
// LocalMachine certificate stores via the native X509Store API (no
// PowerShell spawn). Returns raw DER (base64) + store context +
// HasPrivateKey flag per certificate; all X.509 parsing happens in the
// Node.js agent so every platform produces identical wire items.
//
// SECURITY CONTRACT: this handler NEVER exports or touches private key
// material. `hasPrivateKey` is the X509Certificate2.HasPrivateKey
// attribute — a boolean lookup, not a key read. RawData is the public
// certificate blob only. Same read-only class as security.compliance.

using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpCertificates
{
    // Whitelist: only LocalMachine stores the design allows in Phase A.
    // Requests naming any other store are silently ignored (not an
    // error) so a newer agent policy can't turn this into an arbitrary
    // store reader.
    private static readonly HashSet<string> AllowedStores = new(StringComparer.OrdinalIgnoreCase)
    {
        "My",
        "WebHosting",
        "CA",
        "TrustedPeople",
        "TrustedPublisher",
        "Root",
        "AuthRoot"
    };

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            var requested = GetRequestedStores(req.Params);
            var certificates = new List<object>();
            var storeErrors = new List<object>();

            foreach (var storeName in requested)
            {
                if (!AllowedStores.Contains(storeName))
                {
                    Console.WriteLine($"[PrivSvc][CdpCertificates] Ignoring non-whitelisted store '{storeName}'");
                    continue;
                }

                try
                {
                    using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    foreach (var cert in store.Certificates)
                    {
                        try
                        {
                            certificates.Add(new
                            {
                                store = storeName,
                                rawDerBase64 = Convert.ToBase64String(cert.RawData),
                                hasPrivateKey = SafeHasPrivateKey(cert)
                            });
                        }
                        finally
                        {
                            // X509Certificate2 handles native resources.
                            cert.Dispose();
                        }
                    }
                }
                catch (Exception ex)
                {
                    // A single unopenable store (e.g. WebHosting absent on
                    // client SKUs) must not fail the whole scan.
                    storeErrors.Add(new { store = storeName, message = ex.Message });
                }
            }

            Console.WriteLine($"[PrivSvc][CdpCertificates] Collected {certificates.Count} certs from {requested.Count} stores ({storeErrors.Count} store errors)");

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                certificates,
                storeErrors,
                collectedUtc = DateTime.UtcNow.ToString("O")
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "cdp_certs_read_failed", ex.Message));
        }
    }

    private static bool SafeHasPrivateKey(X509Certificate2 cert)
    {
        try
        {
            return cert.HasPrivateKey;
        }
        catch
        {
            // CNG/CSP mismatches can throw on the attribute lookup for
            // orphaned key references — treat as "no usable key".
            return false;
        }
    }

    private static List<string> GetRequestedStores(Dictionary<string, object>? p)
    {
        // Default = full whitelist; the agent may narrow it.
        if (p == null || !p.TryGetValue("stores", out var raw) || raw is null)
        {
            return AllowedStores.ToList();
        }

        try
        {
            if (raw is System.Text.Json.JsonElement el &&
                el.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                var stores = el.EnumerateArray()
                    .Where(item => item.ValueKind == System.Text.Json.JsonValueKind.String)
                    .Select(item => item.GetString() ?? "")
                    .Where(name => name.Length > 0)
                    .ToList();
                return stores.Count > 0 ? stores : AllowedStores.ToList();
            }
        }
        catch
        {
            // fall through to default
        }

        return AllowedStores.ToList();
    }
}
