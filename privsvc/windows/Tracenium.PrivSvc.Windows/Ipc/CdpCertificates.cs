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

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpCertificates
{
    /// <summary>
    /// Wall-clock ceiling for one scan.
    ///
    /// This handler used to have none, which made the agent-side invariant
    /// (caller outwaits handler) unstatable for cdp.certs.read: there was
    /// no handler budget to be above, so the client sat on the 8s default
    /// that nobody had chosen for it.
    ///
    /// The unbounded cost is HasPrivateKey. It is written like an
    /// attribute read but it asks the key's provider for a handle, so on a
    /// host whose keys live in a TPM, on a smart card, or behind a
    /// network-backed KSP it is I/O — and an orphaned key reference can
    /// block before it throws. Multiply by every certificate in seven
    /// stores and the tail has no natural limit.
    ///
    /// The partial result IS returned, but as diagnostic material, not as
    /// inventory: the agent turns `budgetExceeded` into a collector error
    /// so the control plane keeps the last good projection. It must not be
    /// ingested — a CDP baseline reconciles, so a short payload marks every
    /// certificate missing from it as removed. What the partial buys us is
    /// a precise message ("stopped after 412 certificates in 45s") instead
    /// of a bare timeout.
    /// </summary>
    public const int HandlerBudgetMs = 45_000;

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
            var clock = Stopwatch.StartNew();
            var budgetExceeded = false;

            foreach (var storeName in requested)
            {
                if (budgetExceeded) break;

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
                            // Checked per certificate, not per store: the
                            // expensive call is inside this loop, so a
                            // per-store check could overrun the budget by
                            // one whole store's worth of key lookups.
                            if (clock.ElapsedMilliseconds > HandlerBudgetMs)
                            {
                                budgetExceeded = true;
                                break;
                            }

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

            Console.WriteLine($"[PrivSvc][CdpCertificates] Collected {certificates.Count} certs from {requested.Count} stores in {clock.ElapsedMilliseconds}ms ({storeErrors.Count} store errors{(budgetExceeded ? ", BUDGET EXCEEDED — partial" : "")})");

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                certificates,
                storeErrors,
                // Reported, never silent: a truncated scan that looked
                // complete would read as "these certificates were removed".
                budgetExceeded,
                elapsedMs = clock.ElapsedMilliseconds,
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
