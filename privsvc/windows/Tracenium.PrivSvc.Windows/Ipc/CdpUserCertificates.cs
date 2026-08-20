// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpUserCertificates.cs
//
// CDP — per-user certificate stores (HKEY_USERS), read-only.
//
// The blind spot this closes: until now CDP read only LocalMachine, so a
// certificate in a user's Personal store — client-auth, S/MIME, code
// signing, precisely the ones that carry a private key — did not exist
// for the inventory.
//
// ── WHY THE REGISTRY AND NOT X509Store ──────────────────────────────
//
// `new X509Store(name, StoreLocation.CurrentUser)` from a LocalSystem
// service opens SYSTEM'S OWN profile, not the logged-in users'. It
// succeeds, returns almost nothing, and is silently wrong — the worst
// possible failure for an inventory feature, because it looks like
// "this fleet has no user certificates".
//
// Impersonating each user, or loading their hive, would be the other
// route: more privilege, more moving parts, and a service that touches
// user sessions. Reading HKEY_USERS is none of that — it is the same
// registry access SoftwareInventory already does, and it needs no new
// privilege because LocalSystem can already read it.
//
// ⚠️ COVERAGE LIMIT, stated rather than hidden: only hives that are
// LOADED appear under HKEY_USERS, which in practice means users with an
// active session. A certificate belonging to someone who is logged off
// is not visible. That is a real gap; it is also the honest boundary of
// what can be read without loading other people's profiles.
//
// ── THIS IS A NEW METHOD, NOT A CHANGE TO cdp.certs.read ────────────
//
// `cdp.certs.read` works and is in production. Extending it in place
// would put a brand-new registry walk in the path of the collector that
// already feeds the whole plugin. A separate method cannot regress it,
// and an agent talking to an older PrivSvc simply gets `not_supported`
// and carries on with the machine stores.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpUserCertificates
{
    /// <summary>Same budget and rationale as CdpCertificates.</summary>
    public const int HandlerBudgetMs = 45_000;

    /// <summary>Per-user stores worth reading. Mirrors the machine whitelist.</summary>
    private static readonly HashSet<string> AllowedStores = new(StringComparer.OrdinalIgnoreCase)
    {
        "My", "CA", "Root", "TrustedPeople", "TrustedPublisher"
    };

    /// <summary>`CERT_CERT_PROP_ID` — the encoded certificate inside a store blob.</summary>
    private const uint CERT_CERT_PROP_ID = 32;

    /// <summary>A certificate is a few KB; this only bounds a malformed length field.</summary>
    private const int MaxPropBytes = 512 * 1024;

    /// <summary>
    /// Pull the DER certificate out of a registry store blob.
    ///
    /// The blob is a flat sequence of property records:
    ///
    ///     DWORD propId | DWORD flags | DWORD cbData | byte[cbData]
    ///
    /// and the certificate is the record with propId 32. Everything else
    /// (friendly name, key provider info, hashes) is skipped.
    ///
    /// Internal rather than private so it can be unit-tested: this parser
    /// is the only genuinely new logic here, and it is the part that
    /// cannot be exercised without a Windows box.
    /// </summary>
    internal static byte[]? ExtractCertificateFromBlob(byte[] blob)
    {
        if (blob == null || blob.Length < 12) return null;

        var offset = 0;
        // Bounded by the blob itself: every iteration consumes at least
        // the 12-byte header, so this cannot spin.
        while (offset + 12 <= blob.Length)
        {
            var propId = BitConverter.ToUInt32(blob, offset);
            var cbData = BitConverter.ToUInt32(blob, offset + 8);
            offset += 12;

            // A length that does not fit is a malformed blob, not a
            // reason to guess: stop rather than read past the end.
            if (cbData > MaxPropBytes || offset + (long)cbData > blob.Length) return null;

            if (propId == CERT_CERT_PROP_ID && cbData > 0)
            {
                var der = new byte[cbData];
                Buffer.BlockCopy(blob, offset, der, 0, (int)cbData);
                return der;
            }

            offset += (int)cbData;
        }

        return null;
    }

    /// <summary>
    /// True for a real interactive user's SID.
    ///
    /// HKEY_USERS also carries the service accounts (SYSTEM S-1-5-18,
    /// LOCAL SERVICE -19, NETWORK SERVICE -20), `.DEFAULT`, and a
    /// `_Classes` companion key per user. None of those are a person's
    /// certificate store, and reading them would pad the inventory with
    /// entries nobody can act on.
    /// </summary>
    internal static bool IsInteractiveUserSid(string sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return false;
        if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return false;
        if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            var certificates = new List<object>();
            var storeErrors = new List<object>();
            var clock = Stopwatch.StartNew();
            var budgetExceeded = false;
            var usersSeen = 0;

            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);

            foreach (var sid in users.GetSubKeyNames())
            {
                if (budgetExceeded) break;
                if (!IsInteractiveUserSid(sid)) continue;
                usersSeen += 1;

                foreach (var storeName in AllowedStores)
                {
                    if (budgetExceeded) break;
                    try
                    {
                        using var certsKey = users.OpenSubKey(
                            $@"{sid}\Software\Microsoft\SystemCertificates\{storeName}\Certificates");
                        if (certsKey == null) continue;

                        foreach (var thumbprint in certsKey.GetSubKeyNames())
                        {
                            // Checked per certificate: the registry read
                            // is inside this loop, so a per-store check
                            // could overrun by a whole store.
                            if (clock.ElapsedMilliseconds > HandlerBudgetMs)
                            {
                                budgetExceeded = true;
                                break;
                            }

                            using var certKey = certsKey.OpenSubKey(thumbprint);
                            if (certKey?.GetValue("Blob") is not byte[] blob) continue;

                            var der = ExtractCertificateFromBlob(blob);
                            if (der == null) continue;

                            certificates.Add(new
                            {
                                store = storeName,
                                userSid = sid,
                                rawDerBase64 = Convert.ToBase64String(der),
                                // The private key lives in the user's key
                                // container, which this handler does not
                                // open. Claiming otherwise would be
                                // inventing evidence nobody collected.
                                hasPrivateKey = false
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        // One unreadable store must not cost the rest.
                        storeErrors.Add(new { store = storeName, userSid = sid, message = ex.Message });
                    }
                }
            }

            Console.WriteLine(
                $"[PrivSvc][CdpUserCertificates] {certificates.Count} certs from {usersSeen} loaded user hive(s) " +
                $"in {clock.ElapsedMilliseconds}ms ({storeErrors.Count} store errors" +
                $"{(budgetExceeded ? ", BUDGET EXCEEDED — partial" : "")})");

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                certificates,
                storeErrors,
                usersSeen,
                budgetExceeded,
                elapsedMs = clock.ElapsedMilliseconds
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "cdp_user_certs_read_failed", ex.Message));
        }
    }
}
