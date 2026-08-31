using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Custody of the vCenter service-account credential for the Infrastructure
/// Gateway (ADR-0001).
///
/// PrivSvc owns this because it is the only component holding the enrollment
/// private key. The credential is sealed in the admin's BROWSER against this
/// device's certificate and relayed by a control plane that has no key for it,
/// so it can be opened here and nowhere else.
///
/// KEY LOOKUP — by fingerprint, not by name.
/// The envelope carries the SHA-256 of the certificate it was sealed to. We use
/// that to find the matching cert in LocalMachine\My rather than deriving a key
/// name from the device id. That makes certificate rotation behave exactly
/// right: an envelope sealed to a cert we no longer hold reports
/// <c>stale_envelope</c> — "re-enter the credential" — instead of failing as an
/// indistinguishable decryption error.
///
/// AT-REST — DPAPI machine scope.
/// The unwrapped credential is stored under DPAPI with
/// <see cref="DataProtectionScope.LocalMachine"/>: the protecting key is managed
/// by Windows and never leaves the machine, so a stolen file is inert
/// elsewhere. The file itself is ACL'd to SYSTEM + Administrators.
/// </summary>
public static class CredentialStore
{
    private const int EnvelopeVersion = 1;
    private const string EnvelopeAlg = "RSA-OAEP-256+A256GCM";

    private static string StoreDir()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "credentials");
        Directory.CreateDirectory(dir);
        HardenDirectory(dir);
        return dir;
    }

    /// <summary>SYSTEM + Administrators only; inheritance disabled.</summary>
    private static void HardenDirectory(string dir)
    {
        try
        {
            var info = new DirectoryInfo(dir);
            var sec = info.GetAccessControl();
            // ProgramData grants Users read by default — that is exactly what a
            // credential directory must not have.
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                sec.RemoveAccessRule(rule);

            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            {
                sec.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(sid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }
            info.SetAccessControl(sec);
        }
        catch
        {
            // A hardening failure must not make the service unusable; the DPAPI
            // machine-scope protection still stands on its own.
        }
    }

    private static string CredentialPath(string reference)
    {
        // Refs are namespaced ("vcenter/default") and arrive off the wire, so
        // flatten aggressively — this value must never influence the path.
        var safe = new string(reference.Select(c =>
            char.IsLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_').ToArray());
        if (safe.Length == 0) safe = "default";
        if (safe.Length > 120) safe = safe[..120];
        return Path.Combine(StoreDir(), $"credential-{safe}.bin");
    }

    // ── IPC handlers ────────────────────────────────────────────────────────

    public static Task<PrivSvcResponse> HandleProvision(PrivSvcRequest req)
    {
        var p = req.Params;
        var reference = GetString(p, "ref") ?? "vcenter/default";

        try
        {
            var (username, password, fingerprint) = OpenEnvelope(p);
            var plain = JsonSerializer.SerializeToUtf8Bytes(new { username, password });
            try
            {
                var sealedBytes = ProtectedData.Protect(plain, null, DataProtectionScope.LocalMachine);
                File.WriteAllBytes(CredentialPath(reference), sealedBytes);
            }
            finally
            {
                Array.Clear(plain);
            }
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { ok = true, certFingerprint = fingerprint }));
        }
        catch (CredentialException ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, ex.Code, ex.Message));
        }
        catch (Exception)
        {
            // Never surface raw crypto or IO detail: it can leak oracle
            // information, and the caller only needs the class of failure.
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "store_unavailable", "could not store the credential"));
        }
    }

    public static Task<PrivSvcResponse> HandleRetrieve(PrivSvcRequest req)
    {
        var reference = GetString(req.Params, "ref") ?? "vcenter/default";
        var file = CredentialPath(reference);
        if (!File.Exists(file))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "not_found", "no credential stored under that reference"));

        try
        {
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(file), null, DataProtectionScope.LocalMachine);
            try
            {
                using var doc = JsonDocument.Parse(plain);
                var root = doc.RootElement;
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new
                {
                    username = root.GetProperty("username").GetString(),
                    password = root.GetProperty("password").GetString()
                }));
            }
            finally
            {
                Array.Clear(plain);
            }
        }
        catch (Exception)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "store_unavailable", "stored credential could not be read"));
        }
    }

    public static Task<PrivSvcResponse> HandleRemove(PrivSvcRequest req)
    {
        var reference = GetString(req.Params, "ref") ?? "vcenter/default";
        try
        {
            // Idempotent by contract: already-gone is the desired end state, not
            // an error to retry forever.
            File.Delete(CredentialPath(reference));
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { ok = true }));
        }
        catch (Exception)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "store_unavailable", "could not remove the credential"));
        }
    }

    // ── Envelope ────────────────────────────────────────────────────────────

    private sealed class CredentialException : Exception
    {
        public string Code { get; }
        public CredentialException(string code, string message) : base(message) => Code = code;
    }

    /// <summary>
    /// Open a sealed envelope. Mirrors the browser's sealCredential and the
    /// Node reference implementation byte for byte: RSA-OAEP-SHA256 unwraps the
    /// AES key, AES-256-GCM decrypts the payload, and the certificate
    /// fingerprint is bound as additional authenticated data.
    /// </summary>
    private static (string username, string password, string fingerprint) OpenEnvelope(Dictionary<string, object>? p)
    {
        if (GetObject(p, "envelope") is not { } env)
            throw new CredentialException("malformed", "envelope missing");

        var version = env.TryGetProperty("v", out var v) && v.TryGetInt32(out var vi) ? vi : -1;
        var alg = env.TryGetProperty("alg", out var a) ? a.GetString() : null;
        if (version != EnvelopeVersion || alg != EnvelopeAlg)
            throw new CredentialException("unsupported_version", $"unsupported envelope {version}/{alg}");

        var fingerprint = RequireString(env, "certFingerprint").Replace(":", "").Replace(" ", "").ToLowerInvariant();
        var ek = FromBase64Url(RequireString(env, "ek"));
        var iv = FromBase64Url(RequireString(env, "iv"));
        var ct = FromBase64Url(RequireString(env, "ct"));
        var tag = FromBase64Url(RequireString(env, "tag"));

        using var cert = FindCertificateByFingerprint(fingerprint)
            ?? throw new CredentialException("stale_envelope",
                "credential was sealed to a certificate this device no longer holds");

        using var rsa = cert.GetRSAPrivateKey()
            ?? throw new CredentialException("decrypt_failed", "certificate has no usable private key");

        byte[] aesKey;
        try
        {
            aesKey = rsa.Decrypt(ek, RSAEncryptionPadding.OaepSHA256);
        }
        catch
        {
            // Two very different faults reach this catch, and telling an
            // operator only that the unwrap failed sends them to re-type a
            // password that was never the problem.
            //
            // So ask the certificate itself: encrypt a nonce with the public
            // key in the store and try to open it with the private key the
            // store hands back for it. If that round trip fails, this device's
            // certificate and key simply do not correspond — nothing about the
            // envelope, the credential, or the browser is wrong, and the only
            // fix is re-enrolling the device.
            //
            // Seen on a gateway whose agent had been replaced by an MSI push
            // over a running install: the certificate survived, its key
            // container did not follow.
            if (!CertificateKeyPairIsUsable(cert))
            {
                throw new CredentialException(
                    "decrypt_failed",
                    "this device's certificate and private key do not match — re-enrol the device; "
                        + "re-entering the credential cannot help");
            }
            throw new CredentialException("decrypt_failed", "could not unwrap the envelope key");
        }

        try
        {
            var plain = new byte[ct.Length];
            using var gcm = new AesGcm(aesKey, tag.Length);
            gcm.Decrypt(iv, ct, tag, plain, Encoding.UTF8.GetBytes(fingerprint));
            try
            {
                using var doc = JsonDocument.Parse(plain);
                var root = doc.RootElement;
                var username = root.TryGetProperty("username", out var u) ? u.GetString() : null;
                var password = root.TryGetProperty("password", out var pw) ? pw.GetString() : null;
                if (username is null || password is null)
                    throw new CredentialException("malformed", "envelope payload is not a credential");
                return (username, password, fingerprint);
            }
            finally
            {
                Array.Clear(plain);
            }
        }
        catch (CredentialException)
        {
            throw;
        }
        catch
        {
            throw new CredentialException("decrypt_failed", "envelope failed authentication");
        }
        finally
        {
            Array.Clear(aesKey);
        }
    }

    /// <summary>
    /// The LocalMachine\My certificate whose DER SHA-256 matches, or null.
    /// Matching on the fingerprint the envelope names is what lets a rotated
    /// certificate be reported as stale rather than as a decryption failure.
    /// </summary>
    private static X509Certificate2? FindCertificateByFingerprint(string sha256Hex)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        foreach (var candidate in store.Certificates)
        {
            var hash = Convert.ToHexString(candidate.GetCertHash(HashAlgorithmName.SHA256)).ToLowerInvariant();
            if (hash == sha256Hex) return candidate;
        }
        return null;
    }

    private static string RequireString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String)
            throw new CredentialException("malformed", $"envelope field {name} missing");
        var s = el.GetString();
        if (string.IsNullOrEmpty(s))
            throw new CredentialException("malformed", $"envelope field {name} missing");
        return s;
    }

    /// <summary>base64url (RFC 4648 §5) — the wire format, not standard base64.</summary>
    /// <summary>
    /// Does the private key the store hands back for this certificate actually
    /// belong to it?
    ///
    /// A cheap round trip with a random nonce, using the same padding the
    /// envelope uses. Only ever called on a failure path, so it costs nothing
    /// in the normal case and turns an ambiguous unwrap error into an
    /// instruction.
    /// </summary>
    private static bool CertificateKeyPairIsUsable(X509Certificate2 cert)
    {
        try
        {
            using var pub = cert.GetRSAPublicKey();
            using var priv = cert.GetRSAPrivateKey();
            if (pub is null || priv is null) return false;

            var nonce = RandomNumberGenerator.GetBytes(16);
            var sealedNonce = pub.Encrypt(nonce, RSAEncryptionPadding.OaepSHA256);
            var opened = priv.Decrypt(sealedNonce, RSAEncryptionPadding.OaepSHA256);
            return CryptographicOperations.FixedTimeEquals(nonce, opened);
        }
        catch
        {
            // Any failure here IS the answer: the pair is not usable.
            return false;
        }
    }

    private static byte[] FromBase64Url(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        switch (b64.Length % 4)
        {
            case 2: b64 += "=="; break;
            case 3: b64 += "="; break;
            case 1: throw new CredentialException("malformed", "malformed base64url in envelope");
        }
        try { return Convert.FromBase64String(b64); }
        catch { throw new CredentialException("malformed", "malformed base64url in envelope"); }
    }

    /// <summary>Same shape the other handlers use: values arrive boxed as JsonElement.</summary>
    private static string? GetString(Dictionary<string, object>? p, string key)
    {
        if (p == null || !p.TryGetValue(key, out var val) || val == null) return null;
        if (val is string s) return s;
        if (val is JsonElement je)
            return je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
        return val.ToString();
    }

    /// <summary>The `envelope` sub-object, as a JsonElement.</summary>
    private static JsonElement? GetObject(Dictionary<string, object>? p, string key)
    {
        if (p == null || !p.TryGetValue(key, out var val) || val == null) return null;
        if (val is JsonElement je) return je.ValueKind == JsonValueKind.Object ? je : null;
        // Defensive: a non-JsonElement value means the envelope did not survive
        // deserialisation as an object — treat as malformed rather than guess.
        return null;
    }
}
