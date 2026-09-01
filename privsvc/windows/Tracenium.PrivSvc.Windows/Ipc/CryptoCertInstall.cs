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

            // Mismo parametro, mismo tratamiento (ADR-0011 action item 9).
            // Aqui no se borra nada —solo se abre el contenedor— pero
            // dejarlo libre seria un arreglo a medias: es la otra mitad
            // del mismo flujo y la misma superficie.
            string keyName;
            try
            {
                keyName = CryptoKeyNames.Resolve(GetString(p, "keyName"), deviceId);
            }
            catch (ArgumentException ex)
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", ex.Message));
            }

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

            // ── Pin de anclas (ADR-0011 fase 0) ─────────────────────
            //
            // Ultima comprobacion antes de que una raiz entre en el trust
            // store DEL SISTEMA. En `observe` (por defecto) solo avisa;
            // en `enforce` niega la instalacion de un ancla que este
            // equipo no habia visto nunca.
            //
            // Va aqui, en el privsvc, y no en el backend: un gate en el
            // control plane no defiende de un control plane comprometido,
            // que es justo el adversario de esta ruta.
            if (rootCert != null)
            {
                var pinVerdict = AnchorPin.Evaluate(
                    AnchorPin.Load(),
                    new List<string> { rootCert.Thumbprint },
                    AnchorPin.IsEnforcing());

                Console.WriteLine($"[PrivSvc][Crypto] {AnchorPin.Describe(pinVerdict)}");

                if (pinVerdict.Rejected.Count > 0)
                {
                    // Se niega el ancla, NO el enrolamiento: la identidad
                    // de cliente y las intermedias siguen instalandose.
                    // Romper el enrolamiento entero por esto dejaria al
                    // equipo incomunicado, que es peor que el riesgo que
                    // se intenta evitar.
                    Console.WriteLine(
                        $"[PrivSvc][Crypto] Root CA RECHAZADA por anchor-pin: {rootCert.Subject}");
                    rootCert = null;
                }
                else
                {
                    AnchorPin.Save(pinVerdict.Pinned.Concat(pinVerdict.Incoming));
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

            // Open previously generated key container. We can't assume
            // ECDSA anymore — since the contract pinned RSA_2048 most
            // fresh enrolls will produce an RSA CNG key, but legacy
            // hosts that enrolled before the contract change still have
            // ECDSA keys sitting in the same container name. Detect at
            // runtime and wrap with the matching provider.
            var key = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey
            );

            // Associate certificate with private key. CopyWithPrivateKey
            // has RSA and ECDSA overloads — picking the right one is
            // the whole reason we dispatch on key.Algorithm here.
            X509Certificate2 certWithKey;
            if (string.Equals(key.Algorithm.Algorithm, CngAlgorithm.Rsa.Algorithm,
                StringComparison.OrdinalIgnoreCase))
            {
                using var rsa = new RSACng(key);
                certWithKey = certTmp.CopyWithPrivateKey(rsa);
            }
            else if (string.Equals(key.Algorithm.Algorithm, CngAlgorithm.ECDsaP256.Algorithm,
                StringComparison.OrdinalIgnoreCase))
            {
                using var ecdsa = new ECDsaCng(key);
                certWithKey = certTmp.CopyWithPrivateKey(ecdsa);
            }
            else
            {
                key.Dispose();
                throw new Exception(
                    $"Unsupported CNG key algorithm '{key.Algorithm.Algorithm}' for key '{keyName}'");
            }

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

            // Avoid duplicate install — but only when the entry already there
            // is actually usable.
            //
            // Windows is the only platform where privsvc keeps its own copy of
            // the identity: Linux and macOS unseal with the same PEM files gRPC
            // and the distribution point use, while here the store IS the key
            // vault. That makes the store the one copy nothing else on the
            // device exercises, so a broken key association is invisible —
            // mTLS keeps working from the files, the DP keeps serving, the
            // agent keeps reporting, and the fault only surfaces when someone
            // seals a vCenter credential months later.
            //
            // Skipping the install because the thumbprint matched kept whatever
            // association the existing entry had, including none or a stale
            // one, and reported success. Now the entry has to prove it can
            // still do the one thing it is here for.
            var existing = store.Certificates
                .Find(X509FindType.FindByThumbprint, certWithKey.Thumbprint, false);

            X509Certificate2 finalCert;

            if (existing.Count > 0 && PrivateKeyMatches(existing[0]))
            {
                finalCert = existing[0];
                Console.WriteLine("[PrivSvc][Crypto] Client certificate already installed.");
            }
            else
            {
                if (existing.Count > 0)
                {
                    // Replace rather than leave both: two entries with the same
                    // thumbprint and different key associations is precisely the
                    // ambiguity that produced this bug, and a lookup by
                    // fingerprint takes the first match.
                    Console.WriteLine(
                        "[PrivSvc][Crypto] Existing client certificate has an unusable private key; replacing it.");
                    foreach (var stale in existing)
                    {
                        try { store.Remove(stale); } catch { /* best effort */ }
                    }
                }
                store.Add(certWithKey);
                finalCert = certWithKey;
                Console.WriteLine("[PrivSvc][Crypto] Client certificate installed.");
            }

            finalCert.FriendlyName = "Tracenium Agent mTLS Client Certificate";

            store.Close();

            string? issuingThumbprint = null;
            var issuingThumbprints = new System.Collections.Generic.List<string>();

            if (bundleCerts != null)
            {
                // TODAS las CA intermedias del bundle, no sólo la primera.
                //
                // Fijar una sola convierte cualquier rotación de la CA emisora en
                // una desconexión: el pin exige una huella que la cadena nueva ya
                // no contiene, y sin conexión no hay forma de mandar el arreglo —
                // se vuelve una visita presencial por equipo. Con la lista, basta
                // que el bundle instalado contenga la CA vieja Y la nueva durante
                // la transición para que el equipo acepte ambas cadenas.
                foreach (var c in bundleCerts.Where(c => c.Subject != c.Issuer))
                {
                    if (!string.IsNullOrWhiteSpace(c.Thumbprint))
                        issuingThumbprints.Add(c.Thumbprint!);
                }
                issuingThumbprint = issuingThumbprints.FirstOrDefault();
            }

            var result = new
            {
                deviceId = deviceId,
                clientCertThumbprint = finalCert.Thumbprint,
                // Se conserva el campo singular por compatibilidad: un agente
                // nuevo hablando con un control plane viejo, o al revés.
                issuingCaThumbprint = issuingThumbprint,
                issuingCaThumbprints = issuingThumbprints.ToArray(),
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

    /// <summary>
    /// Can this store entry still open what its own certificate seals?
    ///
    /// A certificate and the key the store hands back for it are linked by a
    /// container reference, not by cryptography — nothing validates the pair on
    /// the way in or on the way out. So we validate it here, the only moment we
    /// can still fix it, with the same round trip CredentialStore uses to
    /// diagnose the failure later.
    /// </summary>
    private static bool PrivateKeyMatches(X509Certificate2 cert)
    {
        try
        {
            using var pub = cert.GetRSAPublicKey();
            using var priv = cert.GetRSAPrivateKey();
            if (pub is null || priv is null) return false;

            var nonce = RandomNumberGenerator.GetBytes(16);
            var opened = priv.Decrypt(
                pub.Encrypt(nonce, RSAEncryptionPadding.OaepSHA256),
                RSAEncryptionPadding.OaepSHA256);
            return CryptographicOperations.FixedTimeEquals(nonce, opened);
        }
        catch
        {
            // ECDSA certificates have no RSA key to test; treat "cannot test"
            // as usable so this never blocks a legitimate install. The RSA path
            // is the one that carries sealed credentials.
            return cert.GetRSAPublicKey() is null;
        }
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
