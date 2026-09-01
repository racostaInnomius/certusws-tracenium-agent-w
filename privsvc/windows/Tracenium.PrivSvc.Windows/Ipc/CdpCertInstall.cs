// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpCertInstall.cs
//
// ADR-0011 FASE 3 — `cdp.cert.install`.
//
// Gemelo de `privsvc/macos/src/cdp-cert-install.ts` y de
// `privsvc/linux/src/cdp-cert-install.ts`. Es el momento en el que
// CdpWriteGuard deja de estar sin cablear:
//
//   decision 1 · allowlist de stores {My, WebHosting}, que EXCLUYE Root
//                y AuthRoot
//   decision 2 · solo se instala lo que YA encadena a un ancla presente,
//                validado contra el trust store LOCAL — un backend
//                comprometido afirmaria que la cadena es buena
//
// ⚠️ NO se reutiliza `CryptoCertInstall`. Ese instala la identidad del
// PROPIO agente y escribe en Root y CertificateAuthority, que es
// exactamente lo que la decision 1 saca de la mesa. Es fontaneria de
// enrolamiento, no un instalador parametrizable — lo dice la correccion
// medida de ADR-0004.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpCertInstall
{
    /// <summary>
    /// Tope de certificados por peticion.
    ///
    /// ⚠️ El tope va tambien AQUI, no solo en el control plane. Un tope
    /// que solo vive en el backend no protege de un backend
    /// comprometido, que es exactamente el adversario que este ADR
    /// modela. El del control plane existe para dar un error util al
    /// operador; este existe para que el limite sea real.
    /// </summary>
    public const int MaxCertsPorJob = 10;

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        var p = req.Params ?? new Dictionary<string, object>();
        var keyId = GetString(p, "keyId") ?? "";

        if (!CdpKeys.IsValidKeyId(keyId))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "keyId invalido"));

        string keyName;
        try
        {
            keyName = CdpKeys.CdpKeyName(keyId);
            CdpKeys.AssertNotEnrollmentKey(keyName, GetString(p, "deviceId") ?? req.Meta?.DeviceId);
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", ex.Message));
        }

        var certPem = GetString(p, "certPem") ?? "";
        if (!certPem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "certPem requerido"));

        var chainPems = GetStringList(p, "chainPems")
            .Where(c => c.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
            .ToList();

        if (1 + chainPems.Count > MaxCertsPorJob)
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "too_many_certs",
                $"{1 + chainPems.Count} certificados en una peticion; el tope es {MaxCertsPorJob}"));

        // ── Guard 1: el destino ────────────────────────────────────
        //
        // `My` por defecto: es donde vive la identidad de una maquina o
        // un servicio. Root y AuthRoot no estan en la allowlist ni lo
        // estaran por esta via — plantar un ancla es la amenaza que
        // ADR-0011 existe para gobernar.
        var store = GetString(p, "destination") ?? "My";
        if (!CdpWriteGuard.IsWritableStore(store))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "destination_not_writable",
                $"destino no permitido: {store} (solo My o WebHosting; nunca anclas)"));

        X509Certificate2 leaf;
        try
        {
            leaf = X509Certificate2.CreateFromPem(certPem);
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request",
                $"el certificado no parsea: {ex.Message}"));
        }

        try
        {
            // ── Guard 2: la cadena, contra el trust store LOCAL ────
            //
            // Las intermedias se pasan como certificados extra: sin
            // ellas este gate rechazaria TODO, incluido lo legitimo.
            var extra = new X509Certificate2Collection();
            foreach (var pem in chainPems)
            {
                try { extra.Add(X509Certificate2.CreateFromPem(pem)); }
                catch { /* una intermedia ilegible no vale, y la cadena lo dira */ }
            }

            var veredicto = CdpWriteGuard.ChainsToInstalledAnchor(leaf, extra);
            if (!veredicto.Trusted)
            {
                Console.WriteLine($"[PrivSvc][CDP] install rechazado por cadena: {veredicto.Reason}");
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "chain_not_trusted", veredicto.Reason));
            }

            // ── Atar el certificado a la clave que ya existe ────────
            //
            // El par lo formo `cdp.csr.generate` y la clave NO es
            // exportable, asi que aqui no se importa material: se abre
            // el contenedor CNG por nombre y se asocia. Si el
            // certificado no corresponde a esa clave,
            // `CopyWithPrivateKey` lanza — que es el rechazo correcto y
            // no una instalacion que «funciona» sin servir para nada.
            if (!CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider,
                               CngKeyOpenOptions.MachineKey))
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "key_not_found",
                    $"no hay clave para keyId {keyId}"));
            }

            using var cngKey = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider,
                                           CngKeyOpenOptions.MachineKey);
            X509Certificate2 conClave;
            try
            {
                using var rsa = new RSACng(cngKey);
                conClave = leaf.CopyWithPrivateKey(rsa);
            }
            catch (Exception ex)
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "cert_key_mismatch",
                    $"el certificado no corresponde a la clave {keyId}: {ex.Message}"));
            }

            using (var st = new X509Store(store, StoreLocation.LocalMachine))
            {
                st.Open(OpenFlags.ReadWrite);
                st.Add(conClave);
            }

            CdpKeys.MarkCertInstalled(keyId);

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                keyId,
                installed = true,
                destination = store,
                subject = conClave.Subject,
                thumbprint = conClave.Thumbprint,
                sha256 = Convert.ToHexString(SHA256.HashData(conClave.RawData)).ToLowerInvariant(),
                chainReason = veredicto.Reason
            }));
        }
        catch (Exception ex)
        {
            // ⚠️ NO se destruye la clave. La decision 9.c enumera las
            // salidas terminales —fallo de FIRMA, timeout, cancelacion,
            // aprobacion denegada o caducada— y esta no es una: para
            // cuando llegamos aqui la CA YA firmo, asi que clave y
            // certificado son un par. Destruirla tiraria un certificado
            // emitido y dejaria el reintento imposible.
            //
            // Y hay una propiedad util en dejarla: mientras no se
            // instale sigue apareciendo como huerfana en `cdp.key.list`
            // (decision 9.d). La lista de huerfanas ES la cola de
            // reintentos.
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "cert_install_failed", ex.Message));
        }
        finally
        {
            leaf.Dispose();
        }
    }

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return null;
        if (val is string s) return s;
        if (val is JsonElement je)
            return je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
        return val.ToString();
    }

    private static List<string> GetStringList(Dictionary<string, object> p, string key)
    {
        var outp = new List<string>();
        if (!p.TryGetValue(key, out var val) || val == null) return outp;
        if (val is JsonElement je && je.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in je.EnumerateArray())
            {
                var s = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                if (!string.IsNullOrWhiteSpace(s)) outp.Add(s!);
            }
            return outp;
        }
        if (val is IEnumerable<object> lista)
            foreach (var item in lista)
            {
                var s = item?.ToString();
                if (!string.IsNullOrWhiteSpace(s)) outp.Add(s!);
            }
        return outp;
    }
}
