// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoGatewayKey.cs
//
// ADR-0013 — la clave con la que se abre la credencial de vCenter.
//
// ── Por qué existe ─────────────────────────────────────────────────
//
// ADR-0001 decidió abrir el sobre sellado con la clave privada de
// ENROLAMIENTO. Esa clave no puede descifrar: CryptoCsr la crea con
// `CngKeyUsages.Signing` y pide una KeyUsage crítica de
// DigitalSignature, y CNG hace cumplir ambas cosas. La entrega de
// credenciales de vCenter no ha funcionado nunca en ningún Windows.
//
// Se escondió porque la autenticación TLS de cliente solo FIRMA, así que
// el canal gRPC, el bridge y el listener del distribution point
// funcionan impecables sobre la misma clave que no abre un sobre.
//
// ── Por qué al asignar el rol, y no al enrolar ─────────────────────
//
// Provisionar esto en el enrolamiento le daría a cada equipo de cada
// tenant una clave capaz de descifrar, para servir como mucho a un
// equipo por tenant — y a los tenants sin vCenter, a ninguno, nunca.
//
// Y eso no es solo despilfarro: una clave capaz de descifrar es
// precisamente lo que puede abrir datos sellados. Hoy no existe ninguna
// en la flota (las cuatro rutas de creación del servicio son
// solo-firma). El invariante merece conservarse donde no hace falta
// romperlo, así que la clave nace con el rol de gateway y muere con él.
//
// ── Cómo se conecta con el resto ───────────────────────────────────
//
// CredentialStore NO necesita cambios. Busca el certificado por la
// huella que viaja DENTRO del sobre, no por un nombre derivado del
// device: en cuanto el navegador sella contra este certificado, la
// búsqueda existente lo encuentra sola. Esa decisión de ADR-0001 —
// mirar por huella— es la que hace barato este arreglo.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoGatewayKey
{
    private const int RsaKeyBits = 2048;

    /// <summary>
    /// Alta idempotente: la sincronización de políticas la llama cada vez
    /// que ve `policy.gateway.vcenter`, no solo la primera.
    ///
    /// Devuelve siempre lo mismo para un equipo dado mientras el rol siga
    /// puesto — si generase una clave nueva en cada llamada, invalidaría
    /// la credencial ya sellada en cada sincronización.
    /// </summary>
    public static Task<PrivSvcResponse> HandleEnsure(PrivSvcRequest req)
    {
        try
        {
            var deviceId = DeviceIdOf(req);
            if (string.IsNullOrWhiteSpace(deviceId))
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "deviceId required"));

            var keyName = CryptoKeyNames.GatewayEncryptionKeyName(deviceId);

            // Reutilizar exige las DOS mitades. Una clave sin su
            // certificado no se puede publicar, y un certificado cuya
            // clave desapareció abre exactamente nada: en ambos casos hay
            // que rehacer el par, no devolver la mitad que quedó.
            var existing = FindGatewayCert(deviceId);
            if (existing is not null && CngKey.Exists(
                    keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
            {
                using (existing)
                    return Task.FromResult(PrivSvcResponse.Success(req.Id, Describe(existing)));
            }

            // Cualquier resto de un intento a medias se retira antes de
            // volver a crear: dos certificados con el mismo asunto y
            // claves distintas dejarían la búsqueda por huella eligiendo
            // en función del orden del almacén.
            RemoveGatewayCerts(deviceId);
            DeleteKey(keyName);

            using var cert = CreateKeyAndSelfSignedCert(deviceId, keyName);
            InstallInMyStore(cert);

            return Task.FromResult(PrivSvcResponse.Success(req.Id, Describe(cert)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "gateway_key_error", ex.Message));
        }
    }

    /// <summary>
    /// Baja: se retira el rol de gateway, se va la capacidad de
    /// descifrar. Idempotente — que ya no esté es el estado deseado, no
    /// un error que reintentar para siempre.
    /// </summary>
    public static Task<PrivSvcResponse> HandleDestroy(PrivSvcRequest req)
    {
        try
        {
            var deviceId = DeviceIdOf(req);
            if (string.IsNullOrWhiteSpace(deviceId))
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "deviceId required"));

            var removed = RemoveGatewayCerts(deviceId);
            var deleted = DeleteKey(CryptoKeyNames.GatewayEncryptionKeyName(deviceId));

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { ok = true, removed, deleted }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "gateway_key_error", ex.Message));
        }
    }

    // ── Construcción ────────────────────────────────────────────────

    /// <summary>
    /// Clave no exportable + certificado autofirmado que la envuelve.
    ///
    /// ⚠️ La clave lleva `Signing` ADEMÁS de `Decryption`, y no por
    /// descuido: `CreateSelfSigned` tiene que FIRMAR el certificado con
    /// la propia clave que certifica. Sin ese permiso la creación falla.
    ///
    /// Esa firma es un artefacto de construcción y nada más — este
    /// certificado no autentica a nadie, no cuelga de la CA, y nadie
    /// construye una cadena con él. La identidad mTLS del equipo sigue
    /// viviendo en otra clave, intacta. Por eso la extensión KeyUsage
    /// declara únicamente lo que este material existe para hacer:
    /// KeyEncipherment.
    /// </summary>
    private static X509Certificate2 CreateKeyAndSelfSignedCert(string deviceId, string keyName)
    {
        var creationParams = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            // Una clave que no se puede extraer convierte una huérfana en
            // un hueco desperdiciado y no en una fuga.
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey
        };
        creationParams.Parameters.Add(
            new CngProperty("Length", BitConverter.GetBytes(RsaKeyBits), CngPropertyOptions.None));

        using var rsa = new RSACng(CngKey.Create(CngAlgorithm.Rsa, keyName, creationParams));

        var request = new CertificateRequest(
            new X500DistinguishedName(SubjectOf(deviceId)),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));

        var now = DateTimeOffset.UtcNow;
        // Un margen hacia atrás para que un reloj adelantado en el
        // navegador no vea "todavía no válido" el mismo minuto en que se
        // creó.
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(5));
    }

    private static void InstallInMyStore(X509Certificate2 cert)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
    }

    // ── Consulta y limpieza ─────────────────────────────────────────

    /// <summary>El certificado de gateway de este equipo, o null.</summary>
    private static X509Certificate2? FindGatewayCert(string deviceId)
    {
        var subject = SubjectOf(deviceId);
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        foreach (var cert in store.Certificates)
        {
            // Solo sirve el que conserva su clave: uno sin ella no puede
            // abrir nada, y publicarlo sería prometer algo que no se
            // cumple.
            if (SubjectMatches(cert, subject) && cert.HasPrivateKey)
                return cert;
        }
        return null;
    }

    private static int RemoveGatewayCerts(string deviceId)
    {
        var subject = SubjectOf(deviceId);
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);

        var doomed = store.Certificates.Where(c => SubjectMatches(c, subject)).ToList();
        foreach (var cert in doomed)
        {
            try { store.Remove(cert); } catch { /* otra sesión se adelantó */ }
        }
        return doomed.Count;
    }

    private static bool DeleteKey(string keyName)
    {
        try
        {
            if (!CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
                return false;
            using var key = CngKey.Open(
                keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);
            key.Delete();
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ── Ayudas ──────────────────────────────────────────────────────

    private static object Describe(X509Certificate2 cert) => new
    {
        certPem = ToPem(cert),
        // Minúsculas y sin separadores: es la forma que el sobre usa como
        // AAD y con la que CredentialStore busca. Divergir aquí rompería
        // la autenticación del GCM sin decir por qué.
        fingerprintSha256 = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256)).ToLowerInvariant(),
        notAfter = cert.NotAfter.ToUniversalTime().ToString("o")
    };

    private static string ToPem(X509Certificate2 cert) =>
        new string(PemEncoding.Write("CERTIFICATE", cert.RawData));

    /// <summary>
    /// El asunto identifica al material sin ambigüedad y sin depender del
    /// nombre del contenedor CNG, que no viaja dentro del certificado.
    /// </summary>
    private static string SubjectOf(string deviceId) =>
        $"CN=Tracenium Gateway Credential Key,OU={EscapeDn(deviceId)}";

    private static bool SubjectMatches(X509Certificate2 cert, string subject) =>
        string.Equals(cert.Subject, subject, StringComparison.OrdinalIgnoreCase)
        // X500DistinguishedName normaliza el espaciado al construirlo, así
        // que comparar la cadena cruda deja fuera certificados propios
        // según cómo los devuelva el almacén.
        || string.Equals(
            cert.SubjectName.Format(false),
            new X500DistinguishedName(subject).Format(false),
            StringComparison.OrdinalIgnoreCase);

    /// <summary>El deviceId llega del llamante y termina dentro de un DN.</summary>
    private static string EscapeDn(string value) =>
        value.Replace("\\", "\\\\")
             .Replace(",", "\\,")
             .Replace("+", "\\+")
             .Replace("\"", "\\\"")
             .Replace("<", "\\<")
             .Replace(">", "\\>")
             .Replace(";", "\\;")
             .Replace("=", "\\=");

    private static string? DeviceIdOf(PrivSvcRequest req)
    {
        var p = req.Params;
        if (p is not null && p.TryGetValue("deviceId", out var raw) && raw is not null)
        {
            var s = raw is System.Text.Json.JsonElement je
                ? (je.ValueKind == System.Text.Json.JsonValueKind.String ? je.GetString() : je.ToString())
                : raw.ToString();
            if (!string.IsNullOrWhiteSpace(s)) return s;
        }
        return req.Meta?.DeviceId;
    }
}
