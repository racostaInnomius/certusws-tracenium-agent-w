// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CertIssuedBy.cs
//
// ¿Firmó alguna CA del bundle a esta hoja? Verificación DIRECTA de la firma.
//
// ⚠️ LA PRIMERA VERSIÓN DEL GUARD DE INSTALACIÓN ROMPIÓ WINDOWS ENTERO
// (2026-09-11). Usaba `X509Chain` con `CustomRootTrust` y metía el bundle
// entregado como anclas de confianza. Ese modo sólo cierra la cadena en una
// RAÍZ AUTOFIRMADA, y el bundle que entrega el backend lleva las dos
// intermedias (G2 y la Issuing vieja) SIN la Root. Resultado: `Build`
// devolvía false para CUALQUIER certificado, bueno o malo. Ningún Windows
// podía enrolarse y ninguna renovación de Windows se instalaba desde la
// 1.1.68. Falló de forma segura —el equipo conserva el certificado que
// tenía— pero falló, y sólo se vio al instalar una VM nueva.
//
// macOS y Linux no lo sufrieron porque allí el guard verifica la firma de
// la hoja contra la clave pública de cada CA del bundle, sin motor de
// cadenas. Aquí se hace lo mismo, que además es lo que se quería medir:
// «¿firmó una de ESTAS CAs este certificado?», no «¿confía el sistema en
// la cadena?». Y no depende de cómo construya cadenas cada plataforma, así
// que un test en macOS prueba lo mismo que corre en Windows.
//
// Algoritmos: los tres que produce el emisor del backend
// (sha256WithRSAEncryption, ecdsa-with-SHA256, ecdsa-with-SHA384) más sus
// hermanos SHA-512. Cualquier otro se rechaza: mejor no instalar que
// instalar sin haber podido comprobar la firma.

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CertIssuedBy
{
    /// <summary>
    /// Holgura para el desfase de reloj entre el equipo y el emisor. Un
    /// certificado recién emitido con notBefore unos segundos en el futuro
    /// es normal; rechazarlo sería el mismo desastre por el otro lado. La
    /// misma que macOS y Linux.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>¿Firmó <paramref name="ca"/> a <paramref name="leaf"/>?</summary>
    public static bool SignedBy(X509Certificate2 leaf, X509Certificate2 ca)
    {
        try
        {
            var certificado = new AsnReader(leaf.RawData, AsnEncodingRules.DER).ReadSequence();
            var tbs = certificado.ReadEncodedValue().ToArray();
            var algoritmo = certificado.ReadSequence();
            var oid = algoritmo.ReadObjectIdentifier();
            var firma = certificado.ReadBitString(out _);

            HashAlgorithmName hash;
            bool rsa;
            switch (oid)
            {
                case "1.2.840.113549.1.1.11": hash = HashAlgorithmName.SHA256; rsa = true; break;
                case "1.2.840.113549.1.1.12": hash = HashAlgorithmName.SHA384; rsa = true; break;
                case "1.2.840.113549.1.1.13": hash = HashAlgorithmName.SHA512; rsa = true; break;
                case "1.2.840.10045.4.3.2": hash = HashAlgorithmName.SHA256; rsa = false; break;
                case "1.2.840.10045.4.3.3": hash = HashAlgorithmName.SHA384; rsa = false; break;
                case "1.2.840.10045.4.3.4": hash = HashAlgorithmName.SHA512; rsa = false; break;
                default: return false;
            }

            if (rsa)
            {
                using var clave = ca.GetRSAPublicKey();
                return clave != null && clave.VerifyData(tbs, firma, hash, RSASignaturePadding.Pkcs1);
            }

            using var ec = ca.GetECDsaPublicKey();
            return ec != null && ec.VerifyData(tbs, firma, hash, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch
        {
            // Una CA con otra clase de clave, o un DER que no se deja leer:
            // simplemente no fue ésta la que firmó.
            return false;
        }
    }

    /// <summary>
    /// null si la hoja es instalable; si no, el MOTIVO, escrito para que
    /// quepa al principio del mensaje: el log IPC corta a 200 caracteres, y
    /// la primera versión puso el motivo al final — el día que falló, no se
    /// veía.
    /// </summary>
    public static string? WhyNotUsable(
        X509Certificate2 leaf,
        IReadOnlyCollection<X509Certificate2> cas,
        DateTime utcNow)
    {
        var desde = leaf.NotBefore.ToUniversalTime();
        var hasta = leaf.NotAfter.ToUniversalTime();

        if (utcNow + ClockSkew < desde)
            return $"not yet valid (notBefore={desde:o}, now={utcNow:o})";

        if (utcNow - ClockSkew > hasta)
            return $"expired (notAfter={hasta:o}, now={utcNow:o})";

        // ⚠️ SÓLO CUENTAN LAS CAs CON EL NOMBRE QUE LA HOJA DECLARA.
        //
        // La primera versión aceptaba la hoja si la firmaba CUALQUIER CA del
        // bundle, y durante la rotación el bundle trae la G2 Y la Issuing
        // vieja. El certificado del 2026-09-10 —declaraba la G2 y lo firmó la
        // clave de la vieja— pasaba: su firma verifica contra la vieja, que
        // está ahí. El TLS lo habría rechazado igual, porque el verificador
        // busca al emisor por el NOMBRE que declara, no por quién firmó. O
        // sea que el guard no paraba justo el caso para el que existe. Lo
        // destapó un test con el bundle de verdad; el anterior sólo metía la
        // G2.
        var lista = string.Join(" | ", cas.Select(c => c.Subject));
        var declaradas = cas
            .Where(ca => ca.SubjectName.RawData.AsSpan().SequenceEqual(leaf.IssuerName.RawData))
            .ToList();

        if (declaradas.Count == 0)
            return $"no delivered CA is the issuer the certificate names; issuer='{leaf.Issuer}' cas=[{lista}]";

        if (declaradas.Any(ca => SignedBy(leaf, ca)))
            return null;

        return $"signature does not verify against the issuer it names (named one CA, signed by another); " +
               $"issuer='{leaf.Issuer}' cas=[{lista}]";
    }
}
