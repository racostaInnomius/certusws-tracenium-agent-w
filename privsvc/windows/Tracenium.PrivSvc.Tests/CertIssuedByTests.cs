// privsvc/windows/Tracenium.PrivSvc.Tests/CertIssuedByTests.cs
//
// El guard de instalación de Windows: ¿firmó una CA del bundle esta hoja?
//
// ⚠️ SU PRIMERA VERSIÓN RECHAZABA TODO (2026-09-11). Usaba X509Chain con
// CustomRootTrust, que sólo cierra en una raíz autofirmada, y el bundle que
// entrega el backend lleva las intermedias SIN la Root. Ningún Windows
// enrolaba y ninguna renovación de Windows se instalaba desde la 1.1.68.
// Nadie lo vio porque sólo se había compilado: nunca corrió contra un
// bundle con la forma real.
//
// Por eso aquí la jerarquía reproduce la de producción —Root RSA, Issuing
// G2 en EC P-384 firmando con ecdsa-with-SHA384, Issuing vieja en RSA— y el
// bundle va SIN la Root, como lo entrega el backend.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class CertIssuedByTests
{
    private static readonly DateTimeOffset Ahora = DateTimeOffset.UtcNow;

    private static readonly RSA RootKey = RSA.Create(2048);
    private static readonly ECDsa G2Key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    private static readonly RSA G1Key = RSA.Create(2048);

    private static readonly X509Certificate2 Root = CrearRoot();
    private static readonly X509Certificate2 G2 = CrearIntermedia(
        "CN=Tracenium Issuing CA G2, O=Tracenium, C=US",
        new CertificateRequest("CN=Tracenium Issuing CA G2, O=Tracenium, C=US", G2Key, HashAlgorithmName.SHA384), 2);
    private static readonly X509Certificate2 G1 = CrearIntermedia(
        "CN=Tracenium Issuing CA, OU=IssuingCA, O=Tracenium, C=US",
        new CertificateRequest("CN=Tracenium Issuing CA, OU=IssuingCA, O=Tracenium, C=US", G1Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), 3);

    /// <summary>El bundle tal como lo entrega el backend: intermedias, SIN Root.</summary>
    private static readonly X509Certificate2[] BundleReal = { G2, G1 };

    private static X509Certificate2 CrearRoot()
    {
        var req = new CertificateRequest("CN=Tracenium Root CA, OU=RootCA, O=Tracenium, C=US", RootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return req.CreateSelfSigned(Ahora.AddYears(-1), Ahora.AddYears(5));
    }

    private static X509Certificate2 CrearIntermedia(string sujeto, CertificateRequest req, byte serial)
    {
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        return req.Create(
            Root.SubjectName,
            X509SignatureGenerator.CreateForRSA(RootKey, RSASignaturePadding.Pkcs1),
            Ahora.AddYears(-1), Ahora.AddYears(4), new[] { serial });
    }

    /// <summary>Una hoja de agente, con el emisor y el firmante que se pidan.</summary>
    private static X509Certificate2 Hoja(
        X500DistinguishedName emisor,
        X509SignatureGenerator firmante,
        HashAlgorithmName hash,
        DateTimeOffset? desde = null,
        DateTimeOffset? hasta = null)
    {
        using var clave = RSA.Create(2048);
        var req = new CertificateRequest("CN=tracenium-agent-e9bd0014", clave, hash, RSASignaturePadding.Pkcs1);
        return req.Create(emisor, firmante,
            desde ?? Ahora.AddMinutes(-1), hasta ?? Ahora.AddDays(365),
            RandomNumberGenerator.GetBytes(16));
    }

    private static X509Certificate2 HojaDeLaG2(DateTimeOffset? desde = null, DateTimeOffset? hasta = null) =>
        Hoja(G2.SubjectName, X509SignatureGenerator.CreateForECDsa(G2Key), HashAlgorithmName.SHA384, desde, hasta);

    [Fact]
    public void Una_hoja_de_la_G2_se_acepta_con_el_bundle_REAL_sin_Root()
    {
        // ⭐ La regresión del 2026-09-11. Con X509Chain + CustomRootTrust
        // esto daba false, y era el caso normal de TODO enrolamiento.
        Assert.Null(CertIssuedBy.WhyNotUsable(HojaDeLaG2(), BundleReal, DateTime.UtcNow));
    }

    [Fact]
    public void Con_la_Root_en_la_lista_tambien_se_acepta()
    {
        Assert.Null(CertIssuedBy.WhyNotUsable(HojaDeLaG2(), new[] { G2, G1, Root }, DateTime.UtcNow));
    }

    [Fact]
    public void Una_hoja_de_la_Issuing_vieja_se_acepta_durante_la_rotacion()
    {
        // El bundle lleva las DOS a propósito: un equipo tiene que poder
        // instalar lo que emita cualquiera de ellas mientras dura el corte.
        var hoja = Hoja(G1.SubjectName, X509SignatureGenerator.CreateForRSA(G1Key, RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256);
        Assert.Null(CertIssuedBy.WhyNotUsable(hoja, BundleReal, DateTime.UtcNow));
    }

    [Fact]
    public void RECHAZA_el_descuadre_de_campo_emisor_G2_firmado_con_la_clave_de_la_G1()
    {
        // ⚠️ El fallo del 2026-09-10 que este guard existe para parar: la
        // hoja DECLARA la G2 y viene firmada con la RSA de la G1. El DN
        // coincide; la firma no.
        var hoja = Hoja(G2.SubjectName, X509SignatureGenerator.CreateForRSA(G1Key, RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256);

        // ⚠️ Con el bundle REAL, que lleva también la G1: la firma SÍ
        // verifica contra ella. La primera versión la daba por buena por eso;
        // lo que importa es si la firmó la CA que NOMBRA.
        var motivo = CertIssuedBy.WhyNotUsable(hoja, BundleReal, DateTime.UtcNow);

        Assert.NotNull(motivo);
        Assert.StartsWith("signature does not verify against the issuer it names", motivo);
    }

    [Fact]
    public void RECHAZA_una_hoja_firmada_por_una_CA_ajena()
    {
        using var otra = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var hoja = Hoja(new X500DistinguishedName("CN=Otra CA"), X509SignatureGenerator.CreateForECDsa(otra), HashAlgorithmName.SHA256);

        var motivo = CertIssuedBy.WhyNotUsable(hoja, BundleReal, DateTime.UtcNow);

        Assert.NotNull(motivo);
        Assert.StartsWith("no delivered CA is the issuer", motivo);
    }

    [Fact]
    public void RECHAZA_una_hoja_caducada()
    {
        var hoja = HojaDeLaG2(Ahora.AddDays(-30), Ahora.AddHours(-1));

        var motivo = CertIssuedBy.WhyNotUsable(hoja, BundleReal, DateTime.UtcNow);

        Assert.NotNull(motivo);
        Assert.StartsWith("expired", motivo);
    }

    [Fact]
    public void Acepta_un_desfase_de_reloj_razonable()
    {
        // El emisor adelantado dos minutos respecto al equipo: normal.
        Assert.Null(CertIssuedBy.WhyNotUsable(HojaDeLaG2(Ahora.AddMinutes(2)), BundleReal, DateTime.UtcNow));
    }

    [Fact]
    public void RECHAZA_una_hoja_que_aun_no_es_valida()
    {
        var motivo = CertIssuedBy.WhyNotUsable(HojaDeLaG2(Ahora.AddMinutes(30)), BundleReal, DateTime.UtcNow);

        Assert.NotNull(motivo);
        Assert.StartsWith("not yet valid", motivo);
    }

    [Fact]
    public void El_motivo_cabe_al_principio_del_mensaje()
    {
        // El log IPC corta a 200 caracteres, y la primera versión puso el
        // motivo al final: el día que falló no se veía.
        var hoja = Hoja(G2.SubjectName, X509SignatureGenerator.CreateForRSA(G1Key, RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256);
        var mensaje = $"Client certificate not usable: {CertIssuedBy.WhyNotUsable(hoja, BundleReal, DateTime.UtcNow)}";

        Assert.Contains("signature does not verify against the issuer it names", mensaje[..Math.Min(200, mensaje.Length)]);
    }
}
