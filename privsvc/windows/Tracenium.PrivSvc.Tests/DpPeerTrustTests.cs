// privsvc/windows/Tracenium.PrivSvc.Tests/DpPeerTrustTests.cs
//
// ¿A quién sirve un Distribution Point?
//
// 🔴 EL CASO DE CAMPO (15-sep): los DP de T111 están en la Issuing vieja y
// MSIG-VEEAM-PC rotó a la G2. El DP sólo aceptaba SU CA, así que rechazaba al
// peer y el update caía a Azure, que esa VLAN no alcanza. Aquí la jerarquía
// reproduce la de producción: Root RSA, G2 en P-384, Issuing vieja en RSA.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class DpPeerTrustTests
{
    private static readonly DateTimeOffset Ahora = DateTimeOffset.UtcNow;

    private static readonly RSA RootKey = RSA.Create(2048);
    private static readonly ECDsa G2Key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    private static readonly RSA G1Key = RSA.Create(2048);

    private static readonly X509Certificate2 Root = CrearRoot("CN=Tracenium Root CA, OU=RootCA, O=Tracenium, C=US", RootKey);
    private static readonly X509Certificate2 G2 = CrearIntermedia(Root, RootKey,
        new CertificateRequest("CN=Tracenium Issuing CA G2, O=Tracenium, C=US", G2Key, HashAlgorithmName.SHA384), 2);
    private static readonly X509Certificate2 G1 = CrearIntermedia(Root, RootKey,
        new CertificateRequest("CN=Tracenium Issuing CA, OU=IssuingCA, O=Tracenium, C=US", G1Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), 3);

    private static X509Certificate2 CrearRoot(string sujeto, RSA clave)
    {
        var req = new CertificateRequest(sujeto, clave, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return req.CreateSelfSigned(Ahora.AddYears(-1), Ahora.AddYears(5));
    }

    private static X509Certificate2 CrearIntermedia(X509Certificate2 raiz, RSA claveRaiz, CertificateRequest req, byte serial)
    {
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        return req.Create(raiz.SubjectName, X509SignatureGenerator.CreateForRSA(claveRaiz, RSASignaturePadding.Pkcs1),
            Ahora.AddYears(-1), Ahora.AddYears(4), new[] { serial });
    }

    private static X509Certificate2 HojaDe(X509Certificate2 ca, X509SignatureGenerator firmante, HashAlgorithmName hash)
    {
        using var clave = RSA.Create(2048);
        var req = new CertificateRequest("CN=tracenium-agent-18f2240b", clave, hash, RSASignaturePadding.Pkcs1);
        return req.Create(ca.SubjectName, firmante, Ahora.AddMinutes(-1), Ahora.AddDays(365), RandomNumberGenerator.GetBytes(16));
    }

    private static readonly X509Certificate2 PeerG2 =
        HojaDe(G2, X509SignatureGenerator.CreateForECDsa(G2Key), HashAlgorithmName.SHA384);
    private static readonly X509Certificate2 PeerG1 =
        HojaDe(G1, X509SignatureGenerator.CreateForRSA(G1Key, RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256);

    private static string Pem(params X509Certificate2[] certs) =>
        string.Concat(certs.Select(c => c.ExportCertificatePem() + "\n"));

    /// <summary>Lo que acepta un DP de la Issuing vieja tras recibir el bundle del backend.</summary>
    private static List<X509Certificate2> AceptadasPorDpViejoConBundle(string bundlePem) =>
        DpPeerTrust.Union(new[] { G1 },
            DpPeerTrust.TrustedDeliveredCas(DpPeerTrust.ParsePemBundle(bundlePem), new[] { Root }, DateTime.UtcNow));

    [Fact]
    public void Sin_bundle_un_DP_de_la_vieja_rechaza_al_peer_de_la_G2__el_fallo_de_campo()
    {
        var motivo = DpPeerTrust.WhyPeerRejected(PeerG2, new[] { G1 }, DateTime.UtcNow);
        Assert.NotNull(motivo);
        Assert.StartsWith("no delivered CA is the issuer", motivo);
    }

    [Fact]
    public void Con_el_bundle_REAL_del_backend_acepta_a_la_G2_y_sigue_aceptando_a_la_vieja()
    {
        // ⭐ El arreglo. El bundle va como lo sirve el backend: G2 + vieja, SIN Root.
        var aceptadas = AceptadasPorDpViejoConBundle(Pem(G2, G1));

        Assert.Equal(2, aceptadas.Count);
        Assert.Null(DpPeerTrust.WhyPeerRejected(PeerG2, aceptadas, DateTime.UtcNow));
        Assert.Null(DpPeerTrust.WhyPeerRejected(PeerG1, aceptadas, DateTime.UtcNow));
    }

    [Fact]
    public void Un_DP_que_ya_rotó_a_la_G2_sigue_sirviendo_a_los_peers_de_la_vieja()
    {
        // El otro sentido de la rotación: si los DP rotan primero.
        var aceptadas = DpPeerTrust.Union(new[] { G2 },
            DpPeerTrust.TrustedDeliveredCas(DpPeerTrust.ParsePemBundle(Pem(G2, G1)), new[] { Root }, DateTime.UtcNow));
        Assert.Null(DpPeerTrust.WhyPeerRejected(PeerG1, aceptadas, DateTime.UtcNow));
    }

    [Fact]
    public void RECHAZA_una_CA_entregada_que_no_firmó_la_raíz_del_DP()
    {
        // El canal de entrega amplía el conjunto dentro de la jerarquía; no
        // puede meter una CA ajena aunque se llame igual.
        using var otraRaizKey = RSA.Create(2048);
        var otraRaiz = CrearRoot("CN=Tracenium Root CA, OU=RootCA, O=Tracenium, C=US", otraRaizKey);
        using var falsaKey = RSA.Create(2048);
        var falsa = CrearIntermedia(otraRaiz, otraRaizKey,
            new CertificateRequest("CN=Tracenium Issuing CA G2, O=Tracenium, C=US", falsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), 9);

        var confiables = DpPeerTrust.TrustedDeliveredCas(new[] { falsa }, new[] { Root }, DateTime.UtcNow);

        Assert.Empty(confiables);
        var peerFalso = HojaDe(falsa, X509SignatureGenerator.CreateForRSA(falsaKey, RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256);
        Assert.NotNull(DpPeerTrust.WhyPeerRejected(peerFalso, DpPeerTrust.Union(new[] { G1 }, confiables), DateTime.UtcNow));
    }

    [Fact]
    public void RECHAZA_entregar_una_hoja_o_una_raíz_como_si_fueran_CA_emisora()
    {
        var confiables = DpPeerTrust.TrustedDeliveredCas(new[] { PeerG1, Root }, new[] { Root }, DateTime.UtcNow);
        Assert.Empty(confiables);
    }

    [Fact]
    public void Sin_anclas_no_se_acepta_nada_de_lo_entregado()
    {
        Assert.Empty(DpPeerTrust.TrustedDeliveredCas(new[] { G2 }, Array.Empty<X509Certificate2>(), DateTime.UtcNow));
    }

    [Fact]
    public void Sin_ninguna_CA_aceptada_se_rechaza_a_todos()
    {
        Assert.Equal("no accepted issuing CA on this DP",
            DpPeerTrust.WhyPeerRejected(PeerG1, Array.Empty<X509Certificate2>(), DateTime.UtcNow));
    }

    [Fact]
    public void Un_peer_que_presenta_una_CA_no_entra()
    {
        var motivo = DpPeerTrust.WhyPeerRejected(G2, new[] { G1, G2, Root }, DateTime.UtcNow);
        Assert.NotNull(motivo);
        Assert.StartsWith("peer presented a CA certificate", motivo);
    }

    [Fact]
    public void El_parser_ignora_basura_y_bloques_rotos_y_respeta_el_tope()
    {
        var pem = "basura\n" + Pem(G2) + "-----BEGIN CERTIFICATE-----\nno-es-base64\n-----END CERTIFICATE-----\n" + Pem(G1);
        Assert.Equal(2, DpPeerTrust.ParsePemBundle(pem).Count);
        Assert.Empty(DpPeerTrust.ParsePemBundle(new string('A', DpPeerTrust.MaxBundleChars + 1)));
        Assert.Empty(DpPeerTrust.ParsePemBundle(null));
    }

    [Fact]
    public void La_unión_no_repite_por_huella()
    {
        Assert.Equal(2, DpPeerTrust.Union(new[] { G1, G2 }, new[] { G2, G1 }).Count);
    }
}
