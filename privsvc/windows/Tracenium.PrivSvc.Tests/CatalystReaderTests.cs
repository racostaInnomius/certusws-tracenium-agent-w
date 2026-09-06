// privsvc/windows/Tracenium.PrivSvc.Tests/CatalystReaderTests.cs
//
// ADR-0015 punto 12 — el agente de Windows mira la mitad alternativa del
// SERVIDOR.
//
// ⚠️ EL CERTIFICADO DE PRUEBA SE EMITE AQUÍ, con el orden catalyst de
// verdad. Un doble que devolviera «es híbrido» no probaría nada: lo que
// puede fallar es quitar la 74 del TBS y verificar sobre lo que queda,
// y eso no se simula.

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

namespace Tracenium.PrivSvc.Tests;

public class CatalystReaderTests
{
    private static readonly MlDsaKeyPairDer CaAlt = MlDsaAlt.GenerateKeyPair();

    /// <summary>
    /// Un certificado autofirmado con las tres extensiones catalyst,
    /// respetando el orden: la 74 se firma sobre el TBS SIN ella.
    ///
    /// Se apoya en `CertificateRequest.Create`, que es el mismo truco de
    /// dos pasadas que usa HybridCsr: se emite una vez sin la 74 para
    /// tener el TBS, se firma, y se emite otra vez con ella.
    /// </summary>
    private static byte[] CertCatalyst(bool conAlt = true, bool firmaRota = false)
    {
        using var clasica = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sujeto = new X500DistinguishedName("CN=grpc.tracenium.com");
        var sujetoAlt = MlDsaAlt.GenerateKeyPair();
        var desde = DateTimeOffset.UtcNow.AddDays(-1);
        var hasta = DateTimeOffset.UtcNow.AddDays(30);

        CertificateRequest Nueva(byte[]? sig74)
        {
            var r = new CertificateRequest(sujeto, clasica, HashAlgorithmName.SHA256);
            r.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            if (!conAlt) return r;

            r.CertificateExtensions.Add(
                new X509Extension(HybridCsr.OidAltSpki, sujetoAlt.SpkiDer, critical: false));
            r.CertificateExtensions.Add(
                new X509Extension(HybridCsr.OidAltSigAlg, MlDsaAlt.AlgorithmIdentifierDer(), critical: false));
            if (sig74 is not null)
            {
                r.CertificateExtensions.Add(
                    new X509Extension(HybridCsr.OidAltSigValue, HybridCsr.BitStringDer(sig74), critical: false));
            }
            return r;
        }

        // ⚠️ SERIAL FIJO, y no es un detalle del test.
        //
        // El primer intento usó `CreateSelfSigned`, que genera un número
        // de serie ALEATORIO en cada llamada. Con eso los TBS de las dos
        // pasadas no difieren sólo en la 74 —difieren también en el
        // serial— y la firma alternativa deja de verificar. El test se
        // puso rojo y tenía razón.
        //
        // Vale la pena que quede escrito porque es la trampa que espera
        // al EMISOR de verdad (fase 2, bloque 4): quien emita un
        // certificado catalyst tiene que construir el TBS UNA vez y
        // reutilizarlo, o fijar todo lo aleatorio antes de la primera
        // pasada. En el CSR el problema no existe porque el cuerpo es
        // determinista; en un certificado, no.
        var generador = X509SignatureGenerator.CreateForECDsa(clasica);
        var serial = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        if (!conAlt)
        {
            using var soloClasico = Nueva(null).Create(sujeto, generador, desde, hasta, serial);
            return soloClasico.RawData;
        }

        // Pasada 1 — sin la 74. De aquí sale el TBS que firma ML-DSA.
        using var sinAlt74 = Nueva(null).Create(sujeto, generador, desde, hasta, serial);
        var tbs = TbsDe(sinAlt74.RawData);

        var firma = MlDsaAlt.Sign(tbs, CaAlt.Pkcs8Der);
        if (firmaRota) firma[10] ^= 0xFF;

        // Pasada 2 — con la 74 dentro, mismo serial y mismas fechas.
        using var conAlt74 = Nueva(firma).Create(sujeto, generador, desde, hasta, serial);
        return conAlt74.RawData;
    }

    private static byte[] TbsDe(byte[] certDer)
    {
        var cert = new AsnReader(certDer, AsnEncodingRules.DER).ReadSequence();
        return cert.ReadEncodedValue().ToArray();
    }

    [Fact]
    public void Un_certificado_clasico_es_Absent_que_es_toda_la_flota_hoy()
    {
        Assert.Equal(CatalystVerdict.Absent, CatalystReader.Classify(CertCatalyst(conAlt: false), CaAlt.SpkiDer));
    }

    [Fact]
    public void Uno_catalyst_firmado_por_la_alt_de_la_CA_es_Valid()
    {
        Assert.Equal(CatalystVerdict.Valid, CatalystReader.Classify(CertCatalyst(), CaAlt.SpkiDer));
    }

    [Fact]
    public void Catalyst_sin_alt_de_CA_es_Unverifiable_NO_Invalid()
    {
        // ⚠️ El estado por el que se pasa: primer servidor híbrido, bundle
        // todavía clásico porque la Issuing híbrida depende de D1. Si esto
        // dijera Invalid, el día del cambio el informe diría que el
        // servidor tiene la firma rota — y alguien lo creería.
        Assert.Equal(CatalystVerdict.Unverifiable, CatalystReader.Classify(CertCatalyst(), null));
    }

    [Fact]
    public void Una_firma_alternativa_corrompida_es_Invalid()
    {
        // Lo que da sentido a Valid. Sin esto, Valid sólo significaría
        // «trae tres extensiones».
        Assert.Equal(CatalystVerdict.Invalid,
            CatalystReader.Classify(CertCatalyst(firmaRota: true), CaAlt.SpkiDer));
    }

    [Fact]
    public void La_alt_de_OTRA_CA_es_Invalid()
    {
        // Verificar contra la clave equivocada sería peor que no
        // verificar: diría «válido» sobre un certificado que no emitimos.
        var otra = MlDsaAlt.GenerateKeyPair();
        Assert.Equal(CatalystVerdict.Invalid, CatalystReader.Classify(CertCatalyst(), otra.SpkiDer));
    }

    [Fact]
    public void Basura_no_lanza()
    {
        // Esto corre dentro de la validación del certificado del servidor,
        // en el camino de una conexión viva.
        Assert.Equal(CatalystVerdict.Absent, CatalystReader.Classify(new byte[] { 0x30, 0x02, 0x05, 0x00 }, null));
        Assert.Equal(CatalystVerdict.Absent, CatalystReader.Classify(Array.Empty<byte>(), CaAlt.SpkiDer));
    }

    [Fact]
    public void El_TBS_sin_la_74_conserva_lo_demas()
    {
        var der = CertCatalyst();
        var cuerpo = CatalystReader.TbsWithoutAltSignature(der);
        Assert.NotNull(cuerpo);

        var altSpki = CatalystReader.SubjectAltSpki(der)!;
        var firma = CatalystReader.AltSignatureValue(der)!;
        // La SPKI alternativa sigue dentro; la firma alternativa ya no.
        Assert.True(Contiene(cuerpo!, altSpki));
        Assert.False(Contiene(cuerpo!, firma));
    }

    [Fact]
    public void Un_certificado_sin_74_no_tiene_TBS_alternativo()
    {
        Assert.Null(CatalystReader.TbsWithoutAltSignature(CertCatalyst(conAlt: false)));
    }

    [Fact]
    public void La_firma_alternativa_mide_lo_que_debe()
    {
        Assert.Equal(MlDsaAlt.SignatureBytes, CatalystReader.AltSignatureValue(CertCatalyst())!.Length);
    }

    [Fact]
    public void IssuerAltSpkiFrom_recorre_el_bundle_y_tolera_basura()
    {
        // Un certificado ilegible del bundle no puede tumbar la conexión:
        // quedarse sin mitad alternativa degrada a Unverifiable, que es un
        // veredicto y no un corte.
        var bundle = new List<byte[]> { new byte[] { 0x30, 0x02 }, CertCatalyst() };
        Assert.NotNull(CatalystReader.IssuerAltSpkiFrom(bundle));
        Assert.Null(CatalystReader.IssuerAltSpkiFrom(new List<byte[]> { new byte[] { 0x30, 0x02 } }));
        Assert.Null(CatalystReader.IssuerAltSpkiFrom(new List<byte[]>()));
    }

    private static bool Contiene(byte[] heno, byte[] aguja)
    {
        if (aguja.Length == 0 || aguja.Length > heno.Length) return false;
        for (var i = 0; i <= heno.Length - aguja.Length; i++)
        {
            var igual = true;
            for (var j = 0; j < aguja.Length; j++)
            {
                if (heno[i + j] != aguja[j]) { igual = false; break; }
            }
            if (igual) return true;
        }
        return false;
    }
}
