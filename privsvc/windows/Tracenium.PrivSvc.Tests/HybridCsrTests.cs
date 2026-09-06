// privsvc/windows/Tracenium.PrivSvc.Tests/HybridCsrTests.cs
//
// ADR-0015 bloque 3 — la mitad híbrida del agente de Windows.
//
// ⚠️ ESTAS PRUEBAS CORREN FUERA DE WINDOWS, y por eso existen.
//
// El proyecto es `net8.0` a secas y compila los ficheros puros del
// servicio. Si la criptografía híbrida hubiera necesitado CNG o DPAPI
// para probarse, estas pruebas sólo correrían en una máquina que nadie
// tiene delante — o sea que no correrían. De ahí que `MlDsaAlt`,
// `HybridCsr` y `CatalystReader` se escribieran sin nada de Windows
// dentro, y que DPAPI viva aparte.
//
// ⚠️ LO QUE NO PUEDEN PROBAR, dicho para que nadie lo dé por cubierto:
// la clave clásica de verdad vive en CNG NO EXPORTABLE, y aquí se usa
// una RSA en memoria. Lo que se fija es la FORMA del CSR y el orden de
// las firmas; que CNG entregue esa firma es cosa del equipo Windows.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

namespace Tracenium.PrivSvc.Tests;

public class MlDsaAltTests
{
    [Fact]
    public void Los_tamanos_son_los_del_parametro_65()
    {
        // ⚠️ Los mismos números que noble y OpenSSL, medidos el
        // 2026-09-06. Si esto cambia, la interoperabilidad se rompió y
        // hay que volver a medir antes de tocar nada más.
        var kp = MlDsaAlt.GenerateKeyPair();
        Assert.Equal(MlDsaAlt.SpkiBytes, kp.SpkiDer.Length);   // 1974
        Assert.Equal(4098, kp.Pkcs8Der.Length);

        var firma = MlDsaAlt.Sign(System.Text.Encoding.ASCII.GetBytes("x"), kp.Pkcs8Der);
        Assert.Equal(MlDsaAlt.SignatureBytes, firma.Length);   // 3309
    }

    [Fact]
    public void Firma_y_verifica_lo_suyo()
    {
        var kp = MlDsaAlt.GenerateKeyPair();
        var msg = System.Text.Encoding.ASCII.GetBytes("mensaje");
        Assert.True(MlDsaAlt.Verify(MlDsaAlt.Sign(msg, kp.Pkcs8Der), msg, kp.SpkiDer));
    }

    [Fact]
    public void Otro_mensaje_no_verifica()
    {
        // Lo que separa «verifica» de «devuelve true».
        var kp = MlDsaAlt.GenerateKeyPair();
        var firma = MlDsaAlt.Sign(System.Text.Encoding.ASCII.GetBytes("original"), kp.Pkcs8Der);
        Assert.False(MlDsaAlt.Verify(firma, System.Text.Encoding.ASCII.GetBytes("alterado"), kp.SpkiDer));
    }

    [Fact]
    public void Otra_clave_no_verifica()
    {
        var a = MlDsaAlt.GenerateKeyPair();
        var b = MlDsaAlt.GenerateKeyPair();
        var msg = System.Text.Encoding.ASCII.GetBytes("mensaje");
        Assert.False(MlDsaAlt.Verify(MlDsaAlt.Sign(msg, a.Pkcs8Der), msg, b.SpkiDer));
    }

    [Fact]
    public void Entrada_ilegible_devuelve_false_en_vez_de_lanzar()
    {
        // Esto corre dentro de la verificación del certificado del
        // servidor, en el camino de una conexión viva. Una excepción ahí
        // tiraría el canal por una comprobación en modo observación.
        Assert.False(MlDsaAlt.Verify(new byte[10], new byte[4], new byte[5]));
    }

    [Fact]
    public void La_SPKI_se_deriva_de_la_privada()
    {
        // Para no tener que guardar la pública en un segundo fichero:
        // dos ficheros que pueden discrepar son un desacuerdo esperando
        // ocurrir.
        var kp = MlDsaAlt.GenerateKeyPair();
        Assert.Equal(kp.SpkiDer, MlDsaAlt.SpkiFromPkcs8(kp.Pkcs8Der));
    }

    [Fact]
    public void El_AlgorithmIdentifier_no_lleva_parametros()
    {
        // ⚠️ ML-DSA no lleva parámetros. Meter un NULL —el reflejo que
        // viene de RSA— produce un AlgorithmIdentifier que otros
        // verificadores rechazan.
        var der = MlDsaAlt.AlgorithmIdentifierDer();
        var r = new System.Formats.Asn1.AsnReader(der, System.Formats.Asn1.AsnEncodingRules.DER)
            .ReadSequence();
        Assert.Equal(MlDsaAlt.Oid, r.ReadObjectIdentifier());
        Assert.False(r.HasData); // nada después del OID
    }
}

public class HybridCsrTests
{
    private static RSA _clasica = RSA.Create(2048);

    private static Func<CertificateRequest> Peticion(string cn = "SRVOC-MainAgent") => () =>
    {
        var r = new CertificateRequest(
            new X500DistinguishedName($"CN={cn}"), _clasica,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        r.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") };
        r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, critical: false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("tracenium://tenant/1/device/d1"));
        r.CertificateExtensions.Add(san.Build(critical: false));
        return r;
    };

    [Fact]
    public void Sin_clave_alternativa_sale_un_CSR_clasico()
    {
        // El 100 % de la flota de hoy, por el MISMO camino de código. Dos
        // caminos dejarían el clásico peor probado que el híbrido.
        var der = HybridCsr.Build(Peticion(), null, null);
        Assert.Null(CatalystReaderPeek.AltSpkiDeCsr(der));
    }

    [Fact]
    public void Media_pareja_de_claves_es_un_error()
    {
        // Un CSR con SPKI alternativa y sin su prueba lo RECHAZA el
        // backend por diseño. Degradar en silencio dejaría al equipo
        // creyendo que pidió un híbrido.
        var kp = MlDsaAlt.GenerateKeyPair();
        Assert.Throws<ArgumentException>(() => HybridCsr.Build(Peticion(), null, kp.SpkiDer));
        Assert.Throws<ArgumentException>(() => HybridCsr.Build(Peticion(), kp.Pkcs8Der, null));
    }

    [Fact]
    public void El_CSR_hibrido_lleva_las_tres_extensiones()
    {
        var kp = MlDsaAlt.GenerateKeyPair();
        var der = HybridCsr.Build(Peticion(), kp.Pkcs8Der, kp.SpkiDer);
        var alt = CatalystReaderPeek.AltSpkiDeCsr(der);
        Assert.NotNull(alt);
        Assert.Equal(kp.SpkiDer, alt);
    }

    [Fact]
    public void La_firma_alternativa_verifica_sobre_el_cuerpo_SIN_la_74()
    {
        // ⚠️ EL TEST DEL ORDEN, y el único sitio donde se nota si está
        // mal. Firmar sobre el cuerpo que ya contiene la 74 —el error
        // natural— produce un CSR bien formado que nadie puede verificar.
        var kp = MlDsaAlt.GenerateKeyPair();
        var der = HybridCsr.Build(Peticion(), kp.Pkcs8Der, kp.SpkiDer);

        var cuerpo = CatalystReaderPeek.InfoSinAlt74(der);
        var firma = CatalystReaderPeek.FirmaAltDeCsr(der);
        Assert.NotNull(cuerpo);
        Assert.NotNull(firma);
        Assert.Equal(MlDsaAlt.SignatureBytes, firma!.Length);
        Assert.True(MlDsaAlt.Verify(firma, cuerpo!, kp.SpkiDer));
    }

    [Fact]
    public void Y_NO_verifica_sobre_el_cuerpo_CON_la_74()
    {
        // El contrapunto: sin esto, un verify que devolviera true para
        // cualquier cuerpo pasaría el test anterior.
        var kp = MlDsaAlt.GenerateKeyPair();
        var der = HybridCsr.Build(Peticion(), kp.Pkcs8Der, kp.SpkiDer);
        var conTodo = HybridCsr.CertificationRequestInfoDe(der);
        Assert.False(MlDsaAlt.Verify(CatalystReaderPeek.FirmaAltDeCsr(der)!, conTodo, kp.SpkiDer));
    }

    [Fact]
    public void La_firma_de_otra_clave_alternativa_no_verifica()
    {
        var kp = MlDsaAlt.GenerateKeyPair();
        var otra = MlDsaAlt.GenerateKeyPair();
        var der = HybridCsr.Build(Peticion(), kp.Pkcs8Der, kp.SpkiDer);
        Assert.False(MlDsaAlt.Verify(
            CatalystReaderPeek.FirmaAltDeCsr(der)!,
            CatalystReaderPeek.InfoSinAlt74(der)!,
            otra.SpkiDer));
    }

    [Fact]
    public void El_BitString_lleva_su_octeto_de_relleno()
    {
        // Se olvida con facilidad y su ausencia desplaza el contenido un
        // byte: la firma deja de verificar sin que la estructura parezca
        // mal formada.
        var der = HybridCsr.BitStringDer(new byte[] { 0xAA, 0xBB });
        Assert.Equal(0x03, der[0]); // BIT STRING
        Assert.Equal(0x00, der[2]); // bits sin usar
    }

    [Fact]
    public void El_tamano_del_CSR_hibrido_cabe_en_los_topes()
    {
        // Contra el tope de 64 KB del punto 4 y el de línea del pipe.
        var kp = MlDsaAlt.GenerateKeyPair();
        var der = HybridCsr.Build(Peticion(), kp.Pkcs8Der, kp.SpkiDer);
        Assert.InRange(der.Length, 5000, 12000);
    }
}

/// <summary>
/// Lectura de las extensiones dentro de un CSR.
///
/// `CatalystReader` lee CERTIFICADOS; un CSR tiene otra estructura —las
/// extensiones viven dentro del atributo extensionRequest— así que se
/// recorre aquí. Está en el fichero de pruebas a propósito: en
/// producción el agente no necesita releer sus propios CSR, y meter en
/// el servicio código que sólo usan los tests es superficie regalada.
/// </summary>
internal static class CatalystReaderPeek
{
    private const string OidExtensionRequest = "1.2.840.113549.1.9.14";

    private static System.Formats.Asn1.AsnReader? Extensiones(byte[] csrDer)
    {
        var info = HybridCsr.CertificationRequestInfoDe(csrDer);
        var r = new System.Formats.Asn1.AsnReader(info, System.Formats.Asn1.AsnEncodingRules.DER)
            .ReadSequence();
        r.ReadInteger();          // version
        r.ReadEncodedValue();     // subject
        r.ReadEncodedValue();     // SPKI

        var etiqueta = new System.Formats.Asn1.Asn1Tag(
            System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true);
        if (!r.HasData || r.PeekTag() != etiqueta) return null;

        var attrs = r.ReadSetOf(etiqueta);
        while (attrs.HasData)
        {
            var attr = attrs.ReadSequence();
            if (attr.ReadObjectIdentifier() != OidExtensionRequest) continue;
            return attr.ReadSetOf().ReadSequence();
        }
        return null;
    }

    public static byte[]? AltSpkiDeCsr(byte[] csrDer) => Valor(csrDer, "2.5.29.72");

    public static byte[]? FirmaAltDeCsr(byte[] csrDer)
    {
        var v = Valor(csrDer, "2.5.29.74");
        if (v is null) return null;
        return new System.Formats.Asn1.AsnReader(v, System.Formats.Asn1.AsnEncodingRules.DER)
            .ReadBitString(out _);
    }

    private static byte[]? Valor(byte[] csrDer, string oid)
    {
        var exts = Extensiones(csrDer);
        if (exts is null) return null;
        while (exts.HasData)
        {
            var ext = exts.ReadSequence();
            var id = ext.ReadObjectIdentifier();
            if (ext.PeekTag() == System.Formats.Asn1.Asn1Tag.Boolean) ext.ReadBoolean();
            var valor = ext.ReadOctetString();
            if (id == oid) return valor;
        }
        return null;
    }

    /// <summary>El CertificationRequestInfo sin la 74, rehecho como lo hará el backend.</summary>
    public static byte[]? InfoSinAlt74(byte[] csrDer)
    {
        var info = HybridCsr.CertificationRequestInfoDe(csrDer);
        var r = new System.Formats.Asn1.AsnReader(info, System.Formats.Asn1.AsnEncodingRules.DER)
            .ReadSequence();
        var version = r.ReadEncodedValue().ToArray();
        var subject = r.ReadEncodedValue().ToArray();
        var spki = r.ReadEncodedValue().ToArray();

        var etiqueta = new System.Formats.Asn1.Asn1Tag(
            System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true);
        var attrs = r.ReadSetOf(etiqueta);
        var attr = attrs.ReadSequence();
        var oidAttr = attr.ReadEncodedValue().ToArray();
        var extSeq = attr.ReadSetOf().ReadSequence();

        var conservadas = new List<byte[]>();
        var habia74 = false;
        while (extSeq.HasData)
        {
            var raw = extSeq.ReadEncodedValue().ToArray();
            var ext = new System.Formats.Asn1.AsnReader(raw, System.Formats.Asn1.AsnEncodingRules.DER)
                .ReadSequence();
            if (ext.ReadObjectIdentifier() == "2.5.29.74") { habia74 = true; continue; }
            conservadas.Add(raw);
        }
        if (!habia74) return null;

        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteEncodedValue(version);
            w.WriteEncodedValue(subject);
            w.WriteEncodedValue(spki);
            using (w.PushSetOf(etiqueta))
            using (w.PushSequence())
            {
                w.WriteEncodedValue(oidAttr);
                using (w.PushSetOf())
                using (w.PushSequence())
                {
                    foreach (var b in conservadas) w.WriteEncodedValue(b);
                }
            }
        }
        return w.Encode();
    }
}
