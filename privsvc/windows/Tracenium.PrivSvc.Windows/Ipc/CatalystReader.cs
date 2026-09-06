// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CatalystReader.cs
//
// ADR-0015 punto 12 — leer y VERIFICAR la mitad alternativa del
// certificado del SERVIDOR, desde el agente de Windows.
//
// ── QUÉ PROTEGE, QUE NO ES LO MISMO QUE EN EL BACKEND ─────────────────
//
// El backend mira el certificado del agente. Esto mira el del servidor.
// Lo que cubre esta dirección es la SUPLANTACIÓN DEL CONTROL PLANE:
// cualquiera con la clave de la Issuing —que estuvo publicada dentro de
// una imagen de Docker Hub— puede presentar un certificado que la CA
// avala. La mitad post-cuántica no estaba en esa filtración.
//
// SChannel valida la mitad clásica y pasa de largo por las tres
// extensiones catalyst, que son no críticas. Ninguna pila TLS las
// verifica —ni OpenSSL, que sí sabe NOMBRARLAS, ni Node, ni SChannel—
// así que sin este fichero la mitad alternativa del servidor no la
// comprueba nadie.
//
// ── PURO A PROPÓSITO ──────────────────────────────────────────────────
//
// `System.Formats.Asn1` y nada más. Se compila en el proyecto de pruebas
// `net8.0` y se ejecuta fuera de Windows, que es donde alguien lo va a
// mirar de verdad.

using System.Formats.Asn1;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Qué se vio en el certificado.
///
/// ⚠️ <c>Unverifiable</c> NO es <c>Invalid</c>, y confundirlos sería el
/// falso positivo grande: significa que el certificado trae mitad
/// alternativa y la CA del bundle no tiene con qué comprobarla porque
/// todavía es clásica. Ése es exactamente el estado por el que se pasa
/// mientras la Issuing híbrida no exista — o sea, hoy.
/// </summary>
public enum CatalystVerdict
{
    Absent,
    Valid,
    Invalid,
    Unverifiable
}

public static class CatalystReader
{
    private static readonly string OidAltSpki = "2.5.29.72";
    private static readonly string OidAltSigValue = "2.5.29.74";

    /// <summary>La subjectAltPublicKeyInfo del certificado, o null.</summary>
    public static byte[]? SubjectAltSpki(byte[] certDer) => ExtensionValue(certDer, OidAltSpki);

    /// <summary>La firma alternativa, sin el octeto de relleno del BIT STRING.</summary>
    public static byte[]? AltSignatureValue(byte[] certDer)
    {
        var v = ExtensionValue(certDer, OidAltSigValue);
        if (v is null) return null;
        try
        {
            var r = new AsnReader(v, AsnEncodingRules.DER);
            return r.ReadBitString(out _);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// El TBSCertificate SIN la extensión 74, que es sobre lo que se firmó.
    ///
    /// ⚠️ Todo lo demás se copia BYTE A BYTE del original. Volver a
    /// codificar los campos anteriores sería «casi» lo mismo, y ese casi
    /// es una firma que no verifica sin que nada parezca roto.
    /// </summary>
    public static byte[]? TbsWithoutAltSignature(byte[] certDer)
    {
        try
        {
            var cert = new AsnReader(certDer, AsnEncodingRules.DER).ReadSequence();
            var tbsBytes = cert.ReadEncodedValue().ToArray();

            var tbs = new AsnReader(tbsBytes, AsnEncodingRules.DER).ReadSequence();
            var antes = new List<byte[]>();
            byte[]? extsBytes = null;

            var etiquetaExts = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);
            while (tbs.HasData)
            {
                var t = tbs.PeekTag();
                var v = tbs.ReadEncodedValue().ToArray();
                if (t == etiquetaExts) { extsBytes = v; break; }
                antes.Add(v);
            }
            if (extsBytes is null) return null;

            // Dentro del [3] hay un SEQUENCE OF Extension.
            var wrapper = new AsnReader(extsBytes, AsnEncodingRules.DER)
                .ReadSequence(etiquetaExts);
            var extSeq = wrapper.ReadSequence();

            var conservadas = new List<byte[]>();
            var habia74 = false;
            while (extSeq.HasData)
            {
                var raw = extSeq.ReadEncodedValue().ToArray();
                var ext = new AsnReader(raw, AsnEncodingRules.DER).ReadSequence();
                var oid = ext.ReadObjectIdentifier();
                if (oid == OidAltSigValue) { habia74 = true; continue; }
                conservadas.Add(raw);
            }
            if (!habia74) return null;

            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                foreach (var b in antes) w.WriteEncodedValue(b);
                using (w.PushSequence(etiquetaExts))
                using (w.PushSequence())
                {
                    foreach (var b in conservadas) w.WriteEncodedValue(b);
                }
            }
            return w.Encode();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>El veredicto, dada la SPKI alternativa del emisor.</summary>
    public static CatalystVerdict Classify(byte[] certDer, byte[]? issuerAltSpki)
    {
        byte[]? alt;
        try { alt = SubjectAltSpki(certDer); }
        catch { return CatalystVerdict.Absent; }

        if (alt is null) return CatalystVerdict.Absent;
        if (issuerAltSpki is null) return CatalystVerdict.Unverifiable;

        var cuerpo = TbsWithoutAltSignature(certDer);
        var firma = AltSignatureValue(certDer);
        if (cuerpo is null || firma is null) return CatalystVerdict.Invalid;

        return MlDsaAlt.Verify(firma, cuerpo, issuerAltSpki)
            ? CatalystVerdict.Valid
            : CatalystVerdict.Invalid;
    }

    /// <summary>Qué pasó con UN tramo de la cadena.</summary>
    public sealed record AltChainLink(string Subject, CatalystVerdict Verdict);

    /// <summary>El resultado de recorrer la cadena alternativa.</summary>
    public sealed record AltChainResult(
        IReadOnlyList<AltChainLink> Links,
        int Depth,
        bool AnyInvalid)
    {
        public override string ToString() =>
            Links.Count == 0
                ? "cadena sin tramos que comprobar"
                : $"profundidad PQ {Depth}/{Links.Count} · {string.Join(" → ", Links.Select(l => l.Verdict))}";
    }

    /// <summary>
    /// Verifica la mitad alternativa a lo largo de la CADENA, no de un
    /// eslabón.
    ///
    /// ⚠️ ES LO QUE HACE QUE LA ROOT HÍBRIDA (D4) SIRVA DE ALGO. Su clave
    /// alternativa sólo compra seguridad si alguien comprueba que la
    /// Issuing lleva una firma hecha con ella; su propia autofirma
    /// alternativa no la verifica nadie, porque un ancla se confía por
    /// estar en el almacén.
    ///
    /// `chain` va de la HOJA a la RAÍZ, como la entrega X509Chain. La raíz
    /// entra porque de ella sale la clave del último tramo, aunque su
    /// autofirma no se comprueba.
    ///
    /// ⚠️ Devuelve PROFUNDIDAD, no un booleano. Durante la migración la
    /// cadena post-cuántica es más corta que la clásica —dos tramos, uno o
    /// ninguno según hasta dónde llegó el despliegue— y un verificador de
    /// «todo o nada» declararía rota una flota que funciona como se
    /// planeó. El número es además lo único con lo que se puede decidir
    /// cuándo exigir sin apostar.
    /// </summary>
    public static AltChainResult ClassifyChain(IReadOnlyList<byte[]> chain)
    {
        var links = new List<AltChainLink>();
        var depth = 0;
        var anyInvalid = false;
        var seguida = true;

        for (var i = 0; i < chain.Count - 1; i++)
        {
            var emisorAlt = SubjectAltSpki(chain[i + 1]);
            var v = Classify(chain[i], emisorAlt);

            if (v == CatalystVerdict.Invalid) anyInvalid = true;
            if (seguida && v == CatalystVerdict.Valid) depth++; else seguida = false;

            links.Add(new AltChainLink($"#{i}", v));
        }

        return new AltChainResult(links, depth, anyInvalid);
    }

    /// <summary>
    /// La SPKI alternativa de la CA, sacada del bundle que el agente ya
    /// tiene instalado.
    ///
    /// ⚠️ Del BUNDLE y no de una variable nueva: la mitad alternativa de
    /// una CA vive en su certificado por definición, y un valor aparte
    /// podría discrepar del certificado que el equipo usa de verdad. Ese
    /// desacuerdo se leería como «el servidor tiene la firma inválida».
    /// </summary>
    public static byte[]? IssuerAltSpkiFrom(IEnumerable<byte[]> bundleDer)
    {
        foreach (var der in bundleDer)
        {
            try
            {
                var alt = SubjectAltSpki(der);
                if (alt is not null) return alt;
            }
            catch
            {
                // Un certificado ilegible del bundle no puede tumbar la
                // conexión: quedarse sin mitad alternativa degrada a
                // Unverifiable, que es un veredicto y no un corte.
            }
        }
        return null;
    }

    // ── Interno ─────────────────────────────────────────────────────────

    private static byte[]? ExtensionValue(byte[] certDer, string oid)
    {
        try
        {
            var cert = new AsnReader(certDer, AsnEncodingRules.DER).ReadSequence();
            var tbs = cert.ReadSequence();

            var etiquetaExts = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);
            AsnReader? extSeq = null;
            while (tbs.HasData)
            {
                if (tbs.PeekTag() == etiquetaExts)
                {
                    extSeq = tbs.ReadSequence(etiquetaExts).ReadSequence();
                    break;
                }
                tbs.ReadEncodedValue();
            }
            if (extSeq is null) return null;

            while (extSeq.HasData)
            {
                var ext = extSeq.ReadSequence();
                var id = ext.ReadObjectIdentifier();
                // `critical` es OPCIONAL: leerlo por posición fija se
                // rompe con las extensiones que sí lo llevan.
                if (ext.PeekTag() == Asn1Tag.Boolean) ext.ReadBoolean();
                var valor = ext.ReadOctetString();
                if (id == oid) return valor;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }
}
