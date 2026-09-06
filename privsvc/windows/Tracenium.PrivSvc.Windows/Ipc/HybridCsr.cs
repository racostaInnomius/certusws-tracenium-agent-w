// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/HybridCsr.cs
//
// ADR-0015 punto 11 — el CSR híbrido, en DOS PASADAS.
//
// ── EL PROBLEMA, Y POR QUÉ NO HACE FALTA ASN.1 A MANO ─────────────────
//
// La prueba de posesión alternativa se firma sobre el propio
// CertificationRequestInfo y va DENTRO de ese mismo cuerpo. Huevo y
// gallina: `CreateSigningRequest()` produce el DER de una vez y no deja
// meter mano en medio.
//
// El encargo daba por hecho que eso obligaba a construir el PKCS#10 con
// `System.Formats.Asn1` o BouncyCastle. **Se comprobó y no hace falta**,
// y evitarlo importa: ASN.1 escrito a mano en el camino de la identidad
// es donde viven los fallos que nadie ve — una longitud en forma corta
// donde toca la larga, un BIT STRING sin su octeto de relleno.
//
// Lo que sí acepta `CertificateRequest` es una `X509Extension` con
// CUALQUIER OID, así que las tres extensiones catalyst caben en su
// `CertificateExtensions`. Con eso el orden se resuelve en dos pasadas:
//
//   1. Se construye el CSR con la 72 y la 73, SIN la 74, y se extrae su
//      CertificationRequestInfo.
//   2. Se firma ese cuerpo con ML-DSA.
//   3. Se construye OTRA VEZ, ahora con la 74 dentro.
//
// Funciona porque el cuerpo de la segunda pasada es el de la primera MÁS
// la 74: mismos campos, mismo orden de extensiones —el de inserción—,
// mismo encoder. Quien verifique quitará la 74 y recuperará exactamente
// el cuerpo de la pasada 1.
//
// ⚠️ Se paga una firma clásica de más (la del CSR de la pasada 1, que se
// tira). Con una clave CNG son milisegundos y ocurre una vez por
// enrolamiento o renovación. Es un precio ridículo por no escribir un
// codificador DER propio.
//
// ⚠️ Y SE COMPROBÓ DE PUNTA A PUNTA antes de escribirlo: el CSR que sale
// de aquí lo acepta `openssl req -verify` y lo acepta el validador del
// backend —el de verdad, con `@noble/post-quantum`— incluida la prueba
// de posesión alternativa.
//
// Este fichero no toca Windows: recibe la clave clásica ya abierta. Así
// se puede probar en el proyecto `net8.0` que corre fuera de Windows.

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class HybridCsr
{
    /// <summary>2.5.29.72 subjectAltPublicKeyInfo.</summary>
    public const string OidAltSpki = "2.5.29.72";
    /// <summary>2.5.29.73 altSignatureAlgorithm.</summary>
    public const string OidAltSigAlg = "2.5.29.73";
    /// <summary>2.5.29.74 altSignatureValue.</summary>
    public const string OidAltSigValue = "2.5.29.74";

    /// <summary>
    /// Construye el CSR.
    ///
    /// <paramref name="nuevaPeticion"/> devuelve una `CertificateRequest`
    /// RECIÉN HECHA con el sujeto, la clave clásica y las extensiones
    /// base. Se llama dos veces a propósito: una `CertificateRequest` no
    /// se puede reutilizar limpiando su lista de extensiones sin
    /// arriesgarse a arrastrar estado entre pasadas.
    ///
    /// Sin <paramref name="altPkcs8Der"/> sale un CSR CLÁSICO por el
    /// mismo camino. Un solo camino de código evita que el clásico —el
    /// 100 % de la flota hoy— quede peor probado que el híbrido.
    /// </summary>
    public static byte[] Build(
        Func<CertificateRequest> nuevaPeticion,
        byte[]? altPkcs8Der,
        byte[]? altSpkiDer)
    {
        if ((altPkcs8Der is null) != (altSpkiDer is null))
        {
            // Media pareja es un error de programación, no un CSR
            // degradado: un CSR con SPKI alternativa y sin su prueba lo
            // RECHAZA el backend por diseño.
            throw new ArgumentException(
                "clave alternativa incompleta: hacen falta PKCS#8 y SPKI, o ninguna");
        }

        if (altPkcs8Der is null || altSpkiDer is null)
        {
            return nuevaPeticion().CreateSigningRequest();
        }

        // Pasada 1 — con la 72 y la 73, sin la 74.
        var sinAlt74 = nuevaPeticion();
        AgregarAltSpkiYAlgoritmo(sinAlt74, altSpkiDer);
        var cuerpo = CertificationRequestInfoDe(sinAlt74.CreateSigningRequest());

        // La firma alternativa cubre ESE cuerpo.
        var firmaAlt = MlDsaAlt.Sign(cuerpo, altPkcs8Der);

        // Pasada 2 — ahora con las tres.
        var conAlt74 = nuevaPeticion();
        AgregarAltSpkiYAlgoritmo(conAlt74, altSpkiDer);
        conAlt74.CertificateExtensions.Add(
            new X509Extension(OidAltSigValue, BitStringDer(firmaAlt), critical: false));

        return conAlt74.CreateSigningRequest();
    }

    private static void AgregarAltSpkiYAlgoritmo(CertificateRequest req, byte[] altSpkiDer)
    {
        // El valor de la 72 es la SPKI TAL CUAL, no envuelta en nada más.
        req.CertificateExtensions.Add(new X509Extension(OidAltSpki, altSpkiDer, critical: false));
        req.CertificateExtensions.Add(
            new X509Extension(OidAltSigAlg, MlDsaAlt.AlgorithmIdentifierDer(), critical: false));
    }

    /// <summary>
    /// El CertificationRequestInfo de un CSR: su primer elemento.
    ///
    /// Se lee con `AsnReader` en modo DER estricto. Un CSR que no se deje
    /// leer aquí no es un CSR que valga la pena firmar.
    /// </summary>
    public static byte[] CertificationRequestInfoDe(byte[] csrDer)
    {
        var lector = new AsnReader(csrDer, AsnEncodingRules.DER);
        var seq = lector.ReadSequence();
        return seq.ReadEncodedValue().ToArray();
    }

    /// <summary>
    /// Un BIT STRING DER con cero bits sin usar.
    ///
    /// ⚠️ El octeto de relleno inicial se olvida con una facilidad
    /// notable, y su ausencia desplaza todo el contenido un byte: la
    /// firma deja de verificar sin que la estructura parezca mal formada.
    /// </summary>
    public static byte[] BitStringDer(byte[] contenido)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteBitString(contenido, unusedBitCount: 0);
        return w.Encode();
    }
}
