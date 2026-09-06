// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/MlDsaAlt.cs
//
// ADR-0015 punto 11 — la primitiva ML-DSA-65 del agente de Windows.
//
// ── POR QUÉ BOUNCYCASTLE Y NO `MLDsa` DE .NET 10 ──────────────────────
//
// El encargo lo dice y conviene que quede aquí escrito, porque «usar lo
// del framework» es siempre la opción que parece correcta:
//
// `System.Security.Cryptography.MLDsa` de .NET 10 es una FACHADA SOBRE
// CNG. Hereda lo que tenga el sistema operativo, y ML-DSA en CNG existe
// sólo desde Windows 11 25H2 y Server 2025. **Los 12 Server 2022 de la
// flota no lo tendrán nunca.** Ahí esa clase lanza, así que subir a .NET
// 10 no compra esta funcionalidad: la parte en dos, una mitad de la flota
// con híbrido y la otra sin él.
//
// BouncyCastle es TOTALMENTE GESTIONADO —C# puro, sin P/Invoke a
// bcrypt.dll— así que echa las cuentas dentro del proceso y da el mismo
// resultado en Server 2022 que en Server 2025. No es que sea mejor
// criptografía: es que no le pregunta nada al sistema.
//
// ── INTEROPERABILIDAD, MEDIDA ANTES DE ESCRIBIR ESTO ──────────────────
//
// El gate 2 del ADR exige que una implementación AJENA verifique lo
// nuestro. Comprobado el 2026-09-06 con BouncyCastle 2.7.0:
//
//   SPKI    1.974 B  ·  PKCS#8  4.098 B  ·  firma  3.309 B
//   → los mismos bytes que noble y que OpenSSL 3.6.
//
//   ✅ OpenSSL 3.6 verifica una firma hecha aquí («Signature Verified
//      Successfully»).
//   ✅ `@noble/post-quantum`, que es lo que usa el BACKEND para validar
//      la prueba de posesión del CSR, también la verifica.
//
// Esa segunda es la que importa de verdad: sin ella, el agente de
// Windows produciría CSR híbridos que el control plane rechazaría.
//
// ── ESTE FICHERO NO TIENE NADA DE WINDOWS DENTRO ──────────────────────
//
// Deliberado. El proyecto de pruebas es `net8.0` a secas y compila
// ficheros SUELTOS del servicio para poder ejecutarse fuera de Windows —
// una suite que sólo corre en una máquina que nadie tiene delante acaba
// sin correr. La parte que sí es de Windows (DPAPI, el directorio de
// ProgramData) vive en AltKeyStore.cs, aparte y a propósito.

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>Par de claves ML-DSA-65 en la moneda común: DER.</summary>
public sealed record MlDsaKeyPairDer(byte[] SpkiDer, byte[] Pkcs8Der);

public static class MlDsaAlt
{
    /// <summary>id-ml-dsa-65, arco CSOR de NIST.</summary>
    public const string Oid = "2.16.840.1.101.3.4.3.18";

    /// <summary>Tamaños fijos del parámetro 65. Para validar, no para adivinar.</summary>
    public const int PublicKeyBytes = 1952;
    public const int SignatureBytes = 3309;
    public const int SpkiBytes = 1974;

    /// <summary>
    /// AlgorithmIdentifier { id-ml-dsa-65 }, ya en DER.
    ///
    /// ⚠️ SIN parámetros. ML-DSA no los lleva, y meter un NULL —el reflejo
    /// que viene de RSA— produce un AlgorithmIdentifier que otros
    /// verificadores rechazan.
    /// </summary>
    public static byte[] AlgorithmIdentifierDer() =>
        Convert.FromHexString("300B0609608648016503040312");

    /// <summary>Genera un par nuevo.</summary>
    public static MlDsaKeyPairDer GenerateKeyPair()
    {
        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), MLDsaParameters.ml_dsa_65));
        var kp = gen.GenerateKeyPair();

        return new MlDsaKeyPairDer(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public).GetDerEncoded(),
            PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private).GetDerEncoded());
    }

    /// <summary>
    /// Firma cruda, sin prehash.
    ///
    /// ⚠️ Es lo que exigen `altSignatureValue` y la prueba de posesión del
    /// CSR: la firma cubre los bytes del cuerpo TAL CUAL. `HashMLDsaSigner`
    /// —la variante prehash— produce una firma de la misma longitud que
    /// NADIE de los nuestros verifica, y el fallo no se distingue de una
    /// clave equivocada.
    /// </summary>
    public static byte[] Sign(byte[] message, byte[] pkcs8Der)
    {
        var priv = PrivateKeyFactory.CreateKey(pkcs8Der);
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    /// <summary>
    /// Verifica una firma contra una SPKI.
    ///
    /// ⚠️ Devuelve `false` en vez de lanzar ante entrada ilegible. Esto se
    /// llama desde la verificación del certificado del SERVIDOR, dentro
    /// del camino de una conexión viva: una excepción ahí tiraría el
    /// canal por una comprobación que está en modo observación.
    /// </summary>
    public static bool Verify(byte[] signature, byte[] message, byte[] spkiDer)
    {
        try
        {
            AsymmetricKeyParameter pub = PublicKeyFactory.CreateKey(spkiDer);
            if (pub is not MLDsaPublicKeyParameters) return false;

            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
            signer.Init(forSigning: false, pub);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>La SPKI que corresponde a un PKCS#8, derivada de la privada.</summary>
    public static byte[] SpkiFromPkcs8(byte[] pkcs8Der)
    {
        var priv = (MLDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(pkcs8Der);
        return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(priv.GetPublicKey()).GetDerEncoded();
    }
}
