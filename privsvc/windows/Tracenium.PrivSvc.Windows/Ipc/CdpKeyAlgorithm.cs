// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpKeyAlgorithm.cs
//
// ADR-0033 F1 — que algoritmos admite `cdp.csr.generate`, y con que
// hash se firma cada uno.
//
// ── Por que un fichero APARTE y puro ────────────────────────────────
//
// Porque asi se puede PROBAR. `CdpKeys.cs` arrastra CNG, ACLs y
// `Environment.SpecialFolder`: es `net8.0-windows` y no compila en el
// proyecto de pruebas, que es `net8.0` a proposito para poder correr en
// el Mac donde se escribe esto (ver la cabecera de
// Tracenium.PrivSvc.Tests.csproj). La tabla de algoritmos es texto puro,
// asi que vive aqui y se compila en las dos partes.
//
// No es cosmetica: lo que hay que garantizar es que un algoritmo
// DESCONOCIDO se rechace y no caiga en silencio a otro mas debil. Eso es
// una decision de tabla, y una tabla sin test es una lista de deseos.
//
// ── Por que la tabla es cerrada ─────────────────────────────────────
//
// El campo lo manda el control plane, que es el adversario del que
// desconfia ADR-0011. «Lo que no entiendo, RSA-2048» convierte una
// peticion de ECDSA P-384 mal escrita en una clave de 2048 bits que
// nadie pidio y que el inventario declarara como lo que se pidio. Se
// falla ruidosamente, como ya hace el CSR de enrolamiento — ahi la razon
// esta escrita: un desajuste silencioso de algoritmo rompio el
// enrolamiento de Windows una vez.
//
// El gemelo de esta tabla vive en `privsvc/linux/src/cdp-keys.ts`,
// `privsvc/macos/src/cdp-keys.ts` y el helper `keystore/main.swift`. Los
// cuatro tienen que aceptar y rechazar EXACTAMENTE lo mismo: la misma
// peticion no puede producir certificados distintos segun el sistema
// operativo del endpoint.

namespace Tracenium.PrivSvc.Windows.Ipc;

public enum CdpKeyKind
{
    Rsa,
    Ecdsa
}

/// <summary>
/// Un algoritmo admitido, ya resuelto.
///
/// `Bits` es el tamaño del modulo para RSA y el de la curva para ECDSA.
/// `HashName` es el nombre que entiende `HashAlgorithmName` — se guarda
/// como texto para que este fichero no dependa de
/// System.Security.Cryptography y siga compilando en `net8.0`.
/// </summary>
public sealed class CdpKeyAlgorithmSpec
{
    public CdpKeyAlgorithmSpec(string name, CdpKeyKind kind, int bits, string hashName)
    {
        Name = name;
        Kind = kind;
        Bits = bits;
        HashName = hashName;
    }

    /// <summary>El nombre canonico. Es el que se DEVUELVE al control plane.</summary>
    public string Name { get; }
    public CdpKeyKind Kind { get; }
    public int Bits { get; }
    public string HashName { get; }
}

public static class CdpKeyAlgorithm
{
    /// <summary>
    /// Lo que se usa cuando el payload no trae el campo.
    ///
    /// ⚠️ Tiene que seguir siendo RSA_2048: un control plane que todavia
    /// no manda `keyAlgorithm` —los hay desplegados— debe seguir
    /// emitiendo exactamente lo que emitia antes de ADR-0033.
    /// </summary>
    public const string DefaultName = "RSA_2048";

    private static readonly Dictionary<string, CdpKeyAlgorithmSpec> Supported =
        new(StringComparer.Ordinal)
        {
            ["RSA_2048"] = new CdpKeyAlgorithmSpec("RSA_2048", CdpKeyKind.Rsa, 2048, "SHA256"),
            ["RSA_3072"] = new CdpKeyAlgorithmSpec("RSA_3072", CdpKeyKind.Rsa, 3072, "SHA256"),
            ["RSA_4096"] = new CdpKeyAlgorithmSpec("RSA_4096", CdpKeyKind.Rsa, 4096, "SHA256"),
            // El hash acompaña a la curva a proposito. Firmar P-384 con
            // SHA-256 es legal y es un desperdicio medible: la CA emite
            // un certificado con menos fuerza de la que el cliente pidio
            // al elegir la curva grande, y nadie lo mira despues.
            ["ECDSA_P256"] = new CdpKeyAlgorithmSpec("ECDSA_P256", CdpKeyKind.Ecdsa, 256, "SHA256"),
            ["ECDSA_P384"] = new CdpKeyAlgorithmSpec("ECDSA_P384", CdpKeyKind.Ecdsa, 384, "SHA384")
        };

    /// <summary>Los nombres admitidos, en orden estable (para los mensajes de error).</summary>
    public static IReadOnlyList<string> Names { get; } = new[]
    {
        "RSA_2048", "RSA_3072", "RSA_4096", "ECDSA_P256", "ECDSA_P384"
    };

    /// <summary>
    /// Resuelve el algoritmo pedido. `null`/vacio → el de por defecto.
    ///
    /// Devuelve false —y NO un valor de reserva— ante cualquier otra
    /// cosa. Ese es el punto entero del fichero.
    /// </summary>
    public static bool TryResolve(string? raw, out CdpKeyAlgorithmSpec spec, out string error)
    {
        var pedido = (raw ?? "").Trim();
        if (pedido.Length == 0) pedido = DefaultName;
        // Se acepta la caja que venga —el resto del contrato tampoco la
        // distingue— pero NADA mas: ni guiones, ni alias, ni prefijos.
        pedido = pedido.ToUpperInvariant();

        if (Supported.TryGetValue(pedido, out var encontrado))
        {
            spec = encontrado;
            error = "";
            return true;
        }

        spec = Supported[DefaultName];
        error = $"keyAlgorithm no soportado: {pedido} ({string.Join("|", Names)})";
        return false;
    }
}
