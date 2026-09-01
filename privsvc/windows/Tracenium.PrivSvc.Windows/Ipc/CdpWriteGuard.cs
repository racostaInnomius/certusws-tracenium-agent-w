// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpWriteGuard.cs
//
// ADR-0011 FASE 1 — la defensa, construida ANTES que la capacidad.
//
// ⚠️ NADA INVOCA ESTO TODAVIA, y es deliberado. La fase 3 del ADR
// (`cdp.cert.install`) es la que lo usara. El propio ADR ordena asi las
// fases "porque es la unica forma de que la defensa no se recorte por
// presion de calendario cuando la funcionalidad ya este a medio camino".
//
// Implementa las decisiones 1 y 2:
//
//   1. La lista de stores escribibles es una ALLOWLIST y excluye las
//      anclas. Nunca Root, nunca AuthRoot, nunca el trust store del
//      sistema.
//   2. Solo se instala lo que YA encadena a un ancla presente. La
//      validacion la hace el ENDPOINT, no el backend: un backend
//      comprometido afirmaria que la cadena es buena.
//
// ── Por que allowlist y no denylist ─────────────────────────────────
//
// Una denylist se equivoca en silencio cada vez que el sistema operativo
// añade un store. Una allowlist, ante algo que no conoce, dice que no —
// que es el lado correcto por el que fallar cuando lo que esta en juego
// es escribir en el almacen de confianza de un equipo ajeno.

using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpWriteGuard
{
    /// <summary>
    /// Los UNICOS stores en los que CDP puede escribir.
    ///
    /// `My` es donde vive la identidad de una maquina o un servicio;
    /// `WebHosting` es donde IIS busca los certificados que sirve. Los
    /// dos son sitios donde poner un certificado de hoja es la operacion
    /// normal, y ninguno de los dos otorga confianza a nadie.
    ///
    /// Root y AuthRoot NO estan, ni lo estaran por esta via: plantar un
    /// ancla es la amenaza que ADR-0011 existe para gobernar, y la
    /// decision 1 la convierte en imposible por construccion en lugar de
    /// prohibida por procedimiento.
    /// </summary>
    /// Se comparan por NOMBRE y no por el enum `StoreName`: `WebHosting`
    /// no tiene entrada en el enum de .NET, y lo que llega por IPC es una
    /// cadena de todas formas. Una lista mixta —enum para unos, cadena
    /// para otros— habria dejado dos sitios donde mirar.
    private static readonly HashSet<string> WritableByName = new(StringComparer.OrdinalIgnoreCase)
    {
        "My",
        "WebHosting"
    };

    /// <summary>
    /// ¿Se puede escribir en este store?
    ///
    /// Se acepta el nombre como cadena porque es lo que llega por IPC.
    /// Cualquier cosa que no este en la lista —incluido un nombre vacio,
    /// una ruta, o un store que Windows añada en el futuro— es NO.
    /// </summary>
    public static bool IsWritableStore(string? storeName)
    {
        if (string.IsNullOrWhiteSpace(storeName)) return false;
        return WritableByName.Contains(storeName.Trim());
    }

    public sealed class ChainVerdict
    {
        public bool Trusted { get; init; }
        public string Reason { get; init; } = "";
    }

    /// <summary>
    /// ¿Encadena este certificado a un ancla que el equipo YA tiene?
    ///
    /// ⚠️ `DisableCertificateDownloads = true` es lo que hace que esta
    /// comprobacion signifique lo que dice. Sin el, X509Chain sale a la
    /// red por AIA a buscar los eslabones que le faltan, y entonces la
    /// respuesta deja de ser "el equipo ya confia en esto" para pasar a
    /// ser "internet dice que esto esta bien" — que es justo lo que la
    /// decision 2 no quiere. Ademas evita que un servicio privilegiado
    /// haga peticiones de red disparadas por un payload del control
    /// plane.
    ///
    /// La revocacion se deja fuera a proposito: es una pregunta distinta
    /// —y una que el backend responde mejor, con CRL/OCSP, sin convertir
    /// cada endpoint en un cliente OCSP (ADR-0004 lo dice explicitamente).
    /// Aqui solo se decide si la CADENA llega a un ancla local.
    /// </summary>
    /// <param name="extraStore">
    /// Intermedias que acompanan al certificado.
    ///
    /// ⚠️ Hacen falta, y este parametro llego tarde: la fase 1 se
    /// escribio sin el, mientras que los gemelos de macOS y Linux si
    /// reciben la cadena desde el principio. Con `DisableCertificateDownloads`
    /// puesto —que es lo que hace que esta comprobacion signifique lo que
    /// dice— la cadena NO puede salir a buscar los eslabones que le
    /// falten, asi que sin pasarlas este gate rechazaria TODO, incluido
    /// lo legitimo. Medido asi en macOS con un certificado real.
    /// </param>
    public static ChainVerdict ChainsToInstalledAnchor(
        X509Certificate2 cert,
        X509Certificate2Collection? extraStore = null)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        if (extraStore != null && extraStore.Count > 0)
        {
            // `ExtraStore` NO otorga confianza: son eslabones candidatos
            // para construir la cadena. La raiz tiene que seguir estando
            // en el equipo, que es justo lo que la decision 2 exige.
            chain.ChainPolicy.ExtraStore.AddRange(extraStore);
        }

        var ok = chain.Build(cert);
        if (ok)
        {
            return new ChainVerdict { Trusted = true, Reason = "la cadena llega a un ancla instalada" };
        }

        // Se reporta el MOTIVO y no solo el no. Un operador al que se le
        // rechaza una instalacion necesita saber si le falta la
        // intermedia (arreglable) o si la raiz no esta en el equipo
        // (que es el caso que este gate existe para impedir).
        var motivos = chain.ChainStatus
            .Where(s => s.Status != X509ChainStatusFlags.NoError)
            .Select(s => s.Status.ToString())
            .Distinct()
            .ToList();

        return new ChainVerdict
        {
            Trusted = false,
            Reason = motivos.Count > 0
                ? string.Join(", ", motivos)
                : "la cadena no valida contra el trust store local"
        };
    }
}
