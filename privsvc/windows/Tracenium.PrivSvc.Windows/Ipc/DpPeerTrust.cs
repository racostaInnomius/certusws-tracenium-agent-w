// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/DpPeerTrust.cs
//
// ¿A qué clientes sirve un Distribution Point? A los que presentan un
// certificado emitido por una CA EMISORA DEL TENANT — cualquiera de ellas.
//
// 🔴 EL INCIDENTE (15-sep, MSIG-VEEAM-PC): el DP aceptaba sólo la huella
// SINGULAR de la CA con la que él mismo se enroló. Los DP de T111 están en la
// Issuing vieja; VEEAM-PC rotó a la G2. El DP rechazaba el handshake en un
// `catch {}` mudo, el equipo caía a descargar de Azure, su VLAN no llega, y el
// job decía `connect ETIMEDOUT` — un error de red que no lo era. Cuando la
// flota rote a la G2 le pasaría a todos los peers; si rotan antes los DP, al
// revés.
//
// Por eso el conjunto aceptado es la UNIÓN de:
//   · las CAs que el propio DP acepta para hablar con el servidor (singular +
//     lista, instaladas en su almacén), y
//   · las que el control plane le entrega con cada prefetch
//     (`peerCaBundlePem`). Un DP enrolado en agosto NO tiene la G2 instalada;
//     sin esto nunca la conocería.
//
// ⚠️ Una CA entregada sólo cuenta si la firmó un ANCLA: la raíz que firmó a
// alguna CA que el DP ya tenía. Así el canal de entrega amplía el conjunto
// dentro de la misma jerarquía y no puede meter una CA ajena.
//
// La comprobación es la firma directa de CertIssuedBy, no X509Chain: es lo
// que corre igual en Windows y en el test de macOS (ver CertIssuedBy.cs, el
// X509Chain con CustomRootTrust rompió Windows entero el 11-sep).

using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class DpPeerTrust
{
    /// <summary>Tope del bundle entregado: dos intermedias ocupan ~4 KB.</summary>
    public const int MaxBundleChars = 64 * 1024;

    public static List<X509Certificate2> ParsePemBundle(string? pem)
    {
        var certs = new List<X509Certificate2>();
        if (string.IsNullOrWhiteSpace(pem) || pem.Length > MaxBundleChars) return certs;

        const string end = "-----END CERTIFICATE-----";
        foreach (var block in pem.Split(end))
        {
            var start = block.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
            if (start < 0) continue;
            try
            {
                certs.Add(X509Certificate2.CreateFromPem(block[start..] + end));
            }
            catch
            {
                // Un bloque ilegible no invalida los demás.
            }
        }
        return certs;
    }

    public static bool IsCa(X509Certificate2 cert) =>
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(b => b.CertificateAuthority);

    public static bool IsSelfSigned(X509Certificate2 cert) =>
        cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);

    /// <summary>
    /// Las CAs entregadas que el DP puede aceptar: CA, no autofirmada, vigente
    /// y firmada por una de <paramref name="anchors"/>.
    /// </summary>
    public static List<X509Certificate2> TrustedDeliveredCas(
        IEnumerable<X509Certificate2> delivered,
        IReadOnlyCollection<X509Certificate2> anchors,
        DateTime utcNow)
    {
        if (anchors.Count == 0) return new List<X509Certificate2>();
        return delivered
            .Where(c => IsCa(c) && !IsSelfSigned(c))
            .Where(c => CertIssuedBy.WhyNotUsable(c, anchors, utcNow) == null)
            .ToList();
    }

    /// <summary>
    /// null si el DP debe servir a este peer; si no, el motivo (va al log).
    /// Sin ninguna CA aceptada se rechaza a todos: un DP sin identidad no
    /// sirve a cualquiera.
    /// </summary>
    public static string? WhyPeerRejected(
        X509Certificate2 peer,
        IReadOnlyCollection<X509Certificate2> acceptedCas,
        DateTime utcNow)
    {
        if (acceptedCas.Count == 0) return "no accepted issuing CA on this DP";
        if (IsCa(peer)) return "peer presented a CA certificate, not an agent certificate";
        return CertIssuedBy.WhyNotUsable(peer, acceptedCas, utcNow);
    }

    /// <summary>Unión sin repetidos (por huella), conservando el orden.</summary>
    public static List<X509Certificate2> Union(params IEnumerable<X509Certificate2>[] sets)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<X509Certificate2>();
        foreach (var set in sets)
            foreach (var c in set)
                if (seen.Add(c.Thumbprint)) result.Add(c);
        return result;
    }
}
