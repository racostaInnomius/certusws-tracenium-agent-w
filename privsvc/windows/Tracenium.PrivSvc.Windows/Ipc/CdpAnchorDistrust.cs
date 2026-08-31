// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpAnchorDistrust.cs
//
// Quitar la confianza a un ancla. ADR-0011, decision 10.
//
// ⚠️ ESTA PRIMITIVA NO TIENE RUTA QUE LA INVOQUE TODAVIA, Y ES
// DELIBERADO. La decision 10 exige el regimen de aprobacion de ADR-0009,
// que esta aceptado y sin construir. La fase 1 del propio ADR-0011 dice
// construir la defensa ANTES que la capacidad que la necesita, "porque
// es la unica forma de que la defensa no se recorte por presion de
// calendario cuando la funcionalidad ya este a medio camino".
//
// ── Por que DESCONFIAR y no BORRAR ──────────────────────────────────
//
// Borrar de LocalMachine\Root es la respuesta intuitiva y la equivocada:
// el trust store de Windows se puebla BAJO DEMANDA — la maquina vuelve a
// descargar una raiz la proxima vez que una cadena la necesite. Un
// borrado puede deshacerse solo, y entonces reportariamos "remediado"
// sobre un equipo que no lo esta, que es peor que no haber hecho nada.
//
// El mecanismo autoritativo es el store `Disallowed` (Untrusted
// Certificates), que es el que usa Microsoft para desconfiar. Persiste,
// gana a la presencia en Root, y es reversible quitandolo de ahi.
//
// ── El control plane NUNCA manda material de certificado aqui ────────
//
// Se opera por HUELLA: el handler localiza el certificado en los stores
// del propio equipo. Si no esta, no hay nada que desconfiar y se niega.
// Consecuencia buscada: por esta ruta un control plane comprometido no
// puede INTRODUCIR nada, solo retirar la confianza de algo que el equipo
// ya tenia. Reduce la capacidad a exactamente lo que dice su nombre.

using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpAnchorDistrust
{
    /// <summary>
    /// Stores donde la PRESENCIA de una raiz significa que el equipo
    /// confia en ella. Son los unicos de los que tiene sentido —y se
    /// permite— retirar confianza.
    /// </summary>
    private static readonly StoreName[] TrustStores =
    {
        StoreName.Root,
        StoreName.AuthRoot
    };

    private static string Normalize(string thumbprint) =>
        new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            // `Params` puede venir nulo: una peticion sin cuerpo tiene
            // que responder "falta thumbprint", no reventar el servicio.
            var thumbprint =
                req.Params != null && req.Params.TryGetValue("thumbprint", out var raw) && raw != null
                    ? raw.ToString() ?? ""
                    : "";

            if (string.IsNullOrWhiteSpace(thumbprint))
                return Task.FromResult(PrivSvcResponse.Fail(
                    req.Id, "invalid_params", "thumbprint is required"));

            var wanted = Normalize(thumbprint);

            // ── Salvaguarda 1: jamas la propia cadena del agente ───────
            //
            // Desconfiar del ancla que sostiene el mTLS del agente seria
            // un suicidio remoto: el equipo dejaria de poder hablar con
            // el control plane, y sin conexion no se le puede mandar el
            // arreglo. Se comprueba LOCALMENTE contra el fichero de pines
            // de la fase 0, no contra lo que diga el servidor — que es el
            // adversario del que este ADR protege.
            foreach (var pinned in AnchorPin.Load())
            {
                if (Normalize(pinned) == wanted)
                {
                    return Task.FromResult(PrivSvcResponse.Fail(
                        req.Id,
                        "anchor_is_own_chain",
                        "refusing to distrust an anchor this agent's own certificate chain depends on"));
                }
            }

            // ── Salvaguarda 2: tiene que estar presente ────────────────
            //
            // Si no esta en ningun trust store no hay confianza que
            // retirar, y añadirlo a Disallowed seria actuar sobre algo
            // que el equipo no tiene. Negarse mantiene la operacion atada
            // a la realidad del endpoint.
            var found = new List<string>();
            X509Certificate2? cert = null;

            foreach (var storeName in TrustStores)
            {
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                var match = store.Certificates.Find(X509FindType.FindByThumbprint, wanted, false);
                if (match.Count > 0)
                {
                    found.Add(storeName.ToString());
                    cert ??= match[0];
                }
                store.Close();
            }

            if (cert == null)
            {
                return Task.FromResult(PrivSvcResponse.Fail(
                    req.Id,
                    "anchor_not_present",
                    "certificate is not in any machine trust store; nothing to distrust"));
            }

            // ── La operacion ──────────────────────────────────────────
            //
            // Se AÑADE a Disallowed y NO se quita de Root. Quitarlo seria
            // el borrado que la decision 10 descarta: reversible por el
            // auto-update de raices, y por tanto una remediacion que se
            // deshace sola sin avisar. Disallowed gana a Root, asi que la
            // confianza queda retirada de verdad.
            using (var disallowed = new X509Store(StoreName.Disallowed, StoreLocation.LocalMachine))
            {
                disallowed.Open(OpenFlags.ReadWrite);
                var already = disallowed.Certificates
                    .Find(X509FindType.FindByThumbprint, wanted, false).Count > 0;
                if (!already) disallowed.Add(cert);
                disallowed.Close();
            }

            Console.WriteLine(
                $"[PrivSvc][CdpAnchorDistrust] {cert.Subject} añadido a Disallowed " +
                $"(presente en: {string.Join(", ", found)})");

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                thumbprint = wanted,
                subject = cert.Subject,
                distrusted = true,
                store = "Disallowed",
                // Se reporta DONDE seguia estando: la remediacion no
                // borra, asi que el inventario seguira viendolo en Root y
                // el operador tiene que poder entender por que.
                stillPresentIn = found
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(
                req.Id, "cdp_anchor_distrust_failed", ex.Message));
        }
    }
}
