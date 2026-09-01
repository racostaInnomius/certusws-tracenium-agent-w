// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoKeyNames.cs
//
// ADR-0011, action item 9 — cerrar el `keyName` sin validar.
//
// ── El agujero ─────────────────────────────────────────────────────
//
// `crypto.csr.generate` y `crypto.cert.install` aceptaban un `keyName`
// del llamante y lo usaban tal cual como nombre de contenedor CNG de
// maquina:
//
//     string keyName = string.IsNullOrWhiteSpace(requestedKeyName)
//         ? $"tracenium-{deviceId}" : requestedKeyName;
//
// Dos consecuencias, y la segunda es peor que la primera:
//
//   1. Con el nombre de enrolamiento y `reuseExistingKey:false`, la
//      ruta entra en `OpenOrCreateMachineRsaKey`, que hace
//      `existingKey.Delete()` y recrea. Eso BORRA la clave privada de
//      la identidad mTLS del agente. El equipo deja de poder hablar con
//      el control plane, y como no puede hablar, no hay forma de
//      mandarle el arreglo: es una visita presencial, multiplicada por
//      la flota.
//
//   2. El nombre era LIBRE. Nada ataba la peticion al espacio de
//      nombres de Tracenium, asi que apuntaba igual de bien a un
//      contenedor de otra aplicacion del equipo. El daño se salia del
//      producto.
//
// ── La regla ───────────────────────────────────────────────────────
//
// Mismo principio que la fase 2: el llamante NO nombra, se DERIVA. Aqui
// no se puede borrar el parametro —la rotacion lo usa de verdad, ver
// abajo—, asi que se acepta solo lo que este codigo mismo podria haber
// generado:
//
//     tracenium-{deviceId}                    identidad viva
//     tracenium-{deviceId}-renew-{segundos}   clave pendiente de rotacion
//
// Cualquier otra cosa es `bad_request`. Se midio quien pasa `keyName`
// antes de decidirlo: solo `CryptoCertRenew`, con la forma `-renew-`, y
// el agente (`src/bootstrap/enroll.ts:119`) que no lo pasa. No hay un
// tercer llamante legitimo.
//
// ⚠️ Y la identidad VIVA no se puede borrar por peticion. La rotacion
// no la necesita —crea una clave pendiente aparte, que es precisamente
// para no tocar la que esta en uso—, asi que exigir `reuseExistingKey`
// ahi no le quita nada a nadie y cierra el caso 1 por construccion.
//
// El recrear-por-algoritmo-equivocado que hace `OpenOrCreateMachineRsaKey`
// sigue intacto: esa decision la toma el propio servicio mirando la
// clave guardada, no el llamante.

using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoKeyNames
{
    /// <summary>El contenedor de la identidad mTLS viva del equipo.</summary>
    public static string EnrollmentKeyName(string deviceId) => $"tracenium-{deviceId}";

    /// <summary>
    /// El contenedor de la clave con la que se abre la credencial del
    /// Infrastructure Gateway (ADR-0013).
    ///
    /// ⚠️ Se DERIVA aquí y `Resolve` no lo acepta a propósito: es la única
    /// clave del equipo capaz de descifrar, y ninguna petición de CSR ni
    /// de instalación debe poder nombrarla — ni para usarla, ni para
    /// borrarla. Vive y muere con el rol de gateway, por
    /// `crypto.gwkey.ensure` y `crypto.gwkey.destroy`, y por nada más.
    /// </summary>
    public static string GatewayEncryptionKeyName(string deviceId) => $"tracenium-{deviceId}-gwenc";

    /// <summary>
    /// Resuelve el nombre del contenedor CNG.
    ///
    /// Vacio o nulo devuelve el de enrolamiento, que es el comportamiento
    /// de siempre. Lo demas tiene que ser una de las dos formas
    /// derivables; si no, se lanza y el llamante responde bad_request.
    ///
    /// ⚠️ `deviceId` se escapa antes de entrar en el patron: llega del
    /// llamante, y sin escapar un `.` o un `|` convertirian la
    /// comprobacion en una comodin. Aun asi el prefijo `tracenium-` es
    /// fijo, asi que lo peor que un deviceId raro puede hacer es
    /// nombrarse a si mismo dentro de nuestro espacio de nombres — nunca
    /// alcanzar el contenedor de otra aplicacion.
    /// </summary>
    public static string Resolve(string? requested, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("deviceId required");

        var enrolamiento = EnrollmentKeyName(deviceId);
        if (string.IsNullOrWhiteSpace(requested)) return enrolamiento;

        var pedido = requested.Trim();
        if (string.Equals(pedido, enrolamiento, StringComparison.Ordinal)) return pedido;

        // `\d{1,20}` y no `\d+`: el sufijo es un unix timestamp, y un
        // numero sin tope seria un nombre de contenedor arbitrariamente
        // largo elegido por el llamante.
        var patron = new Regex(
            $"^{Regex.Escape(enrolamiento)}-renew-\\d{{1,20}}$",
            RegexOptions.CultureInvariant);
        if (patron.IsMatch(pedido)) return pedido;

        throw new ArgumentException(
            "keyName no derivable: solo se acepta el contenedor de enrolamiento " +
            "o uno de rotacion 'tracenium-<deviceId>-renew-<segundos>'");
    }

    /// <summary>
    /// ¿Esta peticion pide destruir la identidad mTLS viva?
    ///
    /// Es el caso 1 del agujero, y no tiene ningun llamante legitimo: la
    /// rotacion trabaja sobre una clave pendiente aparte, justo para no
    /// tocar la que esta en uso.
    /// </summary>
    public static bool WouldDestroyLiveIdentity(string resolvedKeyName, string deviceId, bool reuseExistingKey)
    {
        return !reuseExistingKey
            && string.Equals(resolvedKeyName, EnrollmentKeyName(deviceId), StringComparison.Ordinal);
    }
}
