// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/LoggedOnUsersShape.cs
//
// A QUIÉN preguntarle por sus directivas de usuario. La parte pura.
//
// ── EL FALLO QUE CIERRA, MEDIDO EN CAMPO ────────────────────────────
//
// `appliedUserGpos` llegaba `null` en 18 de 50 equipos de T111. La causa NO era
// gpresult: con la cuenta dada a mano, la MISMA invocación corre en 2,09 s como
// SYSTEM y devuelve la GPO. Era que no había cuenta que darle.
//
// El agente sacaba el usuario de `Win32_ComputerSystem.UserName`, y ese campo
// **NO ve las sesiones RDP**: en un equipo con el usuario conectado por
// Escritorio remoto devuelve cadena vacía. Comprobado en MSIG-VEEAM-PC con la
// sesión abierta: `[]`.
//
// ⚠️ Y despistaba que `host_current_status.last_logon_user` SÍ traía el nombre:
// lo llena OTRO colector (el de hardware de AMP, que enumera sesiones y sí ve
// RDP). Dos lecturas WMI distintas que parecen la misma.
//
// Se resuelve como las impresoras de red: los usuarios con hive cargada en
// HKEY_USERS. Cubre RDP, sesiones desconectadas y equipos multiusuario, que
// hoy son invisibles los tres.

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class LoggedOnUsersShape
{
    /// <summary>Por qué la lista de GPO de usuario es la que es.</summary>
    public const string ReasonNoInteractiveUser = "no_interactive_user";

    /// <summary>
    /// Cuántas cuentas se consultan como mucho.
    ///
    /// ⚠️ No es estética: cada `gpresult /USER` cuesta ~2 s medidos, y el ámbito
    /// de usuario tiene 12 s de presupuesto dentro de un `security.compliance`
    /// que comparte el carril serie del IPC. Un servidor de sesiones con ocho
    /// perfiles cargados agotaría el presupuesto y devolvería `timeout` — o
    /// sea, cambiaríamos un `null` por otro.
    /// </summary>
    public const int MaxUsers = 3;

    /// <summary>
    /// Las cuentas a consultar, en orden: primero la de consola si la hay
    /// —es la respuesta históricamente correcta y la más barata— y después las
    /// de las hives cargadas.
    ///
    /// Se deduplica sin distinguir mayúsculas porque Windows no las distingue
    /// en nombres de cuenta, y consultar dos veces a la misma persona gastaría
    /// la mitad del presupuesto en nada.
    /// </summary>
    public static List<string> Candidates(string? consoleUser, IEnumerable<string?> hiveAccounts)
    {
        var salida = new List<string>();
        var vistos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Añadir(string? cuenta)
        {
            if (string.IsNullOrWhiteSpace(cuenta)) return;
            var limpia = cuenta!.Trim();
            if (salida.Count >= MaxUsers) return;
            if (vistos.Add(limpia)) salida.Add(limpia);
        }

        Añadir(consoleUser);
        foreach (var c in hiveAccounts ?? Enumerable.Empty<string?>()) Añadir(c);
        return salida;
    }

    /// <summary>
    /// Funde lo leído de varias cuentas en una sola lista de nombres.
    ///
    /// ⚠️ Es una UNIÓN, y el payload no dice de quién es cada una. Deliberado:
    /// la pregunta del check es "¿hay inventario de directivas?", no "¿qué se
    /// le aplica a Fulano?", y atribuir una directiva a una persona metería en
    /// la evidencia justo lo que la limpieza del Sprint 4 sacó de ella.
    /// </summary>
    public static List<string> Union(IEnumerable<List<string>?> porCuenta)
    {
        var salida = new List<string>();
        var vistos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var lista in porCuenta ?? Enumerable.Empty<List<string>?>())
        {
            if (lista is null) continue;
            foreach (var n in lista)
            {
                if (string.IsNullOrWhiteSpace(n)) continue;
                if (vistos.Add(n)) salida.Add(n);
            }
        }
        return salida;
    }
}
