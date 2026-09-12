// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/LoggedOnUsers.cs
//
// Las cuentas con perfil cargado, leídas de HKEY_USERS. Ver
// LoggedOnUsersShape.cs para el porqué; aquí sólo está lo que toca Windows.

using System.Security.Principal;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class LoggedOnUsers
{
    /// <summary>
    /// Cuentas (`DOMINIO\usuario`) de los SID interactivos con hive cargada.
    ///
    /// ⚠️ Falla en silencio hacia lista vacía: no poder enumerar no puede
    /// tumbar la evaluación de cumplimiento entera. El llamador distingue
    /// "no hay nadie" de "no se pudo leer" por su propio motivo.
    /// </summary>
    public static List<string> InteractiveAccounts()
    {
        var salida = new List<string>();
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            foreach (var sid in users.GetSubKeyNames())
            {
                // Mismo criterio que CdpUserCertificates y las impresoras:
                // HKEY_USERS trae también SYSTEM, LOCAL SERVICE, .DEFAULT y
                // los `_Classes`, y ninguno es una persona.
                if (!CdpUserCertificates.IsInteractiveUserSid(sid)) continue;
                try
                {
                    // gpresult quiere el NOMBRE de cuenta, no el SID.
                    var cuenta = new SecurityIdentifier(sid)
                        .Translate(typeof(NTAccount)).Value;
                    if (!string.IsNullOrWhiteSpace(cuenta)) salida.Add(cuenta);
                }
                catch
                {
                    // Un SID que ya no resuelve —cuenta borrada del dominio,
                    // DC inalcanzable— se salta. Mandarlo tal cual a gpresult
                    // sólo gastaría uno de los tres intentos.
                }
            }
        }
        catch
        {
            return new List<string>();
        }
        return salida;
    }
}
