// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/UserPrinterConnections.cs
//
// Las impresoras de RED de los usuarios conectados, leídas de HKEY_USERS.
//
// ── EL PUNTO CIEGO QUE CIERRA ───────────────────────────────────────
//
// `Get-Printer` enumera las impresoras DE LA CUENTA QUE LLAMA. PrivSvc es un
// servicio: corre como LocalSystem, en la Sesión 0. Las impresoras de red no
// son objetos de máquina — son CONEXIONES POR USUARIO, guardadas en
// `HKCU\Printers\Connections`. Una cuenta de servicio no las ve.
//
// Medido en producción el 2026-09-10: 60 equipos Windows con el agente ≥1.1.62
// (que ya ejecuta el colector) y CERO filas de impresoras, mientras los macOS
// del mismo tenant sí reportaban por `cups`. El colector funcionaba; miraba
// donde no estaban.
//
// ⚠️ Y AgentCore tampoco habría servido: en Windows es un servicio WinSW sin
// `<serviceaccount>`, o sea LocalSystem, el mismo punto ciego.
//
// ── POR QUÉ EL REGISTRO Y NO IMPERSONAR ─────────────────────────────
//
// Impersonar al usuario conectado (WTSQueryUserToken + CreateProcessAsUser
// para relanzar PowerShell en su sesión) también funcionaría, pero es más
// privilegio, más piezas móviles y un servicio que toca sesiones de usuario.
// Leer HKEY_USERS no necesita ningún privilegio nuevo —LocalSystem ya puede— y
// es EXACTAMENTE la ruta que CdpUserCertificates ya usa en producción para el
// mismo problema con los certificados de usuario. Se reutiliza su criterio de
// SID interactivo en vez de escribir un segundo.
//
// ⚠️ LÍMITE DE COBERTURA, DICHO Y NO ESCONDIDO: sólo aparecen bajo HKEY_USERS
// las hives CARGADAS, que en la práctica son las de usuarios con sesión. Las
// impresoras de alguien desconectado no se ven. Por eso el resultado viaja con
// un `scope`: sin hives interactivas la respuesta es `no_user_hive` y NO una
// lista vacía — que se leería como "este equipo no tiene impresoras".

using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class UserPrinterConnections
{
    /// <summary>
    /// Lee las conexiones de todos los usuarios con hive cargada.
    ///
    /// ⚠️ `scope` distingue las tres cosas que hasta ahora eran la misma fila
    /// vacía: se leyó y no hay ninguna, no hay a quién leer, y no se pudo leer.
    /// </summary>
    public static (string Scope, List<UserPrinterConnection> Items) Collect()
    {
        var salida = new List<UserPrinterConnection>();
        var usuarios = 0;

        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            foreach (var sid in users.GetSubKeyNames())
            {
                // Mismo criterio que CdpUserCertificates: HKEY_USERS también
                // trae SYSTEM, LOCAL SERVICE, .DEFAULT y los `_Classes`, y
                // ninguno es la mesa de nadie.
                if (!CdpUserCertificates.IsInteractiveUserSid(sid)) continue;
                usuarios += 1;

                using var conexiones = users.OpenSubKey($@"{sid}\Printers\Connections");
                if (conexiones is null) continue;

                foreach (var clave in conexiones.GetSubKeyNames())
                {
                    string? nombre = null;
                    string? servidor = null;
                    using (var entrada = conexiones.OpenSubKey(clave))
                    {
                        // El valor `Printer` es el nombre autoritativo cuando
                        // está; el nombre de la clave es el respaldo.
                        nombre = entrada?.GetValue("Printer") as string;
                        servidor = entrada?.GetValue("Server") as string;
                    }
                    nombre ??= UserPrinterConnectionsShape.UncFromKeyName(clave);
                    if (string.IsNullOrWhiteSpace(nombre)) continue;

                    servidor = string.IsNullOrWhiteSpace(servidor)
                        ? UserPrinterConnectionsShape.ServerFromUnc(nombre)
                        : servidor!.TrimStart('\\');

                    salida.Add(new UserPrinterConnection(nombre!, servidor, sid));
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][UserPrinterConnections] ERROR: {ex.Message}");
            return (UserPrinterConnectionsShape.ScopeUnavailable, new List<UserPrinterConnection>());
        }

        // Cero usuarios con hive cargada NO es cero impresoras.
        return (usuarios == 0 ? UserPrinterConnectionsShape.ScopeNoUserHive : UserPrinterConnectionsShape.ScopeCollected, salida);
    }
}
