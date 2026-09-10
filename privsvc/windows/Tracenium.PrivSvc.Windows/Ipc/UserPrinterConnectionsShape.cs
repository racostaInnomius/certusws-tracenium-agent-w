// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/UserPrinterConnectionsShape.cs
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

// ── POR QUÉ ESTE FICHERO ESTÁ PARTIDO ───────────────────────────────
//
// Aquí vive sólo lo que NO toca Windows: decodificar el nombre de la clave,
// sacar el servidor y fundir sin duplicar. El recorrido del registro está en
// UserPrinterConnections.cs. La suite de pruebas es `net8.0` a secas y compila
// ficheros sueltos —misma convención que SeceditShape / RegistryProbeShape—,
// así que partirlo es lo que permite que estas reglas se prueben en un Mac.
//
// Y merecen prueba: un nombre mal decodificado no falla, se guarda, y aparece
// como una impresora fantasma en el inventario de un cliente.

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>Una conexión de impresora de red de un usuario.</summary>
public sealed record UserPrinterConnection(string Name, string? Server, string Sid);

public static class UserPrinterConnectionsShape
{
    /// <summary>Qué se pudo mirar. Nunca se colapsa en "cero impresoras".</summary>
    public const string ScopeCollected = "collected";
    public const string ScopeNoUserHive = "no_user_hive";
    public const string ScopeUnavailable = "unavailable";

    /// <summary>
    /// El nombre UNC de una conexión, a partir del nombre de su subclave.
    ///
    /// Windows guarda `\\SERVIDOR\Cola` como `,,SERVIDOR,Cola`: sustituye las
    /// barras por comas porque una clave del registro no puede llevar `\`.
    /// Deshacerlo es la única forma de recuperar el nombre cuando el valor
    /// `Printer` falta — pasa con conexiones creadas por GPO antiguas.
    ///
    /// Devuelve null si no queda nada reconocible: inventar un nombre sería
    /// peor que no reportar la impresora.
    /// </summary>
    public static string? UncFromKeyName(string? keyName)
    {
        if (string.IsNullOrWhiteSpace(keyName)) return null;
        var unc = keyName.Replace(',', '\\');
        // `,,SERVIDOR,Cola` -> `\\SERVIDOR\Cola`. Sin las dos barras iniciales
        // no es una cola de red y no es asunto de este lector.
        if (!unc.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        var resto = unc.Substring(2);
        if (resto.Length == 0 || !resto.Contains('\\')) return null;
        return unc;
    }

    /// <summary>El servidor de una UNC, o null si no tiene forma de UNC.</summary>
    public static string? ServerFromUnc(string? unc)
    {
        if (string.IsNullOrWhiteSpace(unc) || !unc.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        var resto = unc.Substring(2);
        var corte = resto.IndexOf('\\');
        if (corte <= 0) return null;
        return resto.Substring(0, corte);
    }

    /// <summary>
    /// Funde las conexiones de usuario con lo que vio la máquina.
    ///
    /// Se comparan por nombre y sin distinguir mayúsculas: la misma cola puede
    /// salir por las dos vías si está instalada a nivel de máquina Y conectada
    /// por el usuario, y contarla dos veces inflaría el inventario.
    /// </summary>
    public static List<object> MergeByName(
        IEnumerable<string> machineNames,
        IEnumerable<UserPrinterConnection> userItems)
    {
        var vistos = new HashSet<string>(machineNames.Where(n => !string.IsNullOrWhiteSpace(n)),
                                          StringComparer.OrdinalIgnoreCase);
        var extra = new List<object>();
        foreach (var c in userItems)
        {
            if (!vistos.Add(c.Name)) continue;
            extra.Add(new
            {
                name = c.Name,
                // ⚠️ Driver y estado NO se inventan. La conexión del registro no
                // los trae, y rellenarlos con "Unknown" los volvería
                // indistinguibles de un dato leído de verdad.
                driverName = (string?)null,
                portName = c.Server is null ? (string?)null : $@"\\{c.Server}",
                isDefault = false,
                shared = false,
                location = (string?)null,
                comment = (string?)null,
                printerStatus = (string?)null,
                source = "user_connection"
            });
        }
        return extra;
    }
}
