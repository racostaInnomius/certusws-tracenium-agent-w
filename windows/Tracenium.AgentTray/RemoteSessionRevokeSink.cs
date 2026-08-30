using System;
using System.IO;
using System.Text.Json;

namespace Tracenium.AgentTray;

/// <summary>
/// Canal bandeja → AgentCore para CORTAR una sesión de control remoto desde el
/// equipo del usuario (ADR-0012).
///
/// Mismo mecanismo que <see cref="CatalogInstallSink"/> y por el mismo motivo:
/// la bandeja corre como el usuario de consola y no puede escribir en el
/// directorio de estado compartido, cuya ACL es SYSTEM/Admin-write. Escribe en
/// su propio %LOCALAPPDATA%\Tracenium\, donde el servicio privilegiado sí lee.
///
/// La diferencia está en el ritmo del otro lado: AgentCore sondea el catálogo
/// cada 5 s, y este fichero cada 500 ms mientras haya sesión viva. No es un
/// capricho — es la distancia entre pulsar "detener" y dejar de ser observado.
/// Cinco segundos ahí se perciben como que el botón no funciona, y esa es
/// exactamente la sensación que un control de privacidad no puede permitirse.
/// </summary>
internal static class RemoteSessionRevokeSink
{
    private const string FileName = "remote-session-revoke.json";

    private static string FilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Tracenium",
            FileName);

    /// <summary>
    /// Pide cortar la sesión indicada.
    ///
    /// Lleva el sessionId a propósito: sin él, un fichero que quedara sin
    /// consumir mataría la SIGUIENTE sesión nada más abrirse, y el operador
    /// vería una desconexión sin causa aparente. AgentCore compara y descarta
    /// lo que no corresponda.
    /// </summary>
    public static void Write(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return;

        try
        {
            var dir = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var payload = new
            {
                sessionId,
                atUtc = DateTime.UtcNow.ToString("O"),
                // Para el registro de auditoría: el corte lo pidió una persona
                // en el endpoint, no un fallo de red. Que esos dos casos se
                // distingan es la mitad del valor de tener el control.
                by = Environment.UserName
            };

            // Temp + move, como el sink del catálogo: AgentCore sondea dos
            // veces por segundo y no puede toparse con un fichero a medio
            // escribir. Aquí importa más que allí, porque un JSON corrupto en
            // este canal significa un corte que no ocurre.
            var tempPath = FilePath + ".tmp";
            File.WriteAllText(tempPath, JsonSerializer.Serialize(payload));
            File.Move(tempPath, FilePath, overwrite: true);
        }
        catch
        {
            // Silencioso a propósito, igual que el sink del catálogo: la UI ya
            // refleja el intento y no hay nada útil que decirle al usuario
            // sobre un fallo de E/S en su perfil. El indicador seguirá
            // encendido, que es la señal honesta de que la sesión sigue viva.
        }
    }
}
