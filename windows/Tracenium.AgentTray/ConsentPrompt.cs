using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tracenium.AgentTray;

/// <summary>
/// Petición de consentimiento publicada por el agente (ADR-0012).
///
/// La escribe AgentCore en el directorio de estado compartido, junto a
/// tray-status.json — el mismo que esta bandeja ya vigila, así que llega en
/// milisegundos sin montar otro canal.
/// </summary>
internal sealed class ConsentRequest
{
    public string RequestId { get; set; } = "";
    public string SessionId { get; set; } = "";
    public string Kind { get; set; } = "view";
    public string Title { get; set; } = "Remote access request";
    public string[] Lines { get; set; } = Array.Empty<string>();
    public string AllowLabel { get; set; } = "Allow";
    public string DenyLabel { get; set; } = "Don't allow";
    public DateTime? ExpiresAtUtc { get; set; }

    /// <summary>
    /// ¿Se puede enseñar este aviso con honestidad?
    ///
    /// Sin id no hay a qué responder; sin texto, el diálogo pediría permiso
    /// sin decir para qué. Eso último es peor que no pedirlo: obtiene un "sí"
    /// que no significa nada y deja en auditoría que la persona aceptó.
    /// </summary>
    [JsonIgnore]
    public bool IsShowable =>
        !string.IsNullOrWhiteSpace(RequestId) && Lines.Length > 0;

    /// <summary>
    /// Una petición vencida NO se enseña.
    ///
    /// Sin esto, un fichero que quedara sin consumir —AgentCore reinicia
    /// mientras el diálogo está abierto— haría aparecer horas después un aviso
    /// pidiendo permiso para una sesión que ya terminó. La persona diría que
    /// sí a algo que no existe, y aprendería que estos avisos no significan
    /// nada.
    /// </summary>
    public bool IsExpired(DateTime nowUtc) =>
        ExpiresAtUtc.HasValue && nowUtc >= ExpiresAtUtc.Value;
}

/// <summary>
/// Lee la petición y publica la respuesta donde AgentCore la busca.
///
/// La respuesta va a %LOCALAPPDATA%\Tracenium\, no al directorio de estado:
/// esta bandeja corre como el usuario de consola y ese directorio tiene ACL
/// de solo SYSTEM/Admin. Mismo camino que RemoteSessionRevokeSink.
/// </summary>
internal static class ConsentPrompt
{
    private const string RequestFileName = "consent-request.json";
    private const string ResponseFileName = "consent-response.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// Ya atendida: evita reabrir el diálogo en cada refresco mientras
    /// AgentCore aún no ha retirado el fichero.
    private static string? _handledRequestId;
    private static bool _showing;

    private static string ResponsePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Tracenium",
            ResponseFileName);

    public static ConsentRequest? Read(string statusPath)
    {
        try
        {
            var dir = Path.GetDirectoryName(statusPath);
            if (string.IsNullOrEmpty(dir)) return null;
            var file = Path.Combine(dir, RequestFileName);
            if (!File.Exists(file)) return null;
            return JsonSerializer.Deserialize<ConsentRequest>(File.ReadAllText(file), JsonOptions);
        }
        catch
        {
            // Fichero a medio escribir o ilegible: no hay aviso que enseñar.
            // El agente agotará su plazo, que cuenta como negativa — la
            // dirección correcta para fallar.
            return null;
        }
    }

    /// <summary>
    /// Atiende la petición si procede. Idempotente: se la llama en cada
    /// refresco de la bandeja.
    /// </summary>
    public static void Handle(ConsentRequest? request)
    {
        if (request is null || !request.IsShowable) return;
        if (request.IsExpired(DateTime.UtcNow)) return;
        if (_handledRequestId == request.RequestId) return;
        // Un segundo diálogo encima del primero dejaría a la persona
        // contestando al de arriba sin ver lo que acepta debajo.
        if (_showing) return;

        _handledRequestId = request.RequestId;
        _showing = true;
        try
        {
            Present(request);
        }
        finally
        {
            _showing = false;
        }
    }

    private static void Present(ConsentRequest request)
    {
        var body = string.Join(Environment.NewLine, request.Lines);

        // ⚠️ El botón por defecto es el SEGUNDO (DefaultDesktopOnly + Button2),
        // o sea "No" ⇒ denegar. El botón por defecto se activa con Return y es
        // donde va la mano: en un diálogo que concede acceso a la pantalla de
        // alguien, la opción de reposo no puede ser la que concede. Un Return
        // distraído no debe regalar el control del equipo.
        //
        // MessageBox y no un Form propio: sale por encima de todo sin depender
        // de que la bandeja tenga el foco, y es la ventana que Windows ya sabe
        // colocar bien en cualquier DPI y cualquier tema.
        var result = MessageBox.Show(
            $"{body}{Environment.NewLine}{Environment.NewLine}" +
            $"{request.AllowLabel}?",
            request.Title,
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);

        Write(request.RequestId, result == DialogResult.Yes);
    }

    private static void Write(string requestId, bool approved)
    {
        try
        {
            var dir = Path.GetDirectoryName(ResponsePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            // ⚠️ Quién responde, no solo qué responde.
            //
            // La bandeja corre COMO el usuario, así que es el único punto del
            // sistema que sabe con certeza quién pulsó el botón. AgentCore
            // corre como SYSTEM y busca la respuesta en TODOS los perfiles,
            // porque no sabe de antemano quién está en consola — y eso
            // significaba que una respuesta escrita desde una sesión de RDP
            // valía como si la hubiera dado la persona sentada delante.
            //
            // El nombre del directorio de perfil no sirve para deducirlo: en
            // Windows no tiene por qué coincidir con el del usuario. Por eso
            // se dice explícitamente aquí.
            var payload = new
            {
                requestId,
                decision = approved ? "approved" : "denied",
                atUtc = DateTime.UtcNow.ToString("O"),
                respondedBy = Environment.UserName
            };

            // Temp + move: AgentCore sondea tres veces por segundo y no puede
            // toparse con un fichero a medio escribir.
            var tmp = ResponsePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(payload));
            File.Move(tmp, ResponsePath, overwrite: true);
        }
        catch
        {
            // Si no se puede escribir, AgentCore agota el plazo y eso cuenta
            // como negativa. Fallar hacia el "no" es la dirección correcta.
        }
    }
}
