using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Convierte un log verboso de Windows Installer en UNA línea.
///
/// ⚠️ EXTRAE, NO ENVÍA. Un `/l*v` vuelca todas las propiedades de la sesión:
/// nombre de máquina, usuario, rutas de perfil, y cualquier cosa que un
/// operador haya metido en silentInstallArgs. Subir el log entero sería
/// telemetría con PII sobre la que nadie decidió. Lo que sale de aquí es un
/// código canónico y, como mucho, una frase del propio instalador — acotada a
/// <see cref="MaxDetailChars"/> y sin volcado de propiedades.
///
/// ⚠️ Y ES DETERMINISTA, NO IA. Los logs de MSI tienen gramática fija:
/// "Installation success or error status: N", "Note: 1: &lt;código&gt;",
/// "-- Installation failed", "Return value 3". El valor está en leerla, no en
/// interpretarla: un modelo aquí sería más caro, más lento y menos exacto que
/// estas reglas. La IA tiene sitio en la cola larga, DESPUÉS de esto y con
/// esto como entrada.
/// </summary>
public static class MsiLogDiagnosis
{
    /// <summary>Cuánto del final del log miramos. El desenlace de una sesión
    /// de MSI está siempre en las últimas líneas; el principio es inventario de
    /// tablas. Acotarlo evita cargar un log de decenas de MB en memoria.</summary>
    private const int TailBytes = 64 * 1024;

    private const int MaxDetailChars = 160;

    /// <summary>
    /// Códigos que Windows Installer devuelve y lo que significan de verdad.
    ///
    /// No es una tabla de traducción: es la diferencia entre «falló» y «ya
    /// estaba instalado, no lo vuelvas a intentar». Los que están aquí cubren
    /// la inmensa mayoría de lo que se ve en campo.
    /// </summary>
    private static readonly Dictionary<string, string> KnownCodes = new()
    {
        ["1603"] = "fatal error during installation",
        ["1618"] = "another installation is already in progress",
        ["1619"] = "the installer package could not be opened",
        ["1620"] = "the installer package could not be read",
        ["1625"] = "the installation is blocked by system policy",
        ["1638"] = "another version of this product is already installed",
        ["1639"] = "invalid command line argument",
        ["1641"] = "the installer started a restart",
        ["1708"] = "the installation failed",
        // 1729 es el que costó la tarde: sale cuando `/i` cae sobre un
        // ProductCode YA instalado, así que MSI no instala sino que
        // reconfigura — y sin REINSTALL/REINSTALLMODE la reconfiguración
        // muere y arrastra el 1603.
        ["1729"] = "the product is already installed and was reconfigured, not installed",
        ["3010"] = "the installation succeeded but a restart is required",
    };

    /// <summary>
    /// Lee la cola del log y devuelve la causa, o null si no hay nada legible.
    /// Nunca lanza: un diagnóstico que revienta el instalador que intenta
    /// explicar sería peor que no tenerlo.
    /// </summary>
    public static string? Extract(string logPath)
    {
        try
        {
            var tail = ReadTail(logPath);
            if (string.IsNullOrWhiteSpace(tail)) return null;
            return Diagnose(tail);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// La parte pura, separada para poder probarla sin escribir ficheros.
    /// </summary>
    public static string? Diagnose(string tail)
    {
        var lines = tail.Split('\n');

        string? statusCode = null;
        string? noteCode = null;
        string? failedProduct = null;

        // De atrás hacia delante: en una sesión con reintentos internos, el
        // desenlace que importa es el ÚLTIMO, y leer hacia delante se queda
        // con el primero.
        for (var i = lines.Length - 1; i >= 0; i--)
        {
            var line = lines[i].TrimEnd('\r');

            if (statusCode == null)
            {
                // "Installation success or error status: 1603."
                // "Reconfiguration success or error status: 1603."
                var marker = " success or error status: ";
                var at = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (at >= 0)
                {
                    statusCode = ReadDigits(line, at + marker.Length);
                    // La línea dice también QUÉ operación fue. «Reconfigured»
                    // sobre un `/i` es la pista de que el producto ya estaba:
                    // sin ella, 1603 es sólo «falló algo».
                    if (line.IndexOf("Reconfigur", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return Compose(statusCode, "the product was already installed, so Windows Installer reconfigured it instead of installing");
                    }
                }
            }

            if (noteCode == null)
            {
                // "Note: 1: 1729 " — el código interno del error, que suele ser
                // más específico que el status final.
                var marker = "Note: 1: ";
                var at = line.IndexOf(marker, StringComparison.Ordinal);
                if (at >= 0)
                {
                    var code = ReadDigits(line, at + marker.Length);
                    if (code != null && KnownCodes.ContainsKey(code)) noteCode = code;
                }
            }

            if (failedProduct == null)
            {
                // "Product: Google Chrome -- Configuration failed."
                var at = line.IndexOf("Product: ", StringComparison.Ordinal);
                if (at >= 0 && line.IndexOf(" -- ", StringComparison.Ordinal) > at)
                {
                    failedProduct = line.Substring(at + "Product: ".Length).Trim();
                }
            }

            if (statusCode != null && noteCode != null) break;
        }

        // El código interno gana al status: 1729 dice POR QUÉ, 1603 sólo dice
        // que sí.
        var chosen = noteCode ?? statusCode;
        if (chosen == null) return failedProduct == null ? null : Truncate(failedProduct);

        return Compose(chosen, KnownCodes.TryGetValue(chosen, out var meaning) ? meaning : failedProduct);
    }

    private static string Compose(string? code, string? detail)
    {
        if (code == null) return Truncate(detail ?? "");
        return string.IsNullOrWhiteSpace(detail) ? code : $"{code}: {Truncate(detail!)}";
    }

    private static string Truncate(string s)
    {
        s = s.Trim();
        return s.Length <= MaxDetailChars ? s : s.Substring(0, MaxDetailChars);
    }

    private static string? ReadDigits(string line, int from)
    {
        var sb = new StringBuilder();
        for (var i = from; i < line.Length && char.IsDigit(line[i]); i++) sb.Append(line[i]);
        return sb.Length == 0 ? null : sb.ToString();
    }

    /// <summary>
    /// Las últimas <see cref="TailBytes"/> del fichero. Los logs de MSI son
    /// UTF-16LE cuando msiexec los escribe, así que se decodifica con
    /// detección de BOM; leer sólo la cola puede partir un carácter, y por eso
    /// se alinea a par de bytes.
    /// </summary>
    private static string ReadTail(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var length = fs.Length;
        if (length == 0) return "";

        if (length <= TailBytes)
        {
            using var whole = new StreamReader(fs, Encoding.Default, detectEncodingFromByteOrderMarks: true);
            return whole.ReadToEnd();
        }

        var start = length - TailBytes;
        if (start % 2 != 0) start++; // no partir una unidad UTF-16
        fs.Seek(start, SeekOrigin.Begin);

        var buf = new byte[length - start];
        var read = fs.Read(buf, 0, buf.Length);

        // Sin BOM (estamos a media corriente) hay que elegir. Un log de MSI
        // escrito por msiexec es UTF-16LE; el heurístico barato es que los
        // bytes impares sean cero en texto ASCII.
        var looksUtf16 = read > 8 && buf[1] == 0 && buf[3] == 0 && buf[5] == 0;
        return looksUtf16
            ? Encoding.Unicode.GetString(buf, 0, read)
            : Encoding.UTF8.GetString(buf, 0, read);
    }
}
