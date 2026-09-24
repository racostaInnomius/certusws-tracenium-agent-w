namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Partir un `UninstallString` del registro en ejecutable + argumentos.
///
/// ── Por qué esto merece un fichero y pruebas ─────────────────────────────
///
/// 🔴 CAMPO, 24-sep, T111: TODAS las desinstalaciones de WinRAR fallaron con
///
///     An error occurred trying to start process 'C:\Program'
///
/// WinRAR registra su desinstalador SIN COMILLAS:
///
///     C:\Program Files\WinRAR\uninstall.exe
///
/// y el parseo anterior, cuando la línea no empezaba por comilla, cortaba por
/// el PRIMER ESPACIO: ejecutable `C:\Program`, argumento
/// `Files\WinRAR\uninstall.exe`. No es un caso raro — «Program Files» tiene un
/// espacio, así que le pasa a cualquier desinstalador sin comillas instalado
/// en su sitio.
///
/// ── Cómo se resuelve ─────────────────────────────────────────────────────
///
/// Igual que lo resuelve Windows en `CreateProcess` cuando la línea no viene
/// entrecomillada: se prueban los cortes de izquierda a derecha y gana el
/// PRIMER prefijo que existe como fichero (probando también con `.exe`).
///
/// ⚠️ Se mira el DISCO, no se adivina por la forma de la ruta: sólo el equipo
/// sabe si `C:\Program Files\WinRAR\uninstall.exe` existe o si el ejecutable
/// era `C:\Program.exe` con un argumento detrás. Por eso la comprobación se
/// inyecta: así esta decisión se prueba fuera de Windows.
/// </summary>
public static class UninstallCommandParse
{
    /// <summary>
    /// `"C:\App\u.exe" /S` o `C:\Program Files\App\u.exe /S` → (fichero, args).
    /// </summary>
    /// <param name="fileExists">Si esa ruta existe en el equipo. Inyectable para poder probarlo.</param>
    public static (string File, List<string> Args) Split(string command) =>
        Split(command, System.IO.File.Exists);

    /// <inheritdoc cref="Split(string)"/>
    public static (string File, List<string> Args) Split(string command, Func<string, bool> fileExists)
    {
        var trimmed = (command ?? "").Trim();
        if (trimmed.Length == 0) return ("", new List<string>());

        // Entrecomillado: el propio instalador ya dijo dónde acaba la ruta.
        if (trimmed.StartsWith("\""))
        {
            var end = trimmed.IndexOf('"', 1);
            if (end < 0) return (trimmed.Trim('"'), new List<string>());
            var file = trimmed.Substring(1, end - 1);
            var rest = trimmed.Substring(end + 1).Trim();
            return (file, rest.Length > 0 ? SplitArgs(rest) : new List<string>());
        }

        // Sin comillas: el corte lo decide el disco, no el primer espacio.
        for (var i = 0; i < trimmed.Length; i++)
        {
            if (!char.IsWhiteSpace(trimmed[i])) continue;
            var candidate = trimmed.Substring(0, i);
            var resolved = Resolve(candidate, fileExists);
            if (resolved != null)
            {
                var rest = trimmed.Substring(i + 1).Trim();
                return (resolved, rest.Length > 0 ? SplitArgs(rest) : new List<string>());
            }
        }

        // Ningún corte existe: o la línea entera es el ejecutable, o el
        // ejecutable ya no está. En los dos casos, la línea ENTERA es mejor
        // respuesta que un trozo: si falla, el error nombra la ruta completa y
        // no un «C:\Program» que no explica nada.
        return (Resolve(trimmed, fileExists) ?? trimmed, new List<string>());
    }

    /// <summary>La ruta tal cual, o con `.exe` añadido, si alguna existe.</summary>
    private static string? Resolve(string candidate, Func<string, bool> fileExists)
    {
        if (fileExists(candidate)) return candidate;
        if (!candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            var withExe = candidate + ".exe";
            if (fileExists(withExe)) return withExe;
        }
        return null;
    }

    /// <summary>
    /// Trocear argumentos respetando las comillas (`/D="C:\Program Files\X"`
    /// es UN argumento).
    /// </summary>
    public static List<string> SplitArgs(string raw)
    {
        var args = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        foreach (var ch in raw ?? "")
        {
            if (ch == '"') { inQuotes = !inQuotes; continue; }
            if (char.IsWhiteSpace(ch) && !inQuotes)
            {
                if (current.Length > 0) { args.Add(current.ToString()); current.Clear(); }
                continue;
            }
            current.Append(ch);
        }
        if (current.Length > 0) args.Add(current.ToString());
        return args;
    }
}
