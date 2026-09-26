// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AcmeHttp01Shape.cs
//
// ADR-0033 F2b — la parte PURA de `cdp.acme.http01`: qué se acepta y dónde se
// escribe. Sin E/S, para que corra en los tests en cualquier plataforma.
// Gemelo de privsvc/shared/acme-http01.ts (macOS y Linux): la misma regla en
// tres sitios, a propósito paralela.
//
// Publicar un desafío HTTP-01 es escribir un fichero en el webroot de un
// servidor web. Es una primitiva de escritura, y por eso se estrecha todo lo
// posible —porque un control plane comprometido es el adversario que ADR-0011
// modela—:
//
//   · el NOMBRE del fichero es el token de la CA: sólo base64url, 16-256;
//   · el CONTENIDO es `token.huella`, con la huella SHA-256 de 43 caracteres:
//     no se puede usar para plantar un script ni una página;
//   · el DIRECTORIO es siempre `<webroot>\.well-known\acme-challenge`;
//   · el webroot tiene que estar bajo una raíz permitida. Las raíces por
//     defecto son las de IIS; el administrador del equipo puede añadir más en
//     un fichero LOCAL (`acme-webroots.txt`) que el control plane no escribe.

using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AcmeHttp01Shape
{
    private static readonly Regex TokenRe = new("^[A-Za-z0-9_-]{16,256}$", RegexOptions.Compiled);
    private static readonly Regex ThumbprintRe = new("^[A-Za-z0-9_-]{43}$", RegexOptions.Compiled);

    public static bool IsValidToken(string? token) => token != null && TokenRe.IsMatch(token);

    /// <summary>`token.huella`, y el token tiene que ser EL MISMO que da nombre al fichero.</summary>
    public static bool IsValidKeyAuthorization(string? token, string? keyAuthorization)
    {
        if (!IsValidToken(token) || keyAuthorization == null) return false;
        var prefix = token + ".";
        if (!keyAuthorization.StartsWith(prefix, StringComparison.Ordinal)) return false;
        return ThumbprintRe.IsMatch(keyAuthorization.Substring(prefix.Length));
    }

    /// <summary>Raíces por defecto: las de IIS bajo la unidad del sistema.</summary>
    public static List<string> DefaultRoots(string systemDrive)
    {
        var drive = string.IsNullOrWhiteSpace(systemDrive) ? "C:" : systemDrive.TrimEnd('\\');
        return new List<string> { drive + @"\inetpub" };
    }

    /// <summary>Raíces extra del fichero local: una ruta absoluta por línea; `#` comenta.</summary>
    public static List<string> ParseExtraRoots(string? fileContent)
    {
        var outp = new List<string>();
        if (string.IsNullOrEmpty(fileContent)) return outp;
        foreach (var raw in fileContent.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#")) continue;
            // Sólo absolutas con unidad: una relativa dependería del directorio de trabajo del servicio.
            if (!Regex.IsMatch(line, @"^[A-Za-z]:\\")) continue;
            outp.Add(line.TrimEnd('\\'));
        }
        return outp;
    }

    /// <summary>
    /// ¿Está `webroot` bajo alguna raíz? Se compara la ruta NORMALIZADA (sin
    /// `..`) y exigiendo separador, para que `C:\inetpub-evil` no pase por ser
    /// prefijo de `C:\inetpub`. Sin distinguir mayúsculas, como NTFS.
    /// </summary>
    public static bool IsUnderAllowedRoot(string normalizedWebroot, IEnumerable<string> roots)
    {
        var w = normalizedWebroot.TrimEnd('\\');
        foreach (var r in roots)
        {
            var root = r.TrimEnd('\\');
            if (w.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;
            if (w.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static string ChallengeDir(string normalizedWebroot) =>
        normalizedWebroot.TrimEnd('\\') + @"\.well-known\acme-challenge";

    /// <summary>
    /// Normalización SIN tocar el disco (Path.GetFullPath quita `..` y `.`).
    /// Rechaza lo que no sea absoluto con unidad: rutas UNC incluidas — un
    /// webroot en un recurso compartido haría que el servicio escribiera en
    /// otra máquina.
    /// </summary>
    public static string? NormalizeWebroot(string? webroot)
    {
        if (string.IsNullOrWhiteSpace(webroot)) return null;
        var w = webroot.Trim().Replace('/', '\\');
        if (!Regex.IsMatch(w, @"^[A-Za-z]:\\")) return null;
        if (w.Contains('\0')) return null;
        // `..` se resuelve a mano: Path.GetFullPath fuera de Windows no
        // entiende rutas con unidad, y esto tiene que probarse en cualquier
        // plataforma.
        var parts = new List<string>();
        foreach (var seg in w.Substring(3).Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg == ".") continue;
            if (seg == "..")
            {
                if (parts.Count == 0) return null;
                parts.RemoveAt(parts.Count - 1);
                continue;
            }
            parts.Add(seg);
        }
        return w.Substring(0, 2).ToUpperInvariant() + "\\" + string.Join("\\", parts);
    }
}
