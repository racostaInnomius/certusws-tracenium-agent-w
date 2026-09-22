using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// La identidad con la que se puede QUITAR una app del inventario (ADR-0019 F0).
///
/// ⚠️ VIVE APARTE PARA PODER PROBARSE. `SoftwareInventory` usa
/// `Microsoft.Win32.Registry` y por eso no entra en el proyecto de tests
/// (net8.0 a secas, para que la suite corra fuera de Windows). Estas dos
/// funciones son texto puro, así que se separan — misma convención que
/// `RegistryProbeShape`, `SeceditShape` y `AuditpolShape`.
///
/// Y merece la pena probarlas: una ruta de clave mal construida no falla, se
/// guarda. El error aparece meses después, cuando alguien intenta desinstalar
/// con ella y no encuentra nada — o peor, encuentra otra cosa.
/// </summary>
public static class UninstallIdentity
{
    /// <summary>
    /// ¿El nombre de la clave es un ProductCode de MSI?
    ///
    /// Windows Installer usa el GUID como nombre de clave, así que no hay que
    /// buscarlo en ningún otro sitio. Pero un instalador EXE pone ahí lo que
    /// quiere («Dropbox», «Zoom»), y por eso se COMPRUEBA en vez de asumir:
    /// inventarse un ProductCode es peor que no tenerlo, porque `msiexec /x`
    /// con basura no falla ruidosamente — desinstala otra cosa, o nada.
    /// </summary>
    public static bool LooksLikeProductCode(string? keyName)
    {
        if (string.IsNullOrWhiteSpace(keyName)) return false;
        var s = keyName!.Trim();
        // Forma canónica {8-4-4-4-12}: 36 + las dos llaves.
        if (s.Length != 38 || s[0] != '{' || s[^1] != '}') return false;
        return Guid.TryParse(s, out _);
    }

    /// <summary>
    /// Ruta completa de la clave de desinstalación, con hive y vista.
    ///
    /// ⚠️ EL PREFIJO NO ES DECORACIÓN. El colector lee CUATRO sitios: HKLM y
    /// HKCU, cada uno en vista de 64 y de 32 bits. Sin hive, dos apps distintas
    /// en hives distintos son indistinguibles.
    ///
    /// Y sobre todo: HKCU aquí es el del usuario bajo el que corre el PrivSvc
    /// —LocalSystem—, NO el humano sentado delante. Desinstalar una entrada de
    /// HKCU desde LocalSystem es otra operación, y a menudo imposible. Quien
    /// decida tiene que poder verlo sin adivinar.
    ///
    /// La vista de 32 bits va bajo `WOW6432Node` porque es donde el registro la
    /// expone de verdad: omitirlo daría una ruta que no existe para quien la
    /// lea después con la vista por defecto.
    /// </summary>
    public static string BuildKeyPath(bool localMachine, bool wow6432, string subName)
    {
        var root = localMachine ? "HKLM" : "HKCU";
        var wow = wow6432 ? @"WOW6432Node\" : "";
        return $@"{root}\SOFTWARE\{wow}Microsoft\Windows\CurrentVersion\Uninstall\{subName}";
    }

    /// <summary>
    /// Patrón ILIKE (`Foo App%`) → regex anclada e insensible a mayúsculas.
    /// Sólo `%` y `_` son comodines; el resto se escapa.
    ///
    /// ⚠️ UNA SOLA COPIA, y aquí. La usan la detección y la búsqueda del
    /// desinstalador en HKLM (Sdp) Y la búsqueda en los perfiles de usuario
    /// (UserScopedUninstall). Si divergieran, el pre-detect diría «está» con un
    /// patrón y la desinstalación buscaría con otro — y no encontraría nada, o
    /// encontraría otra cosa. Vivía privada en Sdp; se mudó para poder
    /// compartirse y probarse.
    /// </summary>
    public static Regex LikeToRegex(string pattern)
    {
        var sb = new System.Text.StringBuilder("^");
        foreach (var ch in pattern)
        {
            switch (ch)
            {
                case '%': sb.Append(".*"); break;
                case '_': sb.Append('.'); break;
                default:
                    sb.Append(Regex.Escape(ch.ToString()));
                    break;
            }
        }
        sb.Append('$');
        return new Regex(sb.ToString(),
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Ruta de una app instalada POR USUARIO: <c>HKU\&lt;SID&gt;\...</c>.
    ///
    /// ⚠️ El SID va en la ruta a propósito, y no como campo aparte: la lista de
    /// campos del inventario se copia a mano en tres sitios del lado TypeScript
    /// y un campo nuevo se pierde por el camino (le pasó a `uptimeSeconds`, a
    /// `antivirus.products` y a la propia identidad de desinstalación). La ruta
    /// ya viaja entera hasta el backend.
    ///
    /// Y es lo que le dice al backend que la desinstalación es DE UN USUARIO:
    /// no se lanza como SYSTEM (que no sabría de quién es el perfil, y además
    /// ejecutaría un comando que ese usuario puede escribir) sino con el token
    /// de su sesión — ver UserScopedUninstall.
    /// </summary>
    public static string BuildUserKeyPath(string sid, string subName) =>
        $@"HKU\{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{subName}";
}
