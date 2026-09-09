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
}
