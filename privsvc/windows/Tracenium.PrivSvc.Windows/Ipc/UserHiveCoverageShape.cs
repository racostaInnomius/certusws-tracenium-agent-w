namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Qué perfiles de usuario se pudieron MIRAR en un inventario de software.
///
/// ⚠️ «No lo vi» NO es «no está». Las apps instaladas por usuario viven en el
/// NTUSER.DAT de cada perfil, y HKEY_USERS sólo lo tiene montado mientras hay
/// sesión. Sin esta lista, el agente comparaba contra la línea base y daba por
/// DESINSTALADO todo lo de un usuario en cuanto cerraba sesión, y por
/// reinstalado al volver: Teams, RingCentral, Zoom y OneDrive «entraban y
/// salían» cada ~12 h en bloque en T111 (DESKTOP-CAST-PV, 25–27 sep).
///
/// Por eso se nombran los perfiles que EXISTEN (ProfileList) y no se leyeron:
/// de ésos el agente conserva lo que ya sabía. Un perfil borrado del equipo
/// deja de estar en ProfileList y sus apps sí se van — que es la verdad.
/// </summary>
public static class UserHiveCoverageShape
{
    /// Perfiles de persona que existen en el equipo y cuyo hive no se leyó
    /// (sin sesión, o ilegible). Orden estable, sin duplicados, sin SYSTEM ni
    /// servicios.
    public static List<string> Unread(IEnumerable<string> profileSids, IEnumerable<string> readSids)
    {
        var read = new HashSet<string>(readSids, StringComparer.OrdinalIgnoreCase);
        return profileSids
            .Where(UserRegistryProbeShape.IsUserProfileHive)
            .Where(s => !read.Contains(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
