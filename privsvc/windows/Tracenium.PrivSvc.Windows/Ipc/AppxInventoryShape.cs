using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Qué paquetes de la Store entran en el inventario, y con qué versión.
///
/// ⚠️ EL DEFECTO (T1/T111, sep). El PrivSvc llamaba a <c>Get-AppxPackage</c>
/// SIN <c>-AllUsers</c>, y corre como SYSTEM: veía los paquetes de SYSTEM, no
/// los de las personas. Codex, Claude, Spotify, WhatsApp o Disney+ asomaban
/// en algún escaneo y desaparecían en el siguiente — Activity los daba por
/// instalados y desinstalados una y otra vez (Emilio: Codex 3 veces en una
/// semana; DESKTOP-EA-AMM: Disney+ 6 veces con UNA sola versión). En el
/// inventario de Emilio sólo quedaban 8 paquetes de sistema.
///
/// Con <c>-AllUsers</c> el estado sale del repositorio de AppX, no de la
/// sesión: estable, y con cada usuario y su <c>InstallState</c>. Cuenta un
/// paquete si alguna PERSONA lo tiene <c>Installed</c> (no sólo Staged, que
/// es una actualización a medio desplegar, ni sólo SYSTEM/servicios).
/// </summary>
public static class AppxInventoryShape
{
    /// Cuentas de persona: locales/dominio (S-1-5-21-…) y Entra ID
    /// (S-1-12-1-…). Fuera SYSTEM, LocalService, NetworkService y compañía.
    public static bool IsPersonSid(string? sid) =>
        !string.IsNullOrWhiteSpace(sid) &&
        System.Text.RegularExpressions.Regex.IsMatch(sid.Trim(), @"^S-1-(5-21|12-1)(-\d+){4}$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <param name="users">«SID|InstallState» por cada usuario del paquete.</param>
    public static bool InstalledForPerson(IEnumerable<string> users) =>
        users.Any(u =>
        {
            var sep = u.LastIndexOf('|');
            if (sep <= 0) return false;
            return IsPersonSid(u[..sep]) &&
                   u[(sep + 1)..].Trim().Equals("Installed", StringComparison.OrdinalIgnoreCase);
        });

    /// El campo <c>users</c> tal como llega de ConvertTo-Json: una cadena
    /// «SID|Estado;SID|Estado» (lo que emite el PrivSvc), o un array por si
    /// alguien lo cambia. Cualquier otra cosa → nadie.
    public static List<string> ReadUsers(object? value) => value switch
    {
        null => new List<string>(),
        string s => Split(s),
        JsonElement { ValueKind: JsonValueKind.String } e => Split(e.GetString()),
        JsonElement { ValueKind: JsonValueKind.Array } e => e.EnumerateArray()
            .Where(x => x.ValueKind == JsonValueKind.String)
            .SelectMany(x => Split(x.GetString()))
            .ToList(),
        IEnumerable<string> list => list.SelectMany(Split).ToList(),
        _ => new List<string>()
    };

    private static List<string> Split(string? s) =>
        (s ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    /// <summary>
    /// Un paquete por familia, en su versión MÁS ALTA. Con <c>-AllUsers</c>
    /// dos usuarios pueden tener versiones distintas de la misma app; las dos
    /// comparten install_id en el agente (la identidad no lleva versión) y,
    /// sin elegir aquí, cada escaneo podía quedarse con una distinta.
    /// </summary>
    public static List<Dictionary<string, object?>> LatestPerFamily(IEnumerable<Dictionary<string, object?>> packages)
    {
        return packages
            .GroupBy(p => (Str(p, "packageFamilyName") ?? Str(p, "name") ?? "").ToLowerInvariant())
            .Select(g => g
                .OrderByDescending(p => ParseVersion(Str(p, "version")))
                .ThenBy(p => Str(p, "version") ?? "", StringComparer.Ordinal)
                .First())
            .OrderBy(p => (Str(p, "packageFamilyName") ?? Str(p, "name") ?? "").ToLowerInvariant(), StringComparer.Ordinal)
            .ToList();
    }

    private static string? Str(Dictionary<string, object?> p, string key) =>
        p.TryGetValue(key, out var v) && v != null ? v.ToString() : null;

    private static Version ParseVersion(string? v) =>
        Version.TryParse(v, out var parsed) ? parsed : new Version(0, 0);
}
