namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Desinstalar lo que un usuario instaló en SU perfil (ADR-0019, paso 3):
/// las decisiones, sin Win32.
///
/// ⚠️ VIVE APARTE PARA PODER PROBARSE fuera de Windows, como el resto de los
/// *Shape. `UserScopedUninstall` hace lo que necesita el sistema —leer
/// HKEY_USERS, buscar la sesión, lanzar con el token del usuario— y aquí queda
/// lo que se puede equivocar SIN DAR ERROR:
///
///   · Qué comando se ejecuta. Sólo uno silencioso: como el usuario, un
///     desinstalador con ventana le abre un diálogo en su escritorio, a media
///     mañana, que no pidió. Sin variante silenciosa se rechaza.
///   · Cómo se resume un equipo con varios perfiles. Si Zoom está en dos
///     perfiles y uno no tiene sesión, «éxito» mentiría y «fallo» también.
/// </summary>
public static class UserUninstallShape
{
    /// <summary>Una entrada de desinstalación encontrada en el perfil de un usuario.</summary>
    public sealed record UserEntry(
        string Sid,
        string KeyName,
        string? DisplayName,
        string? UninstallString,
        string? QuietUninstallString,
        bool WindowsInstaller,
        string? DisplayVersion = null);

    /// <summary>El comando a lanzar, o por qué no se lanza ninguno.</summary>
    public sealed record CommandChoice(string? CommandLine, string? Refusal);

    public const string NoSilentUninstall = "no_silent_uninstall";
    public const string UserNotLoggedOn = "user_not_logged_on";

    /// <summary>
    /// El comando con el que se quita esta entrada, sólo si es silencioso.
    ///
    /// ⚠️ La línea se pasa ENTERA, tal cual la registró el instalador
    /// (<c>"C:\Users\ana\...\Uninstall RingCentral.exe" /currentuser /S</c>).
    /// Partirla en ejecutable + argumentos y volver a unirla es donde se rompen
    /// las comillas de una ruta con espacios.
    /// </summary>
    public static CommandChoice ChooseCommand(UserEntry e)
    {
        var quiet = e.QuietUninstallString?.Trim();
        if (!string.IsNullOrEmpty(quiet)) return new CommandChoice(quiet, null);

        // Sin QuietUninstallString, pero el fabricante documenta la forma
        // silenciosa de SU desinstalador (OneDrive, Zoom, Chrome, WinRAR).
        var known = KnownSilentUninstall.For(e.UninstallString);
        if (known != null) return new CommandChoice(known, null);

        // Un MSI por usuario sí tiene forma silenciosa aunque no registre
        // QuietUninstallString: msiexec /x con /qn. Pero SÓLO si el nombre de la
        // clave es de verdad un ProductCode: `msiexec /x` con basura no falla
        // ruidosamente — quita otra cosa, o nada.
        if (e.WindowsInstaller && UninstallIdentity.LooksLikeProductCode(e.KeyName))
        {
            return new CommandChoice($"msiexec.exe /x {e.KeyName.Trim()} /qn /norestart", null);
        }

        return new CommandChoice(null, NoSilentUninstall);
    }

    public enum ProfileStatus { Removed, Failed, NotLoggedOn, NoSilentUninstall }

    /// <summary>
    /// Los códigos que Windows Installer (y casi todo desinstalador) usa para
    /// «hecho»: 0, 3010 (hecho, falta reiniciar) y 1641 (hecho, reinicio en
    /// marcha). El mismo criterio que el agente aplica en src/plugins/sdp/reboot.ts.
    /// </summary>
    public static ProfileStatus ClassifyExit(int exitCode) =>
        exitCode == 0 || exitCode == 3010 || exitCode == 1641 ? ProfileStatus.Removed : ProfileStatus.Failed;

    /// <summary>Lo que pasó en UN perfil. `Label` es el nombre de la cuenta si se pudo resolver, o el SID.</summary>
    public sealed record ProfileResult(string Label, ProfileStatus Status, int? ExitCode);

    /// <summary>El veredicto del equipo entero.</summary>
    /// <param name="ErrorCode">Una negativa del agente (no se ejecutó lo que había que ejecutar), o null.</param>
    /// <param name="ExitCode">Sin negativa: el código que el agente calificará (éxito, reinicio o fallo).</param>
    public sealed record Outcome(string? ErrorCode, int ExitCode, string Summary);

    /// <summary>
    /// Resume varios perfiles en un veredicto, por orden de gravedad:
    ///
    ///   1. Un desinstalador que FALLÓ manda: es un fallo real, y lo que vaya
    ///      detrás (un perfil sin sesión) no lo tapa.
    ///   2. Uno sin variante silenciosa → negativa `no_silent_uninstall`.
    ///   3. Uno sin sesión → negativa `user_not_logged_on`: no hay token con el
    ///      que lanzarlo, y hacerlo como SYSTEM no es una alternativa.
    ///   4. Todos quitados → el código más significativo de reinicio (1641 >
    ///      3010 > 0), para que el agente no pierda un «hace falta reiniciar».
    ///
    /// ⚠️ SIN ENTRADAS NO ES UN ERROR: el pre-detect ya dijo que estaba, así
    /// que llegar aquí sin nada significa que se fue entre medias. Se devuelve
    /// éxito y el post-detect del agente lo confirma — o lo desmiente.
    ///
    /// El resumen lista TODOS los perfiles: con dos perfiles y una negativa, el
    /// operador tiene que saber que en el otro sí se desinstaló.
    /// </summary>
    public static Outcome Aggregate(IReadOnlyList<ProfileResult> results)
    {
        if (results.Count == 0)
        {
            return new Outcome(null, 0, "not installed in any signed-in user's profile");
        }

        var summary = string.Join("; ", results.Select(Describe));

        var failed = results.FirstOrDefault(r => r.Status == ProfileStatus.Failed);
        if (failed != null) return new Outcome(null, failed.ExitCode ?? 1, summary);

        if (results.Any(r => r.Status == ProfileStatus.NoSilentUninstall))
        {
            return new Outcome(NoSilentUninstall, 0, summary);
        }
        if (results.Any(r => r.Status == ProfileStatus.NotLoggedOn))
        {
            return new Outcome(UserNotLoggedOn, 0, summary);
        }

        var codes = results.Select(r => r.ExitCode ?? 0).ToList();
        var exit = codes.Contains(1641) ? 1641 : codes.Contains(3010) ? 3010 : 0;
        return new Outcome(null, exit, summary);
    }

    private static string Describe(ProfileResult r) => r.Status switch
    {
        ProfileStatus.Removed => $"{r.Label}: removed (exit {r.ExitCode ?? 0})",
        ProfileStatus.Failed => $"{r.Label}: uninstaller failed (exit {r.ExitCode ?? 1})",
        ProfileStatus.NotLoggedOn => $"{r.Label}: not signed in — nothing was run for this user",
        ProfileStatus.NoSilentUninstall => $"{r.Label}: no silent uninstaller registered — nothing was run",
        _ => $"{r.Label}: {r.Status}",
    };

}
