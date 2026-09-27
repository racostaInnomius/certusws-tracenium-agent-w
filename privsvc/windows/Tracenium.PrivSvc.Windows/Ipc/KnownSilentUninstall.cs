namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Desinstaladores que NO registran `QuietUninstallString` pero cuyo fabricante
/// documenta cómo ejecutarlos sin ventana.
///
/// ⚠️ SÓLO LO DOCUMENTADO, nada adivinado. Añadir `/S` a cualquier
/// «uninstall.exe» funcionaría con los NSIS y, con el resto, abriría una
/// ventana — en la sesión del usuario si la desinstalación es suya, o en la
/// sesión 0 (donde no la ve NADIE y el job se cuelga hasta el timeout) si es de
/// máquina. Una app que no esté aquí se ejecuta como venga.
///
/// ⚠️ ESTA TABLA TIENE UN GEMELO en el backend
/// (`modules/software-delivery/known-silent-uninstall.ts`), que la usa para la
/// vista previa. Si divergen, el portal enseña un comando y el equipo ejecuta
/// otro. Los tests de los dos lados usan las MISMAS líneas reales de T111.
///
/// Se casa sobre la ruta del ejecutable y el verbo, no sobre el nombre de la
/// app: el parámetro silencioso es del BINARIO.
/// </summary>
public static class KnownSilentUninstall
{
    /// <summary>La línea silenciosa documentada para este desinstalador, o null.</summary>
    public static string? For(string? uninstallString)
    {
        var cmd = uninstallString?.Trim();
        if (string.IsNullOrEmpty(cmd)) return null;

        // OneDrive por usuario: `OneDriveSetup.exe /uninstall` no pregunta
        // (así lo documenta Microsoft para quitarlo por script). 13 filas en T111.
        if (OneDrive.IsMatch(cmd)) return cmd;

        // Zoom por usuario: `%APPDATA%\Zoom\uninstall\Installer.exe /uninstall`
        // es la desinstalación por línea de comandos de Zoom. 17 filas en T111.
        if (Zoom.IsMatch(cmd)) return cmd;

        // Chrome por usuario: `setup.exe --uninstall` pide confirmación;
        // `--force-uninstall` la quita (switch documentado del instalador).
        if (Chrome.IsMatch(cmd))
        {
            return cmd.Contains("--force-uninstall", StringComparison.OrdinalIgnoreCase)
                ? cmd
                : cmd + " --force-uninstall";
        }

        // Edge: el MISMO instalador de Chromium, mismo modificador. 102 filas de
        // «setup.exe» en T111 son suyas.
        if (Edge.IsMatch(cmd))
        {
            return cmd.Contains("--force-uninstall", StringComparison.OrdinalIgnoreCase)
                ? cmd
                : cmd + " --force-uninstall";
        }

        // 🔴 WinRAR (campo 24-sep, T111): registra `C:\Program Files\WinRAR\
        // uninstall.exe` SIN comillas y SIN forma silenciosa. Su desinstalador
        // acepta `/S`, y sin él se abriría una ventana en la sesión 0 que no ve
        // NADIE — el job se quedaría colgado hasta el timeout.
        if (WinRar.IsMatch(cmd))
        {
            return cmd.Contains("/S", StringComparison.Ordinal) ? cmd : cmd + " /S";
        }

        // 🔴 AnyDesk (campo 26-sep, W11-JPR-LAB02). Registra
        // `"…\AnyDesk.exe" --uninstall`, y `--uninstall` ABRE UNA VENTANA: el
        // fabricante lo documenta como «opens a user interface to guide the
        // uninstallation process». Como SYSTEM esa ventana sale en la sesión 0,
        // no la ve nadie, y el job se colgó 1740 s × 5 intentos sin quitar nada.
        //
        // ⚠️ ES EL ÚNICO QUE SUSTITUYE EL VERBO. A WinRAR y Chrome se les AÑADE
        // un modificador a lo que ya hay; aquí `--uninstall` es justo la parte
        // mala. La forma documentada para script es `--remove`, y `--silent`
        // calla los mensajes: `anydesk.exe --silent --remove`.
        //
        // ⚠️ Se reconstruye desde cero en vez de concatenar, para que una cadena
        // que YA sea silenciosa no acabe en `--silent --remove --silent
        // --remove`. La ruta entre comillas se conserva tal cual (lección de
        // WinRAR: `C:\Program` es lo que queda al partirla mal).
        if (AnyDeskExe.IsMatch(cmd) && AnyDeskRemove.IsMatch(cmd))
        {
            var bare = AnyDeskVerbs.Replace(cmd, string.Empty);
            return bare + " --silent --remove";
        }

        return null;
    }

    private static readonly System.Text.RegularExpressions.Regex Edge = new(
        @"\\Microsoft\\Edge[^\\]*\\Application\\[\d.]+\\Installer\\setup\.exe""?\s.*--uninstall\b",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex WinRar = new(
        @"\\WinRAR\\uninstall\.exe""?",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex OneDrive = new(
        @"\\OneDriveSetup\.exe""?\s+/uninstall\b",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex Zoom = new(
        @"\\Zoom\\uninstall\\Installer\.exe""?\s+/uninstall\b",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// Su binario Y una orden de quitar: son DOS condiciones. Con el verbo
    /// pegado al .exe, una cadena que ya trajera `--silent` delante no casaba.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex AnyDeskExe = new(
        @"\\AnyDesk\.exe""?(\s|$)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex AnyDeskRemove = new(
        @"--(uninstall|remove)\b",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Los verbos y modificadores que se recomponen desde cero.</summary>
    private static readonly System.Text.RegularExpressions.Regex AnyDeskVerbs = new(
        @"\s+--(uninstall|remove|silent)\b",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex Chrome = new(
        @"\\Google\\Chrome\\Application\\[\d.]+\\Installer\\setup\.exe""?\s.*--uninstall\b",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
}
