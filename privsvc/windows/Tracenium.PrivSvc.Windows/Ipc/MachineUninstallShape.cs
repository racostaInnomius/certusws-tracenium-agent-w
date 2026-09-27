namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Qué comando ejecutar para desinstalar una app DE MÁQUINA, o por qué no se
/// puede ejecutar ninguno.
///
/// ── Por qué existe (26-sep) ──────────────────────────────────────────────
///
/// La decisión vivía suelta dentro de <c>Sdp.RunExeUninstaller</c>, que es
/// async, toca el registro y lanza procesos: imposible de probar, y por eso
/// nadie vio que su último recurso era ejecutar la cadena CRUDA. AnyDesk en
/// W11-JPR-LAB02 registró <c>"…\AnyDesk.exe" --uninstall</c> sin
/// QuietUninstallString; <c>--uninstall</c> pide confirmación, la ventana se
/// abrió en la sesión 0 —donde no la ve NADIE— y el job estuvo 1740 s colgado.
/// Se reintentó cinco veces, ~2,5 h de instalador muerto, y AnyDesk siguió
/// instalado.
///
/// ⚠️ ES EL ESPEJO DE <see cref="UserUninstallShape"/>, que toma esta misma
/// decisión para las apps de un perfil y devuelve <c>no_silent_uninstall</c>
/// desde el principio. La rama de máquina es donde más duele —por usuario la
/// ventana al menos sale en el escritorio de alguien— y era la que no la tenía.
///
/// ⚠️ El gemelo del SERVIDOR es `modules/software-delivery/uninstall-target.ts`,
/// que aplica la misma regla en la vista previa. Si divergen, el portal enseña
/// «se va a desinstalar» y el equipo se niega.
/// </summary>
public static class MachineUninstallShape
{
    public const string NoSilentUninstall = "no_silent_uninstall";

    /// <summary>
    /// El comando elegido, o <paramref name="ErrorCode"/> cuando no hay ninguno
    /// que se pueda ejecutar sin abrir una ventana.
    /// </summary>
    /// <param name="Command">La línea completa a ejecutar, o null si hay negativa.</param>
    /// <param name="ExtraArgs">Argumentos del operador a añadir, o null.</param>
    /// <param name="ErrorCode">La negativa, o null.</param>
    public sealed record CommandChoice(string? Command, string? ExtraArgs, string? ErrorCode);

    /// <summary>
    /// Decide con qué se desinstala, por orden de confianza:
    ///
    ///   1. <c>QuietUninstallString</c> del propio instalador — un hecho.
    ///   2. La forma que documenta el fabricante (<see cref="KnownSilentUninstall"/>).
    ///   3. Lo que diga el BINARIO: NSIS se reconoce por su firma y acepta <c>/S</c>.
    ///   4. Un <c>silentUninstallArgs</c> que haya escrito el operador — sabe
    ///      más que nuestra tabla sobre ESE desinstalador, y es una decisión
    ///      deliberada de una persona.
    ///   5. Nada de lo anterior → negativa. NO se ejecuta la cadena desnuda.
    ///
    /// ⚠️ El orden entre 3 y 4 da igual para el resultado, pero no para lo que
    /// se ejecuta: si el binario es NSIS se usa su <c>/S</c> y los argumentos
    /// del operador no hacen falta. Se prefiere lo que el binario dice de sí
    /// mismo antes que lo que alguien escribió hace meses en un paquete.
    /// </summary>
    /// <param name="uninstallString">La cadena del registro (puede ser null).</param>
    /// <param name="registryQuiet">El QuietUninstallString del registro, si lo hay.</param>
    /// <param name="probedSilent">
    /// Lo que resolvieron la tabla de fabricantes y la sonda del binario. Se
    /// pasa ya resuelto porque leer el fichero es E/S y esto es puro.
    /// </param>
    /// <param name="operatorArgs">`silentUninstallArgs` del paquete, si lo hay.</param>
    public static CommandChoice ChooseCommand(
        string? uninstallString,
        string? registryQuiet,
        string? probedSilent,
        string? operatorArgs)
    {
        var quiet = registryQuiet?.Trim();
        if (!string.IsNullOrEmpty(quiet)) return new CommandChoice(quiet, null, null);

        var probed = probedSilent?.Trim();
        if (!string.IsNullOrEmpty(probed)) return new CommandChoice(probed, null, null);

        var cmd = uninstallString?.Trim();
        if (string.IsNullOrEmpty(cmd)) return new CommandChoice(null, null, null);

        var extra = operatorArgs?.Trim();
        if (!string.IsNullOrEmpty(extra)) return new CommandChoice(cmd, extra, null);

        // 🔴 Aquí se devolvía `cmd` a secas. Ver la cabecera de la clase.
        return new CommandChoice(null, null, NoSilentUninstall);
    }
}
