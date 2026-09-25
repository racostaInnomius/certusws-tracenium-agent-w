namespace Tracenium.AgentTray;

/// <summary>
/// El cuaderno de fallos de la bandeja.
///
/// Estaba dentro de <see cref="Program"/> y solo lo usaba el manejador de
/// excepciones no controladas. Se saca aquí porque ahora hay sitios que
/// ATRAPAN un fallo y siguen adelante —el arranque, el refresco— y un fallo que
/// se atrapa sin dejar rastro es peor que uno que tumba el proceso: el síntoma
/// desaparece y la causa sigue ahí.
///
/// Escribe en %ProgramData%\Tracenium\Agent\logs\tray-crash.log, el mismo
/// fichero de siempre, para que no haya dos sitios donde mirar.
/// </summary>
internal static class TrayLog
{
    private const long MaxBytes = 1024 * 1024;

    public static string Path
    {
        get
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Tracenium", "Agent", "logs");
            return System.IO.Path.Combine(dir, "tray-crash.log");
        }
    }

    public static void Write(string what, Exception? ex)
    {
        try
        {
            var path = Path;
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);

            // Tope duro: un fallo que se repite en cada tick podría escribir
            // sin fin. Al pasar 1 MB conservamos el archivo como .1 y
            // arrancamos limpio.
            if (new FileInfo(path) is { Exists: true, Length: > MaxBytes })
            {
                File.Move(path, path + ".1", overwrite: true);
            }

            var line =
                $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z] {what}: " +
                $"{ex?.GetType().Name}: {ex?.Message}{Environment.NewLine}{ex?.StackTrace}{Environment.NewLine}";
            File.AppendAllText(path, line);
        }
        catch
        {
            // Registrar no puede ser nunca el motivo de un fallo.
        }
    }
}
