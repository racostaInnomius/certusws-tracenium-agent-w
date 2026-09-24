namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Mirar el binario del desinstalador EN EL EQUIPO para saber si acepta un
/// modificador silencioso (ver InstallerKind).
///
/// ⚠️ SE LEE EL FICHERO, no se deduce del nombre. «uninstall.exe» lo usan NSIS,
/// InstallShield y cualquiera; añadirle `/S` por el nombre abriría una ventana
/// en la mitad de los casos — en la sesión 0, donde nadie la ve, y con el job
/// colgado hasta el timeout.
///
/// ⚠️ Nunca lanza y nunca bloquea: un fichero que no se puede leer (permisos,
/// ya borrado, en red) devuelve «no lo sé», y el llamador decide como antes.
/// </summary>
internal static class UninstallerProbe
{
    /// <summary>
    /// Cuánto se lee de cada binario. La cabecera de NSIS va detrás del
    /// ejecutable, y los desinstaladores pesan cientos de KB: con 2 MB se cubre
    /// de sobra sin cargar en memoria un instalador de 200 MB.
    /// </summary>
    private const int HeadBytes = 2 * 1024 * 1024;

    /// <summary>La línea con el modificador silencioso, o null si no se reconoce.</summary>
    public static string? SilentCommandFor(string? uninstallString)
    {
        var cmd = uninstallString?.Trim();
        if (string.IsNullOrEmpty(cmd)) return null;

        var (file, _) = UninstallCommandParse.Split(cmd!);
        if (string.IsNullOrWhiteSpace(file)) return null;

        var kind = KindOfFile(file);
        if (kind == InstallerKind.Kind.Unknown) return null;

        var silent = InstallerKind.SilentCommandFor(cmd, kind);
        Console.WriteLine($"[PrivSvc][UninstallerProbe] {file}: {kind} → {(silent == null ? "sin modificador" : "silencioso")}");
        return silent;
    }

    private static InstallerKind.Kind KindOfFile(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            var length = (int)Math.Min(stream.Length, HeadBytes);
            var buffer = new byte[length];
            var read = 0;
            while (read < length)
            {
                var n = stream.Read(buffer, read, length - read);
                if (n <= 0) break;
                read += n;
            }
            if (read < length) Array.Resize(ref buffer, read);
            return InstallerKind.Detect(buffer);
        }
        catch (Exception ex)
        {
            // Ilegible: «no lo sé». El desinstalador se ejecutará como venga, o
            // se rechazará, según quien llame — pero nunca por culpa de esto.
            Console.WriteLine($"[PrivSvc][UninstallerProbe] {path} unreadable: {ex.GetType().Name}");
            return InstallerKind.Kind.Unknown;
        }
    }
}
