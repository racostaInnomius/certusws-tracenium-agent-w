namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Qué tecnología generó un desinstalador, mirando el BINARIO.
///
/// ── Por qué hace falta ───────────────────────────────────────────────────
///
/// Un desinstalador sin `QuietUninstallString` abre ventana. En una
/// desinstalación de máquina eso es peor que un fallo: corre como SYSTEM en la
/// sesión 0, su ventana no la ve NADIE y el job se cuelga hasta el timeout.
/// La tabla de fabricantes (`KnownSilentUninstall`) resuelve los conocidos, pero
/// en T111 quedaban 775 filas — y la mayor parte son `uninstall.exe`,
/// `uninst.exe`, `uninstaller.exe`: la cola larga de NSIS.
///
/// ⚠️ POR FIRMA, NO POR NOMBRE. «uninstall.exe» no dice nada: lo usan NSIS,
/// InstallShield y cualquiera. Añadir `/S` porque el fichero se llame así sería
/// adivinar, y con un InstallShield detrás abre la ventana igual. NSIS, en
/// cambio, se puede reconocer: todo ejecutable que genera lleva la cabecera
/// `0xDEADBEEF` + «NullsoftInst» del bloque de datos. Es la misma marca que usan
/// 7-Zip y los desempaquetadores para identificarlos.
///
/// ⚠️ Lo que NO reconoce se queda como estaba. Inno Setup (`unins000.exe`,
/// `/VERYSILENT`) tiene su propia marca y merece su propio caso, con su propia
/// prueba; no se cuela aquí por parecido.
/// </summary>
public static class InstallerKind
{
    public enum Kind { Unknown, Nsis }

    /// <summary>
    /// La marca del bloque de datos de NSIS: firma 0xDEADBEEF (little-endian)
    /// seguida de «NullsoftInst». Se busca la parte de texto, que es la que no
    /// cambia entre versiones ni entre 32 y 64 bits.
    /// </summary>
    private static readonly byte[] NsisFirstHeader = System.Text.Encoding.ASCII.GetBytes("NullsoftInst");

    /// <summary>
    /// El nombre en el recurso de versión, en UTF-16 como lo guarda Windows.
    /// Segundo camino a propósito: un desinstalador cuyo bloque de datos quede
    /// fuera de los bytes que leemos sigue reconociéndose por aquí.
    /// </summary>
    private static readonly byte[] NsisProductWide =
        System.Text.Encoding.Unicode.GetBytes("Nullsoft Install System");

    /// <summary>Qué generó este binario, a partir de sus primeros bytes.</summary>
    public static Kind Detect(byte[]? head)
    {
        if (head == null || head.Length == 0) return Kind.Unknown;
        if (IndexOf(head, NsisFirstHeader) >= 0) return Kind.Nsis;
        if (IndexOf(head, NsisProductWide) >= 0) return Kind.Nsis;
        return Kind.Unknown;
    }

    /// <summary>
    /// El modificador silencioso de esa tecnología, o null si no se conoce.
    ///
    /// NSIS: `/S` (mayúscula obligatoria; su parser distingue) y, por convenio,
    /// va ANTES de otros modificadores en la mayoría de los scripts.
    /// </summary>
    public static string? SilentSwitch(Kind kind) => kind switch
    {
        Kind.Nsis => "/S",
        _ => null,
    };

    /// <summary>
    /// La línea de desinstalación con el modificador silencioso de su
    /// tecnología, o null si no se reconoce (o si ya lo lleva).
    /// </summary>
    public static string? SilentCommandFor(string? uninstallString, Kind kind)
    {
        var cmd = uninstallString?.Trim();
        if (string.IsNullOrEmpty(cmd)) return null;
        var sw = SilentSwitch(kind);
        if (sw == null) return null;
        // `/S` ya presente: se respeta tal cual. Repetirlo no rompe NSIS, pero
        // una línea con dos `/S` se lee como un error nuestro en el log del
        // operador.
        return HasSwitch(cmd, sw) ? cmd : $"{cmd} {sw}";
    }

    private static bool HasSwitch(string cmd, string sw)
    {
        foreach (var token in cmd.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (string.Equals(token, sw, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
        {
            var hit = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { hit = false; break; }
            }
            if (hit) return i;
        }
        return -1;
    }
}
