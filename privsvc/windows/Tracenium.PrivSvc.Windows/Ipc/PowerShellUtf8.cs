using System.Diagnostics;
using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// UTF-8 en los DOS extremos del tubo con powershell.exe.
/// </summary>
/// <remarks>
/// 🔴 En un Windows en español los títulos de parches llegaban como
/// «2026-09 Actualizaci¢n de seguridad (KB5129195)» (3 de 13 en T1, 28-sep).
/// PowerShell escribe la salida redirigida en la página OEM de la consola
/// (CP850: «ó» = 0xA2) y .NET, sin StandardOutputEncoding, la leía como ANSI
/// 1252, donde 0xA2 es «¢». Lo mismo les pasaba a los valores de compliance y
/// a los nombres de apps de la Store con acentos.
///
/// Se fija UTF-8 en los dos lados, sin BOM: un BOM delante del JSON rompería su
/// lectura en el primer carácter. El preámbulo va en try: si la consola no
/// admitiera el cambio, la salida queda como antes (lo ASCII no cambia).
///
/// ⚠️ Con esto PowerShell también decodifica en UTF-8 la salida de un ejecutable
/// NATIVO que capture (`$x = auditpol /get …`), que escribe en OEM. Hoy ningún
/// script lo hace — secedit y auditpol escriben a fichero y se leen con
/// Get-Content, que no depende de la consola —; uno nuevo que capture un nativo
/// localizado tiene que leerlo de fichero o fijar él su codificación.
///
/// ⚠️ ASCII puro y sin líneas que empiecen por `|`: lo parsea Windows
/// PowerShell 5.1. Y el script que lo recibe no puede abrir con param().
/// </remarks>
internal static class PowerShellUtf8
{
    private const string SetOutputEncoding =
        "try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}";

    /// <summary>Delante de un script (-EncodedCommand): va en su propia línea.</summary>
    internal const string Prelude = SetOutputEncoding + "\n";

    /// <summary>Delante de un -Command en una sola línea.</summary>
    internal const string InlinePrelude = SetOutputEncoding + "; ";

    /// <summary>Lee stdout y stderr del proceso como UTF-8 sin BOM.</summary>
    internal static ProcessStartInfo ReadAsUtf8(this ProcessStartInfo psi)
    {
        psi.StandardOutputEncoding = new UTF8Encoding(false);
        psi.StandardErrorEncoding = new UTF8Encoding(false);
        return psi;
    }
}
