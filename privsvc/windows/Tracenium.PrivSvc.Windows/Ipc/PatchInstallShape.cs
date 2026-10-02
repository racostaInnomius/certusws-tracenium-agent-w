// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/PatchInstallShape.cs
//
// La selección de un patch.install, validada y escrita como literal de
// PowerShell. Puro, para poder probarlo fuera de Windows.
//
// ⚠️ POR QUÉ (auditoría PMP 1-oct-2026). HandleInstall escribía cada id en el
// script con JsonSerializer.Serialize, que NO escapa `$` ni `(`, dentro de una
// cadena PowerShell entre comillas dobles: el script corre como SYSTEM y un id
// `KB1$(…)` ejecutaba lo que hubiera dentro. El control plane y el agente ya
// validan la forma, pero esto es la última barrera antes de PowerShell: el
// PrivSvc no se fía de quien le llame.
//
// Dos defensas, cada una suficiente por sí sola:
//   · sólo se acepta «KB» + dígitos (lo único que el script sabe casar);
//   · cada id va entre comillas SIMPLES, donde PowerShell no expande nada.

using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class PatchInstallShape
{
    // «KB» + dígitos, o `UID:<UpdateID>` para lo que no tiene artículo KB
    // (drivers, algunas definiciones, terceros por WSUS; 1-oct-2026).
    private static readonly Regex KbArticlePattern =
        new(@"^(KB\d{1,10}|UID:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Los ids que no son «KB» + dígitos ni «UID:» + GUID (vacío = todos válidos).</summary>
    public static List<string> MalformedKbIds(IEnumerable<string> ids) =>
        ids.Where(id => !KbArticlePattern.IsMatch((id ?? "").Trim())).ToList();

    /// <summary>
    /// La lista como cuerpo de un <c>@(…)</c> de PowerShell: <c>'KB1','KB2'</c>.
    /// Lanza si algún id no es válido: quien llame debe haber filtrado antes, y
    /// escribir un id sin validar es exactamente el fallo que esto cierra.
    /// </summary>
    public static string PowerShellKbList(IEnumerable<string> ids)
    {
        var list = ids.Select(id => (id ?? "").Trim()).ToList();
        if (MalformedKbIds(list).Count > 0)
        {
            throw new ArgumentException("refusing to write a malformed KB id into PowerShell");
        }
        return string.Join(",", list.Select(id => "'" + id.ToUpperInvariant() + "'"));
    }
}
