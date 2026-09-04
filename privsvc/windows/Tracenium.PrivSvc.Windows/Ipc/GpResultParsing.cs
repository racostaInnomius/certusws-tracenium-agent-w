// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GpResultParsing.cs
//
// Qué líneas de `gpresult /R` son directivas aplicadas.
//
// ⚠️ Vive en su propio fichero para poder probarlo. Es lógica de texto pura,
// sin nada de Windows dentro, y el proyecto de pruebas compila el fichero
// concreto bajo prueba (ver el comentario del csproj). Mientras estuvo dentro
// de SecurityCompliance.cs —junto a las llamadas a PowerShell y a WMI— no
// había forma de ejercitarlo, y el bug que corrige esta versión vivió ahí sin
// que ninguna suite pudiera verlo.

using System;
using System.Collections.Generic;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class GpResultParsing
{
    /// <summary>
    /// Los nombres de GPO aplicadas dentro de la salida de `gpresult /R`.
    /// </summary>
    public static List<string> ExtractAppliedGpoNames(IReadOnlyList<string>? lines)
    {
        var result = new List<string>();
        if (lines is null || lines.Count == 0) return result;

        var start = -1;
        for (var i = 0; i < lines.Count; i++)
        {
            if (lines[i] != null &&
                lines[i].Contains("Applied Group Policy Objects", StringComparison.OrdinalIgnoreCase))
            {
                start = i;
                break;
            }
        }
        if (start < 0) return result;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = start + 1; i < lines.Count; i++)
        {
            var line = (lines[i] ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(line)) continue;

            // La línea de guiones que subraya nuestro propio encabezado.
            if (line.StartsWith("---", StringComparison.Ordinal)) continue;

            // ⚠️ AQUÍ estaba el bug. La única condición de parada era la frase
            // "The following GPOs", que encabeza la sección de directivas
            // filtradas. En un equipo donde NO se filtró ninguna, esa sección
            // no existe y el bucle seguía leyendo hasta el final del reporte,
            // tragándose la sección de grupos de seguridad que viene después.
            //
            // Medido en el tenant 111 al construir la vista de inventario: de
            // 20 nombres distintos recolectados como "GPO aplicada", sólo 6 lo
            // eran. Los otros eran Everyone, BUILTIN\Administrators, cuentas
            // de máquina terminadas en $ — y el propio encabezado "The
            // computer is a part of the following security groups", que es la
            // prueba más clara de que el bucle no paraba donde debía. Afectaba
            // a 3 equipos: justo los que no tenían directivas filtradas.
            //
            // La parada correcta es ESTRUCTURAL y no una frase: en gpresult /R
            // todo encabezado de sección va subrayado con guiones. Se corta al
            // primero que aparezca después del nuestro. Además es
            // independiente del idioma, y el reporte SÍ se localiza — buscar
            // frases en inglés habría funcionado en el laboratorio y fallado
            // en el primer dominio en español.
            var next = i + 1 < lines.Count ? (lines[i + 1] ?? string.Empty).Trim() : string.Empty;
            if (next.StartsWith("---", StringComparison.Ordinal)) break;

            // Segunda red, por si una variante del formato no subraya: no
            // cuesta nada y cubre el caso que la versión anterior sí atrapaba.
            if (line.Contains("The following GPOs", StringComparison.OrdinalIgnoreCase)) break;

            if (line.Contains("N/A", StringComparison.OrdinalIgnoreCase)) continue;

            if (seen.Add(line)) result.Add(line);
        }

        return result;
    }
}
