// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GpResultParsing.cs
//
// Qué directivas de grupo tiene aplicadas un equipo.
//
// Dos lectores para la misma pregunta, y el orden importa:
//
//   · ExtractAppliedGposFromRsopXml — `gpresult /X`. Los nombres de elemento
//     del XML de RSOP NO se localizan, y cada GPO trae los campos con los que
//     Windows decide si se aplicó. Es la fuente buena.
//   · ExtractAppliedGpoNames — `gpresult /R`. Prosa localizada. Se queda como
//     respaldo, no como plan A.
//
// ⚠️ El respaldo existe porque el plan A no se puede probar en una Mac: la
// invocación de gpresult sólo corre en Windows. El parseo sí se prueba aquí,
// con ficheros reales de campo; la llamada, no. Si el XML falla en un equipo
// que nadie tiene delante, el texto sigue respondiendo lo de siempre.
//
// ⚠️ Vive en su propio fichero para poder probarlo. Es lógica de texto pura,
// sin nada de Windows dentro, y el proyecto de pruebas compila el fichero
// concreto bajo prueba (ver el comentario del csproj). Mientras estuvo dentro
// de SecurityCompliance.cs —junto a las llamadas a PowerShell y a WMI— no
// había forma de ejercitarlo, y el bug que corrige esta versión vivió ahí sin
// que ninguna suite pudiera verlo.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class GpResultParsing
{
    private const string RSOP_NS = "http://www.microsoft.com/GroupPolicy/Rsop";

    /// <summary>Qué mitad del informe de RSOP se quiere leer.</summary>
    public enum RsopScope
    {
        Computer,
        User
    }

    /// <summary>
    /// Los nombres de GPO aplicadas dentro del XML de `gpresult /X`.
    /// </summary>
    /// <returns>
    /// La lista —posiblemente VACÍA, que significa "este equipo no tiene
    /// ninguna"— o <c>null</c>, que significa algo muy distinto: "no se pudo
    /// leer". Son estados diferentes y el llamador los trata diferente. Un
    /// fallo de lectura devuelto como lista vacía es exactamente el defecto
    /// que trajo hasta aquí: un equipo con tres directivas aplicadas llevaba
    /// meses apareciendo en el portal como equipo sin ninguna.
    /// </returns>
    public static List<string>? ExtractAppliedGposFromRsopXml(string? xml, RsopScope scope)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;

        XElement root;
        try
        {
            root = XDocument.Parse(xml).Root!;
        }
        catch
        {
            // XML truncado, gpresult a medias, fichero de otra cosa.
            return null;
        }
        if (root is null) return null;

        var sectionName = scope == RsopScope.Computer ? "ComputerResults" : "UserResults";
        var section = root.Element(XName.Get(sectionName, RSOP_NS));
        // ⚠️ Ausente NO es vacío. `gpresult /X` sin datos de RSOP de usuario
        // —el caso del servicio, que corre como LocalSystem y no tiene perfil
        // interactivo— no escribe la sección; decir "cero directivas de
        // usuario" a partir de eso sería inventar un hecho sobre el equipo.
        if (section is null) return null;

        var applied = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // ⚠️ Hijos DIRECTOS de la sección, nunca un barrido de todo el
        // documento. Medido en un informe real de campo: 4 GPO de verdad como
        // hijas directas y 30 elementos <GPO> más enterrados dentro de
        // <ExtensionData><Extension>, que son referencias de cada ajuste a la
        // directiva que lo puso. Un `//GPO` los recogería todos.
        foreach (var gpo in section.Elements(XName.Get("GPO", RSOP_NS)))
        {
            var name = (Child(gpo, "Name") ?? string.Empty).Trim();
            if (name.Length == 0) continue;

            // Los tres campos con los que Windows decide. `FilterAllowed` es
            // el filtrado de seguridad o WMI; `AccessDenied`, que el equipo no
            // pueda leer la GPO; `IsValid`, que la GPO exista y se resuelva.
            if (!IsTrue(Child(gpo, "IsValid"))) continue;
            if (!IsTrue(Child(gpo, "FilterAllowed"))) continue;
            if (IsTrue(Child(gpo, "AccessDenied"))) continue;

            // ⚠️ Y una condición que no está en ningún campo booleano: una GPO
            // enlazada pero SIN ajustes no se aplica. `gpresult /R` la manda a
            // la lista de filtradas con el motivo "No aplicado (vacío)", y sus
            // dos contadores de versión están en cero. Sin esto, "Local Group
            // Policy" entraría como directiva aplicada en toda la flota —
            // cincuenta filas nuevas que el informe de texto nunca dio.
            if (Version(gpo, "VersionDirectory") == 0 && Version(gpo, "VersionSysvol") == 0) continue;

            if (seen.Add(name)) applied.Add(name);
        }

        return applied;
    }

    private static string? Child(XElement parent, string localName)
        => parent.Element(XName.Get(localName, RSOP_NS))?.Value;

    private static bool IsTrue(string? value)
        => bool.TryParse((value ?? string.Empty).Trim(), out var parsed) && parsed;

    private static int Version(XElement gpo, string localName)
        => int.TryParse((Child(gpo, localName) ?? string.Empty).Trim(), out var parsed) ? parsed : 0;

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
