// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/UpdateHistoryShape.cs
//
// La lectura del historial de Windows Update que imprime el script de
// `GetInstalledSecurityPatches` (SecurityCompliance.cs), extraída para poder
// probarla fuera de Windows.
//
// ── Por qué existe este fichero ──────────────────────────────────────
//
// Hasta el 22-sep-2026 el script descartaba EN EL EQUIPO todo lo que no fuera
// una instalación correcta (`ResultCode 2`, `Operation 1`). Los fallos, los
// abortos y las desinstalaciones —justo lo que dice si un parche da problemas—
// no salían nunca del equipo. Es la materia prima del Confidence Score de
// parches, y no hay forma de recuperarla hacia atrás: cada día filtrado es un
// día perdido.
//
// ── La distinción que hay que sostener ───────────────────────────────
//
//   items       → SÓLO instalaciones correctas. Lo leen `count` y todos los
//                 checks de SCP («parcheado en los últimos N días»). Su forma
//                 no cambia: meter aquí un fallo haría que cualquier backend
//                 contara un parche fallido como un equipo parcheado.
//   failures    → instalaciones con ResultCode 3/4/5 (con errores, fallida,
//                 abortada), con su HRESULT.
//   uninstalls  → desinstalaciones (Operation 2): un rollback es la señal más
//                 fuerte de que un parche dio problemas.
//
// Las dos listas nuevas viajan al lado de `items`: un backend que no las
// conoce las guarda sin leerlas, y nada depende de qué lado se despliegue
// primero.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class UpdateHistoryShape
{
    /// <summary>
    /// Las tres listas que el script imprime como UN objeto.
    ///
    /// Defensivo a propósito:
    ///   · un array suelto se lee como <c>items</c> — es la forma que imprimía
    ///     el script antes de este cambio;
    ///   · una clave ausente o mal formada se lee como lista vacía, sin
    ///     excepción: perder los fallos nunca puede costar las instalaciones
    ///     correctas que leen los checks de SCP;
    ///   · PowerShell puede emitir un objeto suelto donde se quería un array de
    ///     un elemento: se acepta igual.
    /// </summary>
    public static (List<Dictionary<string, object>> Items,
                   List<Dictionary<string, object>> Failures,
                   List<Dictionary<string, object>> Uninstalls) ParseBuckets(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return (Empty(), Empty(), Empty());

        try
        {
            using var doc = JsonDocument.Parse(output);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array)
                return (ParseList(root), Empty(), Empty());
            if (root.ValueKind != JsonValueKind.Object)
                return (Empty(), Empty(), Empty());

            return (Bucket(root, "items"), Bucket(root, "failures"), Bucket(root, "uninstalls"));
        }
        catch (JsonException)
        {
            return (Empty(), Empty(), Empty());
        }
    }

    private static List<Dictionary<string, object>> Empty() => new();

    private static List<Dictionary<string, object>> Bucket(JsonElement root, string key)
    {
        foreach (var prop in root.EnumerateObject())
        {
            // ConvertTo-Json respeta el caso de las claves, pero no hay por qué
            // depender de ello.
            if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase))
                return ParseList(prop.Value);
        }
        return Empty();
    }

    private static List<Dictionary<string, object>> ParseList(JsonElement el)
    {
        var list = new List<Dictionary<string, object>>();
        if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
            {
                var row = ToRow(item);
                if (row != null) list.Add(row);
            }
        }
        else if (el.ValueKind == JsonValueKind.Object)
        {
            var row = ToRow(el);
            if (row != null) list.Add(row);
        }
        return list;
    }

    private static Dictionary<string, object>? ToRow(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        // Mismo tipo que devolvía la lectura anterior (Dictionary<string, object>
        // con JsonElement dentro): el serializador de salida lo trata igual.
        return JsonSerializer.Deserialize<Dictionary<string, object>>(el.GetRawText());
    }
}
