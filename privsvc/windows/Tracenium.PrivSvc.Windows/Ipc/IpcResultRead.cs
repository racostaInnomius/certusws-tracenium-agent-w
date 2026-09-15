// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/IpcResultRead.cs
//
// Leer campos del resultado de OTRO handler llamado en proceso.
//
// Vive aparte para poder compilarse en Tracenium.PrivSvc.Tests (net8.0): los
// handlers que lo usan arrastran gRPC y Windows, y el fallo que protege —una
// lista que se pierde entre dos handlers— no da error, sólo un estado con
// menos datos.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class IpcResultRead
{
    /// <summary>
    /// Una lista de textos de la respuesta de otro handler. `HandleInstallCert`
    /// se llama en proceso y devuelve un objeto anónimo con `string[]`; se
    /// acepta también JSON por si algún día llega serializado. Vacía, nunca
    /// null: el agente une con lo que ya tenía y una lista vacía no quita nada.
    /// </summary>
    public static string[] StringArray(object? value, string key)
    {
        if (value == null) return Array.Empty<string>();

        IEnumerable<object?>? items = null;
        if (value is JsonElement je && je.ValueKind == JsonValueKind.Object)
        {
            if (je.TryGetProperty(key, out var prop) && prop.ValueKind == JsonValueKind.Array)
                items = prop.EnumerateArray()
                    .Select(e => (object?)(e.ValueKind == JsonValueKind.String ? e.GetString() : null));
        }
        else if (value.GetType().GetProperty(key)?.GetValue(value) is System.Collections.IEnumerable seq
                 && seq is not string)
        {
            items = seq.Cast<object?>();
        }

        return (items ?? Enumerable.Empty<object?>())
            .Select(i => i?.ToString()?.Trim() ?? "")
            .Where(s => s.Length > 0)
            .ToArray();
    }
}
