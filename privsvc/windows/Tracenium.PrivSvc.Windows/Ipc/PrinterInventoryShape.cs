// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/PrinterInventoryShape.cs
//
// La mitad de MÁQUINA del inventario de impresoras: el script de `Get-Printer`
// y cómo se interpreta lo que imprime. Lanzar PowerShell vive en
// PrinterInventory.cs; aquí sólo hay texto y System.Text.Json, para que la
// suite `net8.0` lo compile y lo pruebe en un Mac (misma convención que
// UserPrinterConnectionsShape / SeceditShape).
//
// ── EL BORRADO QUE CIERRA ───────────────────────────────────────────
//
// Hasta 2026-09-14 el script terminaba en `catch { '[]' }` y un JSON que no
// parseaba se convertía en lista vacía. Un Spooler deshabilitado, un SKU sin
// el módulo PrintManagement o una salida corrupta llegaban al agente como
// `machineScope: "collected"` con CERO impresoras: una lectura BUENA y vacía.
// El agente la aplica como "se fueron todas", y el backend borra las filas
// del equipo. El `timeout` ya no borraba (agente 9735333); esto era el mismo
// agujero por la otra puerta.
//
// Ahora sólo hay una forma de obtener `collected` con cero filas: que
// `Get-Printer` TERMINE BIEN y no devuelva nada.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed record MachinePrinterRead(
    List<JsonElement> Items,
    string Scope,
    string? Error)
{
    /// <summary>Los nombres, para fundir con las conexiones de usuario sin duplicar.</summary>
    public IEnumerable<string> Names =>
        Items.Select(e => e.ValueKind == JsonValueKind.Object
                          && e.TryGetProperty("name", out var n)
                          && n.ValueKind == JsonValueKind.String
                              ? n.GetString() ?? ""
                              : "");
}

public static class PrinterInventoryShape
{
    public const string ScopeCollected = "collected";
    public const string ScopeTimeout = "timeout";
    public const string ScopeEmptyOutput = "empty_output";
    public const string ScopeUnavailable = "unavailable";

    /// <summary>
    /// Lo que imprime el catch del script. Un prefijo que ningún JSON puede
    /// tener, para que un fallo no se confunda nunca con una lista.
    /// </summary>
    public const string ErrorMarker = "TRACENIUM_PRINTER_ERROR:";

    // -Depth 4 keeps the JSON small — Get-Printer's raw object has dozens of
    // nested CIM properties we don't ship; the Select-Object trims to the wire
    // schema. Offline printers are NOT filtered out: the backend shows them as
    // "configured but not reachable".
    //
    // ⚠️ `@(...)` y la rama `Count -eq 0`: en PowerShell un pipeline vacío
    // hacia ConvertTo-Json no imprime NADA, que sería `empty_output`. La lista
    // vacía se emite a mano, y SÓLO aquí, tras un Get-Printer que no falló.
    public const string Script = @"
$ErrorActionPreference = 'Stop'
try {
  $default = (Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue |
              Where-Object Default -EQ $true |
              Select-Object -ExpandProperty Name) -join ''

  $printers = @(Get-Printer -ErrorAction Stop |
    Select-Object `
      @{Name='name';          Expression={$_.Name}}, `
      @{Name='driverName';    Expression={$_.DriverName}}, `
      @{Name='portName';      Expression={$_.PortName}}, `
      @{Name='isDefault';     Expression={($_.Name -eq $default)}}, `
      @{Name='shared';        Expression={[bool]$_.Shared}}, `
      @{Name='location';      Expression={$_.Location}}, `
      @{Name='comment';       Expression={$_.Comment}}, `
      @{Name='printerStatus'; Expression={[string]$_.PrinterStatus}})

  if ($printers.Count -eq 0) { '[]' } else { $printers | ConvertTo-Json -Depth 4 -Compress }
} catch {
  # Spooler deshabilitado, cmdlet ausente en el SKU, lo que sea: se DECLARA.
  # Nunca una lista vacía: se leería como 'la máquina no tiene impresoras'.
  'TRACENIUM_PRINTER_ERROR: ' + $_.Exception.Message
}
";

    /// <summary>
    /// Interpreta la salida estándar del script. Sólo un array o un objeto
    /// JSON es una lectura; todo lo demás es `unavailable` con su motivo.
    /// </summary>
    public static MachinePrinterRead ParseMachineOutput(string? stdout)
    {
        var text = stdout?.Trim();
        if (string.IsNullOrEmpty(text))
            return new MachinePrinterRead(new List<JsonElement>(), ScopeEmptyOutput, null);

        if (text.StartsWith(ErrorMarker, StringComparison.Ordinal))
            return Unavailable(text.Substring(ErrorMarker.Length).Trim());

        try
        {
            using var doc = JsonDocument.Parse(text);
            switch (doc.RootElement.ValueKind)
            {
                // ConvertTo-Json emits an ARRAY for 2+ printers and a bare
                // OBJECT for exactly one — normalize both to a list.
                case JsonValueKind.Array:
                    return new MachinePrinterRead(
                        doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToList(),
                        ScopeCollected, null);
                case JsonValueKind.Object:
                    return new MachinePrinterRead(
                        new List<JsonElement> { doc.RootElement.Clone() },
                        ScopeCollected, null);
                default:
                    return Unavailable($"unexpected JSON {doc.RootElement.ValueKind}");
            }
        }
        catch (JsonException ex)
        {
            return Unavailable($"JSON parse failed: {ex.Message}");
        }
    }

    private static MachinePrinterRead Unavailable(string error) =>
        new(new List<JsonElement>(), ScopeUnavailable, error);
}
