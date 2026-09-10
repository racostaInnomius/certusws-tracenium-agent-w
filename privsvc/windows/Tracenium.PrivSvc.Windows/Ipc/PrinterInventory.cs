using System.Diagnostics;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

// Printer inventory collector for the AMP namespace.
//
// We shell out to PowerShell `Get-Printer` and `Get-Printer | Where-
// Object Default`. PowerShell's PrintManagement module ships with
// every Windows SKU that has Print Spooler enabled, so no extra
// dependency. The alternative would be P/Invoke into winspool.drv —
// noticeably faster but ~200 lines of marshalling that is overkill
// for a once-every-AMP-cycle collection.
//
// Output contract (what the agent-side TS expects):
//
//   {
//     count: number,
//     items: [
//       {
//         name:            string,
//         driverName:      string | null,
//         portName:        string | null,
//         isDefault:       bool,
//         shared:          bool,
//         location:        string | null,
//         comment:         string | null,
//         printerStatus:   string | null   // "Normal", "Offline", ...
//       },
//       ...
//     ]
//   }
//
// ⚠️ EL CONTRATO DE DEGRADACIÓN CAMBIÓ (2026-09-10).
//
// Antes cualquier fallo se colapsaba en `{ count: 0, items: [] }`, con el
// argumento de que un resultado vacío es la respuesta canónica a "no pude
// leer". Eso costó un diagnóstico de tres pasadas: "Spooler caído", "sin
// impresoras" e "invisibles desde esta cuenta" producían la MISMA fila, y el
// portal enseñaba cero como si fuera un hecho sobre la empresa.
//
// Ahora la respuesta lleva `machineScope` y `userScope`, y quien la lea puede
// distinguir medido-y-vacío de no-medido. Los campos `count`/`items` no
// cambian, así que un agente viejo sigue funcionando igual.
//
// Y se añade la mitad que faltaba: `Get-Printer` sólo ve las impresoras de la
// cuenta que llama, y las de RED son conexiones por usuario. Ver
// UserPrinterConnections.cs.

public static class PrinterInventory
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            Console.WriteLine("[PrivSvc][PrinterInventory] Starting collection");

            // -Depth 4 keeps the JSON small enough — Get-Printer's
            // raw object has dozens of nested CIM properties (job
            // counters, capabilities arrays) that we don't ship. The
            // explicit Select-Object below trims to just our wire
            // schema. JsonOutput=$true on ConvertTo-Json is implicit;
            // Compress reduces line-noise in /var/log style scrapes.
            //
            // We DON'T use -PrinterStatus filtering — we want offline
            // printers in the snapshot so the backend can flag them
            // as "configured but not currently reachable" in the UI.
            //
            // [CmdletBinding()]-style script body (rather than a
            // one-liner) so future maintenance is easier; the cost is
            // the same single PowerShell process invocation.
            string script = @"
$ErrorActionPreference = 'Stop'
try {
  $default = (Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue |
              Where-Object Default -EQ $true |
              Select-Object -ExpandProperty Name) -join ''

  Get-Printer -ErrorAction Stop |
    Select-Object `
      @{Name='name';          Expression={$_.Name}}, `
      @{Name='driverName';    Expression={$_.DriverName}}, `
      @{Name='portName';      Expression={$_.PortName}}, `
      @{Name='isDefault';     Expression={($_.Name -eq $default)}}, `
      @{Name='shared';        Expression={[bool]$_.Shared}}, `
      @{Name='location';      Expression={$_.Location}}, `
      @{Name='comment';       Expression={$_.Comment}}, `
      @{Name='printerStatus'; Expression={[string]$_.PrinterStatus}} |
    ConvertTo-Json -Depth 4 -Compress
} catch {
  # Anything fatal in Get-Printer (e.g., Spooler service disabled,
  # cmdlet missing in some SKUs) — emit an empty array so the
  # downstream JSON parser doesn't crash.
  '[]'
}
";

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                // -NoLogo / -NoProfile / -NonInteractive cut the cold-
                // start by ~250ms on most hosts. ExecutionPolicy Bypass
                // is required because the inline script isn't signed;
                // confined to this single process invocation.
                Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start powershell.exe");

            proc.StandardInput.Write(script);
            proc.StandardInput.Close();

            // 15s ceiling — a healthy host responds in ~1-2s. If we
            // hit this, Spooler is hung or the system is heavily
            // loaded; bail with empty result rather than wedging the
            // AMP cycle.
            if (!proc.WaitForExit(15_000))
            {
                try { proc.Kill(); } catch { }
                Console.WriteLine("[PrivSvc][PrinterInventory] timeout, machine scope unavailable");
                return Merge(req, new List<object>(), "timeout");
            }

            string stdout = proc.StandardOutput.ReadToEnd().Trim();
            string stderr = proc.StandardError.ReadToEnd().Trim();

            if (!string.IsNullOrEmpty(stderr))
            {
                Console.WriteLine($"[PrivSvc][PrinterInventory] PowerShell stderr: {stderr}");
            }

            if (string.IsNullOrEmpty(stdout))
            {
                // Salida vacía del PowerShell: no se puede afirmar que la
                // máquina no tenga impresoras, sólo que no dijo nada.
                return Merge(req, new List<object>(), "empty_output");
            }

            // ConvertTo-Json emits either a JSON object (1 printer) OR
            // a JSON array (2+ printers) — PowerShell-ism we have to
            // normalize. Try array first; if that fails, wrap a single
            // object into a 1-element array.
            List<JsonElement> items;
            try
            {
                using var doc = JsonDocument.Parse(stdout);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    items = doc.RootElement.EnumerateArray()
                                            .Select(e => e.Clone())
                                            .ToList();
                }
                else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    items = new List<JsonElement> { doc.RootElement.Clone() };
                }
                else
                {
                    items = new List<JsonElement>();
                }
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"[PrivSvc][PrinterInventory] JSON parse failed: {ex.Message}");
                items = new List<JsonElement>();
            }

            Console.WriteLine($"[PrivSvc][PrinterInventory] machine scope: {items.Count} printer(s)");
            return Merge(req, items.Cast<object>().ToList(), "collected",
                         items.Select(e => e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : ""));
        }
        catch (Exception ex)
        {
            // Any unexpected exception → empty result instead of
            // failure response. Keeps the agent-side AMP cycle whole.
            Console.WriteLine($"[PrivSvc][PrinterInventory] ERROR: {ex.Message}");
            return Merge(req, new List<object>(), "unavailable");
        }
    }

    /// <summary>
    /// Une lo de la máquina con las conexiones de los usuarios conectados.
    ///
    /// ⚠️ Se llama SIEMPRE, incluso cuando la mitad de máquina falló: un
    /// Spooler caído no impide leer las conexiones del registro, y devolver
    /// cero por eso volvería a esconder justo las impresoras que motivaron
    /// este cambio.
    /// </summary>
    private static Task<PrivSvcResponse> Merge(
        PrivSvcRequest req,
        List<object> machineItems,
        string machineScope,
        IEnumerable<string>? machineNames = null)
    {
        var (userScope, userItems) = UserPrinterConnections.Collect();
        var extra = UserPrinterConnectionsShape.MergeByName(
            machineNames ?? Enumerable.Empty<string>(), userItems);

        var todos = new List<object>(machineItems);
        todos.AddRange(extra);

        Console.WriteLine(
            $"[PrivSvc][PrinterInventory] machine={machineScope}({machineItems.Count}) " +
            $"user={userScope}({extra.Count} new) total={todos.Count}");

        return Task.FromResult(PrivSvcResponse.Success(req.Id, new
        {
            count = todos.Count,
            items = todos,
            machineScope,
            userScope
        }));
    }
}
