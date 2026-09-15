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
//         printerStatus:   string | null,  // "Normal", "Offline", ...
//         shareName:       string | null,  // nombre con el que se comparte (\\servidor\shareName)
//         hostAddress:     string | null   // dirección del puerto TCP/IP (Get-PrinterPort)
//       },
//       ...
//     ]
//   }
//
// ⚠️ Y OTRA VEZ (2026-09-14): el catch del script y un JSON ilegible ya no
// producen `collected` con cero filas, sino `unavailable`. Ver
// PrinterInventoryShape.cs.
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

            // El script y la lectura de su salida viven en
            // PrinterInventoryShape.cs, donde se prueban.
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                // -NoLogo / -NoProfile / -NonInteractive cut the cold-
                // start by ~250ms on most hosts. ExecutionPolicy Bypass
                // is required because the inline script isn't signed;
                // confined to this single process invocation.
                // ⚠️ Por -EncodedCommand, no por stdin: con `-Command -` el
                // bloque try{} no llegaba a ejecutarse y la salida era vacía en
                // TODOS los equipos. Ver PrinterInventoryShape.cs.
                Arguments = PrinterInventoryShape.PowerShellArguments(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start powershell.exe");

            // ⚠️ Las lecturas arrancan ANTES de esperar. Antes era
            // WaitForExit(15s) y DESPUÉS ReadToEnd: si el JSON pasaba del búfer
            // de la tubería, PowerShell se quedaba bloqueado escribiendo, nunca
            // salía, y la lectura acababa en `timeout` — el deadlock documentado
            // de Process que PatchManagement.RunPs y SecurityCompliance ya
            // sufrieron. En un servidor de impresión con muchas colas era un
            // timeout en CADA ciclo.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();


            // 15s ceiling — a healthy host responds in ~1-2s. If we hit this,
            // Spooler is hung or the system is heavily loaded.
            if (!proc.WaitForExit(15_000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                Console.WriteLine("[PrivSvc][PrinterInventory] timeout, machine scope timeout");
                return Merge(req, new MachinePrinterRead(new List<JsonElement>(),
                                                         PrinterInventoryShape.ScopeTimeout, null));
            }

            // El proceso salió: las tuberías se cierran y las lecturas terminan.
            // El tope sólo cubre un nieto que heredara el handle.
            if (!Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 5_000))
            {
                Console.WriteLine("[PrivSvc][PrinterInventory] output never closed, machine scope timeout");
                return Merge(req, new MachinePrinterRead(new List<JsonElement>(),
                                                         PrinterInventoryShape.ScopeTimeout, null));
            }

            string stderr = stderrTask.Result.Trim();
            if (!string.IsNullOrEmpty(stderr))
            {
                Console.WriteLine($"[PrivSvc][PrinterInventory] PowerShell stderr: {stderr}");
            }

            var machine = PrinterInventoryShape.ParseMachineOutput(stdoutTask.Result);
            if (machine.Error is not null)
            {
                Console.WriteLine($"[PrivSvc][PrinterInventory] machine scope {machine.Scope}: {machine.Error}");
            }
            else
            {
                Console.WriteLine($"[PrivSvc][PrinterInventory] machine scope {machine.Scope}: {machine.Items.Count} printer(s)");
            }
            return Merge(req, machine);
        }
        catch (Exception ex)
        {
            // Any unexpected exception → declared, not an empty list. Keeps
            // the agent-side AMP cycle whole.
            Console.WriteLine($"[PrivSvc][PrinterInventory] ERROR: {ex.Message}");
            return Merge(req, new MachinePrinterRead(new List<JsonElement>(),
                                                     PrinterInventoryShape.ScopeUnavailable, ex.Message));
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
    private static Task<PrivSvcResponse> Merge(PrivSvcRequest req, MachinePrinterRead machine)
    {
        var machineItems = machine.Items.Cast<object>().ToList();
        var machineScope = machine.Scope;
        var (userScope, userItems) = UserPrinterConnections.Collect();
        var extra = UserPrinterConnectionsShape.MergeByName(machine.Names, userItems);

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
