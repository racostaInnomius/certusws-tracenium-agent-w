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
// Errors collapse to `{ count: 0, items: [] }` on the wire — same
// degradation contract as software.inventory: an empty result is the
// canonical "couldn't read" response, never an exception. The agent
// turns that into an empty PrinterInventory (hasChanges=false on
// subsequent runs) so a broken Spooler service doesn't poison the
// rest of the AMP namespace.

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
                Console.WriteLine("[PrivSvc][PrinterInventory] timeout, returning empty");
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new
                {
                    count = 0,
                    items = Array.Empty<object>()
                }));
            }

            string stdout = proc.StandardOutput.ReadToEnd().Trim();
            string stderr = proc.StandardError.ReadToEnd().Trim();

            if (!string.IsNullOrEmpty(stderr))
            {
                Console.WriteLine($"[PrivSvc][PrinterInventory] PowerShell stderr: {stderr}");
            }

            if (string.IsNullOrEmpty(stdout))
            {
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new
                {
                    count = 0,
                    items = Array.Empty<object>()
                }));
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

            Console.WriteLine($"[PrivSvc][PrinterInventory] collected {items.Count} printer(s)");

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                count = items.Count,
                items
            }));
        }
        catch (Exception ex)
        {
            // Any unexpected exception → empty result instead of
            // failure response. Keeps the agent-side AMP cycle whole.
            Console.WriteLine($"[PrivSvc][PrinterInventory] ERROR: {ex.Message}");
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                count = 0,
                items = Array.Empty<object>()
            }));
        }
    }
}
