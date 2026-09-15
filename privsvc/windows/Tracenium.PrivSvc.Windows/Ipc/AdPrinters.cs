// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AdPrinters.cs
//
// ADR-0023 — `amp.ad.printers`: lee los objetos printQueue que Active Directory
// publica, con el script firmado Scripts\ad-printers.ps1, como LocalSystem, es
// decir con la CUENTA DE MÁQUINA del equipo. Validado en campo el 2026-09-15:
// SYSTEM en MSIG-WSUS leyó 21 colas en 314 ms.
//
// SÓLO LECTURA: ni este handler ni el script escriben en AD.
//
// El resultado se devuelve tal cual lo escribe el script —también con `error`—:
// el agente lo manda al control plane y es el backend quien lo interpreta.

using System.Diagnostics;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AdPrinters
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req) => Task.Run(() => Read(req));

    private static PrivSvcResponse Read(PrivSvcRequest req)
    {
        var (request, error) = AdPrintersShape.Validate(req.Params);
        if (request is null) return PrivSvcResponse.Fail(req.Id, "bad_request", error ?? "bad_request");

        var scriptPath = Path.Combine(AppContext.BaseDirectory, "Scripts", AdPrintersShape.ScriptFileName);
        if (!File.Exists(scriptPath))
        {
            IpcLog.Write($"[amp.ad.printers] script missing path={scriptPath}");
            return PrivSvcResponse.Fail(req.Id, "script_missing", scriptPath);
        }

        var (trusted, reason) = SignedScripts.Verify(scriptPath, "amp.ad.printers");
        if (!trusted)
        {
            IpcLog.Write($"[amp.ad.printers] script signature rejected reason={reason}");
            return PrivSvcResponse.Fail(req.Id, "script_untrusted", reason);
        }

        var workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "adprinters", request.RunId);
        Directory.CreateDirectory(workDir);
        var outputPath = Path.Combine(workDir, "out.json");

        var sw = Stopwatch.StartNew();
        try
        {
            if (File.Exists(outputPath)) File.Delete(outputPath);
            var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var psi = new ProcessStartInfo(powershell, AdPrintersShape.PowerShellArguments(scriptPath, outputPath, request.BudgetMs))
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = workDir
            };

            IpcLog.Write($"[amp.ad.printers] begin run={request.RunId} budgetMs={request.BudgetMs}");
            var result = SecurityCompliance.RunProcessWithTimeout(psi, AdPrintersShape.ProcessTimeoutMs(request));
            sw.Stop();

            if (result.TimedOut)
            {
                IpcLog.Write($"[amp.ad.printers] timeout run={request.RunId} ({sw.ElapsedMilliseconds}ms)");
                return PrivSvcResponse.Fail(req.Id, "script_timeout", $"exceeded {AdPrintersShape.ProcessTimeoutMs(request)}ms");
            }
            if (!File.Exists(outputPath))
            {
                var tail = Tail(result.Stderr);
                IpcLog.Write($"[amp.ad.printers] no output run={request.RunId} exit={result.ExitCode} stderr={tail}");
                return PrivSvcResponse.Fail(req.Id, "script_no_output", $"exit={result.ExitCode} {tail}");
            }
            var size = new FileInfo(outputPath).Length;
            if (size > AdPrintersShape.MaxOutputBytes)
            {
                return PrivSvcResponse.Fail(req.Id, "script_output_too_large", $"{size} bytes");
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(outputPath));
            IpcLog.Write($"[amp.ad.printers] done run={request.RunId} exit={result.ExitCode} bytes={size} ({sw.ElapsedMilliseconds}ms)");
            return PrivSvcResponse.Success(req.Id, doc.RootElement.Clone());
        }
        catch (Exception ex)
        {
            IpcLog.Write($"[amp.ad.printers] EXCEPTION {ex.GetType().Name}: {ex.Message}");
            return PrivSvcResponse.Fail(req.Id, "script_error", ex.Message);
        }
        finally
        {
            try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { }
            try { if (Directory.Exists(workDir) && !Directory.EnumerateFileSystemEntries(workDir).Any()) Directory.Delete(workDir); } catch { }
        }
    }

    private static string Tail(string s) => s.Length <= 300 ? s.Trim() : s[^300..].Trim();
}
