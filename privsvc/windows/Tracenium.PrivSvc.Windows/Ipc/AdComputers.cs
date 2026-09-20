// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AdComputers.cs
//
// Cobertura — `amp.ad.computers`: lee los objetos de equipo de Active Directory
// con el script firmado Scripts\ad-computers.ps1, como LocalSystem, es decir con
// la CUENTA DE MÁQUINA del equipo, sin credenciales de nadie. Gemelo de
// AdPrinters: misma mecánica (script firmado por -File, presupuesto, salida en
// JSON en disco), otra pregunta.
//
// SÓLO LECTURA: ni este handler ni el script escriben en AD.
//
// El resultado se devuelve tal cual lo escribe el script —también con `error`—:
// el agente lo manda al control plane y es el backend quien lo interpreta. Un
// solo intérprete, no dos que diverjan.

using System.Diagnostics;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AdComputers
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req) => Task.Run(() => Read(req));

    private static PrivSvcResponse Read(PrivSvcRequest req)
    {
        var (request, error) = AdComputersShape.Validate(req.Params);
        if (request is null) return PrivSvcResponse.Fail(req.Id, "bad_request", error ?? "bad_request");

        var scriptPath = Path.Combine(AppContext.BaseDirectory, "Scripts", AdComputersShape.ScriptFileName);
        if (!File.Exists(scriptPath))
        {
            IpcLog.Write($"[amp.ad.computers] script missing path={scriptPath}");
            return PrivSvcResponse.Fail(req.Id, "script_missing", scriptPath);
        }

        var (trusted, reason) = SignedScripts.Verify(scriptPath, "amp.ad.computers");
        if (!trusted)
        {
            IpcLog.Write($"[amp.ad.computers] script signature rejected reason={reason}");
            return PrivSvcResponse.Fail(req.Id, "script_untrusted", reason);
        }

        var workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "adcomputers", request.RunId);
        Directory.CreateDirectory(workDir);
        var outputPath = Path.Combine(workDir, "out.json");

        var sw = Stopwatch.StartNew();
        try
        {
            if (File.Exists(outputPath)) File.Delete(outputPath);
            var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var psi = new ProcessStartInfo(powershell, AdComputersShape.PowerShellArguments(scriptPath, outputPath, request.BudgetMs))
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = workDir
            };

            IpcLog.Write($"[amp.ad.computers] begin run={request.RunId} budgetMs={request.BudgetMs}");
            var result = SecurityCompliance.RunProcessWithTimeout(psi, AdComputersShape.ProcessTimeoutMs(request));
            sw.Stop();

            if (result.TimedOut)
            {
                IpcLog.Write($"[amp.ad.computers] timeout run={request.RunId} ({sw.ElapsedMilliseconds}ms)");
                return PrivSvcResponse.Fail(req.Id, "script_timeout", $"exceeded {AdComputersShape.ProcessTimeoutMs(request)}ms");
            }
            if (!File.Exists(outputPath))
            {
                var tail = Tail(result.Stderr);
                IpcLog.Write($"[amp.ad.computers] no output run={request.RunId} exit={result.ExitCode} stderr={tail}");
                return PrivSvcResponse.Fail(req.Id, "script_no_output", $"exit={result.ExitCode} {tail}");
            }
            var size = new FileInfo(outputPath).Length;
            if (size > AdComputersShape.MaxOutputBytes)
            {
                return PrivSvcResponse.Fail(req.Id, "script_output_too_large", $"{size} bytes");
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(outputPath));
            IpcLog.Write($"[amp.ad.computers] done run={request.RunId} exit={result.ExitCode} bytes={size} ({sw.ElapsedMilliseconds}ms)");
            return PrivSvcResponse.Success(req.Id, doc.RootElement.Clone());
        }
        catch (Exception ex)
        {
            IpcLog.Write($"[amp.ad.computers] EXCEPTION {ex.GetType().Name}: {ex.Message}");
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
