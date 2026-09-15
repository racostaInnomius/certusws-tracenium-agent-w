// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AspCollector.cs
//
// ADR-0022 — `asp.ad.collect`: ejecuta una tanda de consultas del catálogo de
// Assessment Service con el colector `.ps1` firmado, como LocalSystem.
//
// ⚠️ CARRIL. El cliente de Windows le da 330 s, así que `laneForMethod` lo
// manda al carril LENTO: una tanda larga no deja sin latidos al stream gRPC
// (lección de patch_install, Msig13, 2026-09-04). El agente parte la corrida
// en tandas y sostiene el presupuesto total de 900 s; aquí sólo hay una tanda.
//
// ⚠️ FIRMA. El script vive en disco junto al binario (Scripts\) y se lanza con
// `-File`. Si el propio PrivSvc está firmado —cualquier build de release—, el
// script TIENE que pasar WinVerifyTrust o no se ejecuta: un .ps1 sustituido en
// Program Files correría como SYSTEM en un controlador de dominio. En un build
// de desarrollo sin firmar se ejecuta y se registra.
//
// SÓLO LECTURA: ni este handler ni el script escriben en AD ni en el registro.

using System.Diagnostics;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AspCollector
{
    public static Task<PrivSvcResponse> HandleCollect(PrivSvcRequest req) => Task.Run(() => Collect(req));

    private static PrivSvcResponse Collect(PrivSvcRequest req)
    {
        var (request, error) = AspCollectorShape.Validate(req.Params);
        if (request is null) return PrivSvcResponse.Fail(req.Id, "bad_request", error ?? "bad_request");

        var scriptPath = Path.Combine(AppContext.BaseDirectory, "Scripts", AspCollectorShape.ScriptFileName);
        if (!File.Exists(scriptPath))
        {
            IpcLog.Write($"[asp.ad.collect] script missing path={scriptPath}");
            return PrivSvcResponse.Fail(req.Id, "collector_script_missing", scriptPath);
        }

        var (trusted, reason) = SignedScripts.Verify(scriptPath, "asp.ad.collect");
        if (!trusted)
        {
            IpcLog.Write($"[asp.ad.collect] script signature rejected reason={reason}");
            return PrivSvcResponse.Fail(req.Id, "collector_script_untrusted", reason);
        }

        var workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "asp", request.RunId);
        Directory.CreateDirectory(workDir);
        var inputPath = Path.Combine(workDir, $"batch-{request.Batch}-in.json");
        var outputPath = Path.Combine(workDir, $"batch-{request.Batch}-out.json");

        var sw = Stopwatch.StartNew();
        try
        {
            File.WriteAllText(inputPath, request.InputJson);
            if (File.Exists(outputPath)) File.Delete(outputPath);

            var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var psi = new ProcessStartInfo(powershell, AspCollectorShape.PowerShellArguments(scriptPath, inputPath, outputPath))
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = workDir
            };

            IpcLog.Write($"[asp.ad.collect] begin run={request.RunId} batch={request.Batch} queries={request.QueryCount} budgetMs={request.BudgetMs}");
            var result = SecurityCompliance.RunProcessWithTimeout(psi, AspCollectorShape.ProcessTimeoutMs(request));
            sw.Stop();

            if (result.TimedOut)
            {
                IpcLog.Write($"[asp.ad.collect] timeout run={request.RunId} batch={request.Batch} ({sw.ElapsedMilliseconds}ms)");
                return PrivSvcResponse.Fail(req.Id, "collector_timeout", $"batch {request.Batch} exceeded {AspCollectorShape.ProcessTimeoutMs(request)}ms");
            }
            if (!File.Exists(outputPath))
            {
                var tail = Tail(result.Stderr);
                IpcLog.Write($"[asp.ad.collect] no output run={request.RunId} batch={request.Batch} exit={result.ExitCode} stderr={tail}");
                return PrivSvcResponse.Fail(req.Id, "collector_no_output", $"exit={result.ExitCode} {tail}");
            }
            var size = new FileInfo(outputPath).Length;
            if (size > AspCollectorShape.MaxOutputBytes)
            {
                return PrivSvcResponse.Fail(req.Id, "collector_output_too_large", $"{size} bytes");
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(outputPath));
            IpcLog.Write($"[asp.ad.collect] done run={request.RunId} batch={request.Batch} exit={result.ExitCode} bytes={size} ({sw.ElapsedMilliseconds}ms)");
            return PrivSvcResponse.Success(req.Id, doc.RootElement.Clone());
        }
        catch (Exception ex)
        {
            IpcLog.Write($"[asp.ad.collect] EXCEPTION {ex.GetType().Name}: {ex.Message}");
            return PrivSvcResponse.Fail(req.Id, "collector_error", ex.Message);
        }
        finally
        {
            // La evidencia no se queda en disco: la corrida vive en la SQLite del
            // agente, no en ProgramData.
            TryDelete(inputPath);
            TryDelete(outputPath);
            try { if (Directory.Exists(workDir) && !Directory.EnumerateFileSystemEntries(workDir).Any()) Directory.Delete(workDir); } catch { }
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static string Tail(string s) => s.Length <= 300 ? s.Trim() : s[^300..].Trim();
}
