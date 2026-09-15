// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AdPrintersShape.cs
//
// ADR-0023 — la parte PURA de `amp.ad.printers`: validar la petición, construir
// los argumentos de PowerShell y fijar los plazos. Sin Win32, para que la suite
// net8.0 la compile y la pruebe en un Mac (misma convención que AspCollectorShape).
//
// ⚠️ ORDEN DE PLAZOS (invariante de timeouts IPC, de dentro afuera):
//   script: presupuesto pedido por el agente (100 s), recortado a
//           HandlerCeilingMs − ProcessOverheadMs
//   handler: HandlerCeilingMs = 120 s
//   cliente IPC del agente: 150 s (privsvc-client-windows.ts)
//   job: 300 s (backend, AD_PRINTERS_JOB_TIMEOUT_SECONDS)

using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed record AdPrintersRequest(string RunId, int BudgetMs);

public static class AdPrintersShape
{
    public const int HandlerCeilingMs = 120_000;
    public const int ProcessOverheadMs = 10_000;
    public const int MinBudgetMs = 10_000;
    public const int MaxOutputBytes = 4 * 1024 * 1024;
    public const string ScriptFileName = "ad-printers.ps1";

    private static readonly Regex RunIdRe = new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.Compiled);

    public static (AdPrintersRequest? Request, string? Error) Validate(Dictionary<string, object>? parameters)
    {
        if (parameters is null) return (null, "bad_request:no_params");
        var runId = ReadString(parameters, "runId");
        if (runId is null || !RunIdRe.IsMatch(runId)) return (null, "bad_request:run_id");

        var budget = ReadInt(parameters, "budgetMs") ?? 100_000;
        var ceiling = HandlerCeilingMs - ProcessOverheadMs;
        budget = Math.Clamp(budget, MinBudgetMs, ceiling);
        return (new AdPrintersRequest(runId.ToLowerInvariant(), budget), null);
    }

    /// <summary>
    /// `-File` con rutas entre comillas; nunca `-EncodedCommand`: AMSI bloqueó un
    /// cargador codificado que hacía consultas LDAP (spike de ADR-0022).
    /// </summary>
    public static string PowerShellArguments(string scriptPath, string outputPath, int budgetMs)
    {
        foreach (var p in new[] { scriptPath, outputPath })
        {
            if (p.IndexOf('"') >= 0) throw new ArgumentException("path contains a quote");
        }
        return $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\" -OutputPath \"{outputPath}\" -BudgetMs {budgetMs}";
    }

    public static int ProcessTimeoutMs(AdPrintersRequest request) =>
        Math.Min(HandlerCeilingMs, request.BudgetMs + ProcessOverheadMs);

    private static string? ReadString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v is null) return null;
        if (v is JsonElement el) return el.ValueKind == JsonValueKind.String ? el.GetString() : null;
        return v as string;
    }

    private static int? ReadInt(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v is null) return null;
        if (v is JsonElement el) return el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var n) ? n : null;
        return v switch { int i => i, long l when l is >= int.MinValue and <= int.MaxValue => (int)l, _ => null };
    }
}
