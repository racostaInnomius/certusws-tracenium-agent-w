// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AspCollectorShape.cs
//
// ADR-0022 — la parte SIN Windows de `asp.ad.collect`: validar la tanda que
// manda el agente, construir el JSON de entrada del colector y los argumentos
// de PowerShell. Vive aparte de AspCollector.cs por la misma razón que
// RegistryProbeShape.cs: el proyecto de pruebas es net8.0 multiplataforma y no
// compila nada que toque Win32.
//
// ── El contrato que estas funciones sostienen ────────────────────────
//
//   · El PrivSvc NO interpreta el catálogo: comprueba que cada consulta sea de
//     un tipo que el script conoce y la reenvía como datos. Un tipo desconocido
//     rechaza la tanda entera — mejor un fallo visible que un script que
//     recibe algo que no sabe tratar.
//   · El script se lanza SIEMPRE con `-File` y una ruta fija junto al binario.
//     Nunca `-EncodedCommand` ni `-Command`: AMSI bloqueó el cargador
//     codificado en el spike de la fase 0.
//   · El techo del handler (300 s) es el que ordena el invariante
//     job > cliente IPC (330 s) > handler; el agente pide menos y aquí se
//     recorta a ese techo, nunca se amplía.

using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed record AspBatchRequest(string RunId, int Batch, int EvidenceLimit, int BudgetMs, string InputJson, int QueryCount);

public static class AspCollectorShape
{
    /// <summary>Techo del handler por tanda. Ver el invariante en la cabecera.</summary>
    public const int HandlerCeilingMs = 300_000;

    /// <summary>Lo que se reserva para arrancar PowerShell y escribir la salida.</summary>
    public const int ProcessOverheadMs = 15_000;

    public const int MaxQueriesPerBatch = 50;
    public const int MaxInputBytes = 256 * 1024;
    public const int MaxOutputBytes = 8 * 1024 * 1024;

    public const string ScriptFileName = "asp-ad-collector.ps1";

    public static readonly IReadOnlySet<string> QueryKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "ldap_search", "ldap_object", "group_members", "acl", "acl_search", "rootdse", "sysvol_files", "registry"
    };

    private static readonly Regex RunIdRe = new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.Compiled);
    private static readonly Regex ControlIdRe = new("^ASP-[A-Z]{2,6}-[A-Z]{2,4}-\\d{3}$", RegexOptions.Compiled);

    /// <summary>
    /// Valida `params` de la petición IPC. Devuelve la tanda lista para el
    /// script, o el código de error estable que viaja al agente.
    /// </summary>
    public static (AspBatchRequest? Request, string? Error) Validate(Dictionary<string, object>? parameters)
    {
        if (parameters is null) return (null, "bad_request:no_params");

        var runId = ReadString(parameters, "runId");
        if (runId is null || !RunIdRe.IsMatch(runId)) return (null, "bad_request:run_id");

        var batch = ReadInt(parameters, "batch") ?? -1;
        if (batch < 0 || batch > 1000) return (null, "bad_request:batch");

        var limit = ReadInt(parameters, "evidenceLimit") ?? 200;
        if (limit < 1 || limit > 200) return (null, "bad_request:evidence_limit");

        var budget = ReadInt(parameters, "budgetMs") ?? HandlerCeilingMs;
        if (budget < 1_000) return (null, "bad_request:budget");
        // El script se detiene antes que el handler: su presupuesto es el pedido
        // recortado al techo, menos lo que cuesta arrancar y escribir.
        var scriptBudget = Math.Max(1_000, Math.Min(budget, HandlerCeilingMs) - ProcessOverheadMs);

        if (!parameters.TryGetValue("queries", out var raw) || raw is not JsonElement queries || queries.ValueKind != JsonValueKind.Array)
            return (null, "bad_request:queries");

        var count = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in queries.EnumerateArray())
        {
            count++;
            if (count > MaxQueriesPerBatch) return (null, "bad_request:too_many_queries");
            if (item.ValueKind != JsonValueKind.Object) return (null, "bad_request:query_shape");
            if (!item.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String || !ControlIdRe.IsMatch(id.GetString() ?? ""))
                return (null, "bad_request:query_id");
            if (!seen.Add(id.GetString()!)) return (null, "bad_request:duplicated_query_id");
            if (!item.TryGetProperty("query", out var q) || q.ValueKind != JsonValueKind.Object) return (null, "bad_request:query_shape");
            if (!q.TryGetProperty("kind", out var kind) || kind.ValueKind != JsonValueKind.String || !QueryKinds.Contains(kind.GetString() ?? ""))
                return (null, "bad_request:query_kind");
            if (kind.GetString() == "registry")
            {
                if (!q.TryGetProperty("path", out var path) || path.ValueKind != JsonValueKind.String
                    || !(path.GetString() ?? "").StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
                    return (null, "bad_request:registry_path");
            }
        }
        if (count == 0) return (null, "bad_request:queries");

        var input = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["runId"] = runId,
            ["batch"] = batch,
            ["evidenceLimit"] = limit,
            ["budgetMs"] = scriptBudget,
            ["queries"] = queries
        });
        if (System.Text.Encoding.UTF8.GetByteCount(input) > MaxInputBytes) return (null, "bad_request:input_too_large");

        return (new AspBatchRequest(runId.ToLowerInvariant(), batch, limit, scriptBudget, input, count), null);
    }

    /// <summary>
    /// Argumentos de powershell.exe. `-File` con ruta entre comillas; nada del
    /// catálogo llega a la línea de comandos: viaja en el fichero de entrada.
    /// </summary>
    public static string PowerShellArguments(string scriptPath, string inputPath, string outputPath)
    {
        foreach (var p in new[] { scriptPath, inputPath, outputPath })
        {
            if (p.IndexOf('"') >= 0) throw new ArgumentException("path contains a quote");
        }
        return $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\" -InputPath \"{inputPath}\" -OutputPath \"{outputPath}\"";
    }

    /// <summary>El techo real del proceso: el presupuesto del script más el arranque.</summary>
    public static int ProcessTimeoutMs(AspBatchRequest request) =>
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
