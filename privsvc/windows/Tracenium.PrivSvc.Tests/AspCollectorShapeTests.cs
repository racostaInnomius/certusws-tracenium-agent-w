// privsvc/windows/Tracenium.PrivSvc.Tests/AspCollectorShapeTests.cs
//
// ADR-0022 — el contrato de `asp.ad.collect` que se puede probar sin Windows:
// qué tanda se acepta, con qué presupuesto, y que el script sólo se lanza con
// -File. Lo que NO se prueba aquí (WinVerifyTrust, el proceso real) está escrito
// en la cabecera de AspCollector.cs.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AspCollectorShapeTests
{
    private const string RunId = "5b1f6a52-8d34-4c41-9a0e-1f6c2d3e4a5b";

    private static Dictionary<string, object> Params(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, object>>(json)!;

    private static string Batch(string queries, int budgetMs = 120_000) =>
        $"{{\"runId\":\"{RunId}\",\"batch\":0,\"evidenceLimit\":200,\"budgetMs\":{budgetMs},\"queries\":{queries}}}";

    private const string OneLdap = "[{\"id\":\"ASP-AD-KRB-002\",\"query\":{\"kind\":\"ldap_search\",\"base\":\"{domainDn}\",\"filter\":\"(adminCount=1)\"}}]";

    [Fact]
    public void Validate_AcceptsAWellFormedBatch_AndForwardsQueriesAsData()
    {
        var (req, err) = AspCollectorShape.Validate(Params(Batch(OneLdap)));
        Assert.Null(err);
        Assert.NotNull(req);
        Assert.Equal(1, req!.QueryCount);
        using var doc = JsonDocument.Parse(req.InputJson);
        Assert.Equal("(adminCount=1)", doc.RootElement.GetProperty("queries")[0].GetProperty("query").GetProperty("filter").GetString());
    }

    [Fact]
    public void Validate_AcceptsAclSearch_TheKindTheScriptGainedInCatalog110()
    {
        const string q = "[{\"id\":\"ASP-AD-PRV-007\",\"query\":{\"kind\":\"acl_search\",\"base\":\"{domainDn}\",\"filter\":\"(adminCount=1)\",\"rights\":[\"GenericAll\"]}}]";
        var (req, err) = AspCollectorShape.Validate(Params(Batch(q)));
        Assert.Null(err);
        Assert.Equal(1, req!.QueryCount);
    }

    [Theory]
    [InlineData("[{\"id\":\"ASP-AD-KRB-002\",\"query\":{\"kind\":\"powershell\",\"script\":\"Remove-Item C:\\\\\"}}]", "bad_request:query_kind")]
    [InlineData("[{\"id\":\"rm -rf\",\"query\":{\"kind\":\"ldap_search\"}}]", "bad_request:query_id")]
    [InlineData("[{\"id\":\"ASP-AD-DC-001\",\"query\":{\"kind\":\"registry\",\"path\":\"HKCU\\\\Software\",\"name\":\"x\"}}]", "bad_request:registry_path")]
    [InlineData("[]", "bad_request:queries")]
    public void Validate_RejectsAnythingTheScriptDoesNotKnow(string queries, string expected)
    {
        var (req, err) = AspCollectorShape.Validate(Params(Batch(queries)));
        Assert.Null(req);
        Assert.Equal(expected, err);
    }

    [Fact]
    public void Validate_RejectsDuplicatedQueryIds()
    {
        var dup = "[" + OneLdap.Trim('[', ']') + "," + OneLdap.Trim('[', ']') + "]";
        Assert.Equal("bad_request:duplicated_query_id", AspCollectorShape.Validate(Params(Batch(dup))).Error);
    }

    [Fact]
    public void Validate_RejectsABadRunId()
    {
        var json = Batch(OneLdap).Replace(RunId, "../../Windows");
        Assert.Equal("bad_request:run_id", AspCollectorShape.Validate(Params(json)).Error);
    }

    [Fact]
    public void Budget_IsClampedToTheHandlerCeiling_NeverWidened()
    {
        // El agente pide 900 s: el handler NUNCA se sale de su techo (300 s), y el
        // script se detiene antes que el proceso para poder escribir su salida.
        var (req, _) = AspCollectorShape.Validate(Params(Batch(OneLdap, budgetMs: 900_000)));
        Assert.Equal(AspCollectorShape.HandlerCeilingMs - AspCollectorShape.ProcessOverheadMs, req!.BudgetMs);
        Assert.True(AspCollectorShape.ProcessTimeoutMs(req) <= AspCollectorShape.HandlerCeilingMs);
        Assert.True(AspCollectorShape.ProcessTimeoutMs(req) > req.BudgetMs);
    }

    [Fact]
    public void HandlerCeiling_StaysBelowTheWindowsClientBudget()
    {
        // THE INVARIANT: cliente IPC de Windows 330 s (privsvc-client-windows.ts)
        // > handler. Pineado a mano: los dos lados no comparten código.
        Assert.True(AspCollectorShape.HandlerCeilingMs < 330_000);
    }

    [Fact]
    public void PowerShellArguments_UseFile_NeverEncodedCommand()
    {
        var args = AspCollectorShape.PowerShellArguments(@"C:\Program Files\Tracenium\PrivSvc\Scripts\asp-ad-collector.ps1", @"C:\ProgramData\Tracenium\asp\x\in.json", @"C:\ProgramData\Tracenium\asp\x\out.json");
        Assert.Contains("-File \"C:\\Program Files\\Tracenium\\PrivSvc\\Scripts\\asp-ad-collector.ps1\"", args);
        Assert.DoesNotContain("EncodedCommand", args, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-Command", args, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("-NonInteractive", args);
    }

    [Fact]
    public void PowerShellArguments_RefuseAPathThatCouldBreakQuoting()
    {
        Assert.Throws<ArgumentException>(() => AspCollectorShape.PowerShellArguments("C:\\a\" -Command \"evil", "in", "out"));
    }
}
