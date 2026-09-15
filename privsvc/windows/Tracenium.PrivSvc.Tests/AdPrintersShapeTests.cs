// ADR-0023 — la parte pura de `amp.ad.printers`: petición, argumentos y plazos.
// Lanzar PowerShell y WinVerifyTrust viven en AdPrinters.cs / SignedScripts.cs y
// no se prueban aquí.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AdPrintersShapeTests
{
    private const string Run = "3F1C2B7A-8D4E-4F6A-9B1C-2D3E4F5A6B7C";

    private static Dictionary<string, object> Params(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!
            .ToDictionary(kv => kv.Key, kv => (object)kv.Value);

    [Fact]
    public void UnaPeticionBuenaNormalizaElRunId()
    {
        var (req, err) = AdPrintersShape.Validate(Params($"{{\"runId\":\"{Run}\",\"budgetMs\":100000}}"));
        Assert.Null(err);
        Assert.Equal(Run.ToLowerInvariant(), req!.RunId);
        Assert.Equal(100_000, req.BudgetMs);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"runId\":\"nope\"}")]
    [InlineData("{\"runId\":42}")]
    public void SinRunIdValidoNoHayPeticion(string json)
    {
        var (req, err) = AdPrintersShape.Validate(Params(json));
        Assert.Null(req);
        Assert.Equal("bad_request:run_id", err);
    }

    [Fact]
    public void ElPresupuestoNuncaSuperaElTechoDelHandler()
    {
        // Si el script pudiera usar todo el techo, el handler lo mataría antes de
        // que escribiera la salida y el agente sólo vería un timeout sin motivo.
        var (big, _) = AdPrintersShape.Validate(Params($"{{\"runId\":\"{Run}\",\"budgetMs\":900000}}"));
        Assert.Equal(AdPrintersShape.HandlerCeilingMs - AdPrintersShape.ProcessOverheadMs, big!.BudgetMs);
        Assert.True(AdPrintersShape.ProcessTimeoutMs(big) <= AdPrintersShape.HandlerCeilingMs);

        var (tiny, _) = AdPrintersShape.Validate(Params($"{{\"runId\":\"{Run}\",\"budgetMs\":1}}"));
        Assert.Equal(AdPrintersShape.MinBudgetMs, tiny!.BudgetMs);
    }

    [Fact]
    public void ElScriptVaPorFileNuncaCodificado()
    {
        var args = AdPrintersShape.PowerShellArguments(@"C:\Program Files\Tracenium\PrivSvc\Scripts\ad-printers.ps1", @"C:\ProgramData\Tracenium\adprinters\x\out.json", 100000);
        Assert.Contains("-File \"C:\\Program Files\\Tracenium\\PrivSvc\\Scripts\\ad-printers.ps1\"", args);
        Assert.Contains("-OutputPath \"C:\\ProgramData\\Tracenium\\adprinters\\x\\out.json\" -BudgetMs 100000", args);
        Assert.DoesNotContain("EncodedCommand", args, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-Command", args);
    }

    [Fact]
    public void UnaRutaConComillasSeRechaza()
    {
        Assert.Throws<ArgumentException>(() => AdPrintersShape.PowerShellArguments("C:\\a\"b.ps1", "C:\\out.json", 10000));
    }
}
