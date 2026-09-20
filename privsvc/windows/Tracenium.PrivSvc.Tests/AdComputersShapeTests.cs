// Cobertura — la parte pura de `amp.ad.computers`: petición, argumentos y plazos.
// Lanzar PowerShell y WinVerifyTrust viven en AdComputers.cs / SignedScripts.cs y
// no se prueban aquí.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AdComputersShapeTests
{
    private const string Run = "3F1C2B7A-8D4E-4F6A-9B1C-2D3E4F5A6B7C";

    private static Dictionary<string, object> Params(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!
            .ToDictionary(kv => kv.Key, kv => (object)kv.Value);

    [Fact]
    public void UnaPeticionBuenaNormalizaElRunId()
    {
        var (req, err) = AdComputersShape.Validate(Params($"{{\"runId\":\"{Run}\",\"budgetMs\":100000}}"));
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
        var (req, err) = AdComputersShape.Validate(Params(json));
        Assert.Null(req);
        Assert.Equal("bad_request:run_id", err);
    }

    [Fact]
    public void ElPresupuestoNuncaSuperaElTechoDelHandler()
    {
        // Si el script pudiera usar todo el techo, el handler lo mataría antes de
        // que escribiera la salida y el agente sólo vería un timeout sin motivo.
        var (big, _) = AdComputersShape.Validate(Params($"{{\"runId\":\"{Run}\",\"budgetMs\":900000}}"));
        Assert.Equal(AdComputersShape.HandlerCeilingMs - AdComputersShape.ProcessOverheadMs, big!.BudgetMs);
        Assert.True(AdComputersShape.ProcessTimeoutMs(big) <= AdComputersShape.HandlerCeilingMs);

        var (tiny, _) = AdComputersShape.Validate(Params($"{{\"runId\":\"{Run}\",\"budgetMs\":1}}"));
        Assert.Equal(AdComputersShape.MinBudgetMs, tiny!.BudgetMs);
    }

    [Fact]
    public void ElScriptVaPorFileNuncaCodificado()
    {
        var args = AdComputersShape.PowerShellArguments(@"C:\Program Files\Tracenium\PrivSvc\Scripts\ad-computers.ps1", @"C:\ProgramData\Tracenium\adcomputers\x\out.json", 100000);
        Assert.Contains("-File \"C:\\Program Files\\Tracenium\\PrivSvc\\Scripts\\ad-computers.ps1\"", args);
        Assert.Contains("-OutputPath \"C:\\ProgramData\\Tracenium\\adcomputers\\x\\out.json\" -BudgetMs 100000", args);
        // El tope de objetos viaja SIEMPRE: sin él, un AD grande devolvería un
        // JSON que el handler rechaza por tamaño y la corrida acabaría en un
        // «sin salida» sin motivo aparente.
        Assert.Contains($"-MaxComputers {AdComputersShape.MaxComputers}", args);
        Assert.DoesNotContain("EncodedCommand", args, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-Command", args);
    }

    [Fact]
    public void UnaRutaConComillasSeRechaza()
    {
        Assert.Throws<ArgumentException>(() => AdComputersShape.PowerShellArguments("C:\\a\"b.ps1", "C:\\out.json", 10000));
    }
}
