// privsvc/windows/Tracenium.PrivSvc.Tests/UpdateHistoryShapeTests.cs
//
// El historial de Windows Update, en tres listas.
//
// Hasta el 22-sep-2026 el script descartaba en el propio equipo los fallos,
// los abortos y las desinstalaciones: la materia prima del Confidence Score de
// parches no salía nunca del equipo. Lo que se fija aquí:
//
//   · `items` sigue siendo SÓLO instalaciones correctas (lo leen `count` y los
//     checks de SCP): un fallo ahí contaría como equipo parcheado;
//   · los fallos y las desinstalaciones llegan, cada uno a su lista;
//   · una salida vieja, rota o parcial nunca cuesta las instalaciones correctas.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class UpdateHistoryShapeTests
{
    private static string Str(Dictionary<string, object> row, string key) =>
        row[key] is JsonElement el ? el.ToString() : row[key]?.ToString() ?? "";

    [Fact]
    public void Las_tres_listas_llegan_cada_una_a_su_sitio()
    {
        const string output = @"{
          ""items"": [
            { ""hotFixId"": ""KB5122882"", ""installedOn"": ""2026-09-20T00:31:39Z"", ""resultCode"": 2, ""operation"": ""install"" }
          ],
          ""failures"": [
            { ""hotFixId"": ""KB5120708"", ""attemptedOn"": ""2026-09-10T03:00:00Z"", ""resultCode"": 4, ""hresult"": ""0x80070070"", ""operation"": ""install"" },
            { ""hotFixId"": ""KB5120708"", ""attemptedOn"": ""2026-09-09T03:00:00Z"", ""resultCode"": 5, ""hresult"": ""0x80240017"", ""operation"": ""install"" }
          ],
          ""uninstalls"": [
            { ""hotFixId"": ""KB5094126"", ""attemptedOn"": ""2026-08-15T10:00:00Z"", ""resultCode"": 2, ""hresult"": ""0x00000000"", ""operation"": ""uninstall"" }
          ]
        }";

        var (items, failures, uninstalls) = UpdateHistoryShape.ParseBuckets(output);

        Assert.Single(items);
        Assert.Equal("KB5122882", Str(items[0], "hotFixId"));
        Assert.Equal(2, failures.Count);
        Assert.Equal("0x80070070", Str(failures[0], "hresult"));
        Assert.Equal("4", Str(failures[0], "resultCode"));
        Assert.Single(uninstalls);
        Assert.Equal("uninstall", Str(uninstalls[0], "operation"));
    }

    [Fact]
    public void Un_fallo_nunca_entra_en_items()
    {
        // ⭐ La regla que protege a los checks de SCP: `count` = items.Count.
        const string output = @"{ ""items"": [], ""failures"": [ { ""hotFixId"": ""KB1"", ""resultCode"": 4 } ], ""uninstalls"": [] }";
        var (items, failures, _) = UpdateHistoryShape.ParseBuckets(output);
        Assert.Empty(items);
        Assert.Single(failures);
    }

    [Fact]
    public void La_salida_de_antes_un_array_suelto_se_lee_como_items()
    {
        // La forma que imprimía el script antes de este cambio.
        var (items, failures, uninstalls) = UpdateHistoryShape.ParseBuckets(
            @"[ { ""hotFixId"": ""KB1"" }, { ""hotFixId"": ""KB2"" } ]");
        Assert.Equal(2, items.Count);
        Assert.Empty(failures);
        Assert.Empty(uninstalls);
    }

    [Fact]
    public void Un_objeto_suelto_donde_iba_un_array_de_uno_se_acepta()
    {
        // PowerShell desenvuelve un array de un elemento si se le escapa un pipe.
        var (_, failures, _) = UpdateHistoryShape.ParseBuckets(
            @"{ ""items"": [], ""failures"": { ""hotFixId"": ""KB9"", ""resultCode"": 4 } }");
        Assert.Single(failures);
        Assert.Equal("KB9", Str(failures[0], "hotFixId"));
    }

    [Fact]
    public void Sin_las_claves_nuevas_no_se_pierden_las_instalaciones()
    {
        var (items, failures, uninstalls) = UpdateHistoryShape.ParseBuckets(
            @"{ ""items"": [ { ""hotFixId"": ""KB1"" } ] }");
        Assert.Single(items);
        Assert.Empty(failures);
        Assert.Empty(uninstalls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no es json")]
    [InlineData("42")]
    public void Una_salida_rota_da_tres_listas_vacias_sin_excepcion(string? output)
    {
        var (items, failures, uninstalls) = UpdateHistoryShape.ParseBuckets(output);
        Assert.Empty(items);
        Assert.Empty(failures);
        Assert.Empty(uninstalls);
    }
}
