// La lectura de impresoras de MÁQUINA: qué dijo PowerShell y qué se concluye.
//
// ⚠️ Este fichero existe por un borrado. El script terminaba en
// `catch { '[]' }` y un JSON que no parseaba se tragaba como lista vacía: un
// Spooler deshabilitado, un `Get-Printer` que no existe en el SKU o una salida
// corrupta llegaban al agente como `machineScope: "collected"` con CERO
// impresoras — una lectura buena y vacía. El agente la aplica como "se fueron
// todas" y el backend borra las filas del equipo.
//
// Lo que no se puede probar aquí es lanzar PowerShell en Windows; el script y
// su interpretación son texto, y eso sí.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class PrinterInventoryShapeTests
{
    [Fact]
    public void UnaListaVaciaDeVerdadEsCollected()
    {
        // `'[]'` sólo lo emite ahora la rama de éxito con cero impresoras.
        var r = PrinterInventoryShape.ParseMachineOutput("[]");
        Assert.Equal(PrinterInventoryShape.ScopeCollected, r.Scope);
        Assert.Empty(r.Items);
        Assert.Null(r.Error);
    }

    [Fact]
    public void ElMarcadorDeErrorEsUnavailableConSuMotivo()
    {
        var r = PrinterInventoryShape.ParseMachineOutput(
            PrinterInventoryShape.ErrorMarker + " The term 'Get-Printer' is not recognized");
        Assert.Equal(PrinterInventoryShape.ScopeUnavailable, r.Scope);
        Assert.Empty(r.Items);
        Assert.Contains("Get-Printer", r.Error);
    }

    [Theory]
    [InlineData("{\"name\": \"HP\"")]          // truncado
    [InlineData("WARNING: algo [{\"name\":1}]")] // basura delante
    [InlineData("42")]
    [InlineData("\"texto\"")]
    [InlineData("null")]
    public void UnaSalidaQueNoEsUnaListaNoEsUnaLecturaBuena(string stdout)
    {
        // Antes: JsonException → items vacíos → "collected". El borrado.
        var r = PrinterInventoryShape.ParseMachineOutput(stdout);
        Assert.Equal(PrinterInventoryShape.ScopeUnavailable, r.Scope);
        Assert.Empty(r.Items);
        Assert.NotNull(r.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \r\n")]
    public void SinSalidaEsEmptyOutput(string? stdout)
    {
        var r = PrinterInventoryShape.ParseMachineOutput(stdout);
        Assert.Equal(PrinterInventoryShape.ScopeEmptyOutput, r.Scope);
        Assert.Empty(r.Items);
    }

    [Fact]
    public void UnaSolaImpresoraLlegaComoObjetoYSeEnvuelve()
    {
        // ConvertTo-Json con un solo elemento en el pipeline emite un objeto, no
        // un array: PowerShell-ismo que hay que normalizar.
        var r = PrinterInventoryShape.ParseMachineOutput("{\"name\":\"HP LaserJet\",\"portName\":\"USB001\"}");
        Assert.Equal(PrinterInventoryShape.ScopeCollected, r.Scope);
        Assert.Single(r.Items);
        Assert.Equal(new[] { "HP LaserJet" }, r.Names);
    }

    [Fact]
    public void VariasImpresorasLleganComoArray()
    {
        var r = PrinterInventoryShape.ParseMachineOutput("[{\"name\":\"HP\"},{\"name\":\"Microsoft Print to PDF\"}]");
        Assert.Equal(PrinterInventoryShape.ScopeCollected, r.Scope);
        Assert.Equal(new[] { "HP", "Microsoft Print to PDF" }, r.Names);
    }

    [Fact]
    public void ElScriptNoConvierteUnFalloEnListaVacia()
    {
        // La regla, sobre el texto que se ejecuta: el catch emite el marcador y
        // la lista vacía sólo sale de la rama de éxito. Volver a `catch { '[]' }`
        // reabre el borrado sin que ningún otro test lo note.
        var script = PrinterInventoryShape.Script;
        var catchAt = script.IndexOf("} catch {", StringComparison.Ordinal);
        Assert.True(catchAt > 0, "el script ya no tiene catch");
        var catchBody = script.Substring(catchAt);
        Assert.Contains("TRACENIUM_PRINTER_ERROR:", catchBody);
        Assert.DoesNotContain("'[]'", catchBody);
        Assert.Equal(PrinterInventoryShape.ErrorMarker, "TRACENIUM_PRINTER_ERROR:");
    }
}
