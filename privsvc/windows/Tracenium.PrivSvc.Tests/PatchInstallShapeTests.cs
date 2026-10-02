// privsvc/windows/Tracenium.PrivSvc.Tests/PatchInstallShapeTests.cs
//
// patch.install escribe la selección dentro de un script de PowerShell que
// corre como SYSTEM. Hasta el 1-oct-2026 cada id iba con JsonSerializer dentro
// de una cadena entre comillas dobles, y `KB1$(…)` ejecutaba lo de dentro.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class PatchInstallShapeTests
{
    [Theory]
    [InlineData("KB5129195")]
    [InlineData("kb2267602")]
    [InlineData(" KB4052623 ")]
    public void Acepta_articulos_KB(string id)
    {
        Assert.Empty(PatchInstallShape.MalformedKbIds(new[] { id }));
    }

    [Theory]
    [InlineData("KB1$(Restart-Computer -Force)")]
    [InlineData("KB1$env:TEMP")]
    [InlineData("KB1\"; whoami; \"")]
    [InlineData("KB1'")]
    [InlineData("KB1`n")]
    [InlineData("5066747")]
    [InlineData("python3-apt-2.7.7ubuntu5.3")]
    [InlineData("")]
    public void Rechaza_lo_que_no_es_KB_mas_digitos(string id)
    {
        Assert.Single(PatchInstallShape.MalformedKbIds(new[] { "KB5129195", id }));
    }

    [Fact]
    public void El_literal_va_entre_comillas_simples_y_en_mayusculas()
    {
        Assert.Equal("'KB5129195','KB2267602'", PatchInstallShape.PowerShellKbList(new[] { "KB5129195", " kb2267602 " }));
    }

    [Fact]
    public void Nunca_escribe_un_id_sin_validar()
    {
        Assert.Throws<ArgumentException>(() => PatchInstallShape.PowerShellKbList(new[] { "KB1$(whoami)" }));
    }
}
