// privsvc/windows/Tracenium.PrivSvc.Tests/RegistryProbeShapeTests.cs
//
// Fija el contrato de la parte pura del lector de sondas de registro.
// Lo que NO se puede probar aquí (la lectura real con
// Microsoft.Win32.Registry) tiene su contrato escrito en la cabecera de
// RegistryProbes.cs: ausente → omitido, nunca null.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class RegistryProbeShapeTests
{
    // ── Parse ────────────────────────────────────────────────────────

    [Fact]
    public void Parse_SplitsAtLastColon_AndStripsHive()
    {
        var r = RegistryProbeShape.Parse(@"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start");
        Assert.NotNull(r);
        Assert.Equal(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", r!.Value.SubKey);
        Assert.Equal("Start", r.Value.ValueName);
    }

    [Fact]
    public void Parse_ValueNameMayContainSpacesAndDots()
    {
        // CIS 18.9.x usa nombres con espacios y puntos en los valores.
        var r = RegistryProbeShape.Parse(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowBasic");
        Assert.NotNull(r);
        var r2 = RegistryProbeShape.Parse(@"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCdm");
        Assert.NotNull(r2);
        Assert.Equal(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", r2!.Value.SubKey);
        Assert.Equal("fDisableCdm", r2.Value.ValueName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"HKCU\Software\Policies\Foo:Bar")]     // sólo HKLM: HKCU de SYSTEM no es el del usuario
    [InlineData(@"HKEY_LOCAL_MACHINE\Software\Foo:Bar")] // forma larga no admitida: se normaliza aguas arriba
    [InlineData(@"HKLM\Software\Foo")]                   // sin nombre de valor
    [InlineData(@"HKLM\Software\Foo:")]                  // nombre vacío
    [InlineData(@"HKLM\:Bar")]                           // subclave vacía
    [InlineData(@"HKLM:Bar")]                            // sin barra tras el hive
    public void Parse_RejectsMalformedProbes(string? probe)
    {
        Assert.Null(RegistryProbeShape.Parse(probe));
    }

    [Fact]
    public void Parse_IsCaseInsensitiveOnHive_AndTrimsWhitespace()
    {
        var r = RegistryProbeShape.Parse("  hklm\\Software\\Foo:Bar  ");
        Assert.NotNull(r);
        Assert.Equal(@"Software\Foo", r!.Value.SubKey);
        Assert.Equal("Bar", r.Value.ValueName);
    }

    // ── Normalize ────────────────────────────────────────────────────

    [Fact]
    public void Normalize_NumbersStayNumbers()
    {
        // REG_DWORD llega como int, REG_QWORD como long. Ambos deben salir
        // como número para que `equals: 4` del evaluador no compare "4" con 4.
        Assert.Equal(4, RegistryProbeShape.Normalize(4));
        Assert.Equal(4L, RegistryProbeShape.Normalize(4L));
        Assert.Equal(4L, RegistryProbeShape.Normalize((uint)4));
    }

    [Fact]
    public void Normalize_StringsAndMultiStringsPassThrough()
    {
        Assert.Equal("abc", RegistryProbeShape.Normalize("abc"));
        var arr = new[] { "a", "b" };
        Assert.Same(arr, RegistryProbeShape.Normalize(arr));
    }

    [Fact]
    public void Normalize_BinaryBecomesLowercaseHex()
    {
        Assert.Equal("00ff10", RegistryProbeShape.Normalize(new byte[] { 0x00, 0xFF, 0x10 }));
    }

    [Fact]
    public void Normalize_NullInNullOut()
    {
        // La decisión de OMITIR la clave ausente es del llamador
        // (RegistryProbes.Read); aquí null no se convierte en nada.
        Assert.Null(RegistryProbeShape.Normalize(null));
    }

    // ── FromParams ───────────────────────────────────────────────────

    [Fact]
    public void FromParams_ReadsJsonArrayOfStrings_AndSkipsNonStrings()
    {
        var doc = JsonDocument.Parse(@"{""registryProbes"":[""HKLM\\A:B"", 42, null, ""HKLM\\C:D""]}");
        var parameters = new Dictionary<string, object>
        {
            ["registryProbes"] = doc.RootElement.GetProperty("registryProbes")
        };
        var list = RegistryProbeShape.FromParams(parameters);
        Assert.Equal(new[] { @"HKLM\A:B", @"HKLM\C:D" }, list);
    }

    [Fact]
    public void FromParams_ReadsPlainEnumerable()
    {
        var parameters = new Dictionary<string, object>
        {
            ["registryProbes"] = new List<object> { @"HKLM\A:B", 7 }
        };
        Assert.Equal(new[] { @"HKLM\A:B" }, RegistryProbeShape.FromParams(parameters));
    }

    [Fact]
    public void FromParams_EmptyWhenMissingOrNull()
    {
        Assert.Empty(RegistryProbeShape.FromParams(null));
        Assert.Empty(RegistryProbeShape.FromParams(new Dictionary<string, object>()));
        Assert.Empty(RegistryProbeShape.FromParams(new Dictionary<string, object> { ["registryProbes"] = null! }));
        // Un escalar donde se esperaba una lista: no se adivina.
        Assert.Empty(RegistryProbeShape.FromParams(new Dictionary<string, object> { ["registryProbes"] = "HKLM\\A:B" }));
    }
}
