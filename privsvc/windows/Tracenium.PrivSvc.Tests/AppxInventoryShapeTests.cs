// privsvc/windows/Tracenium.PrivSvc.Tests/AppxInventoryShapeTests.cs
//
// Qué paquetes de la Store entran en el inventario. Sin -AllUsers el PrivSvc
// (SYSTEM) sólo veía los suyos, y Codex/Spotify/Disney+ entraban y salían del
// inventario escaneo tras escaneo (T1/T111, sep).

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AppxInventoryShapeTests
{
    private const string Ana = "S-1-5-21-1111111111-222222222-3333333333-1001";
    private const string Entra = "S-1-12-1-1234567890-1234567890-1234567890-1234567890";

    [Fact]
    public void CountsOnlyPackagesInstalledForAPerson()
    {
        Assert.True(AppxInventoryShape.InstalledForPerson(new[] { $"{Ana}|Installed" }));
        Assert.True(AppxInventoryShape.InstalledForPerson(new[] { $"{Entra}|Installed" }));
        // Una actualización a medio desplegar no es una app instalada.
        Assert.False(AppxInventoryShape.InstalledForPerson(new[] { $"{Ana}|Staged" }));
        // SYSTEM y servicios no son personas.
        Assert.False(AppxInventoryShape.InstalledForPerson(new[] { "S-1-5-18|Installed", "S-1-5-19|Installed" }));
        Assert.False(AppxInventoryShape.InstalledForPerson(new[] { "|Installed", "basura" }));
        Assert.False(AppxInventoryShape.InstalledForPerson(Array.Empty<string>()));
        Assert.True(AppxInventoryShape.InstalledForPerson(new[] { $"{Ana}|Staged", "S-1-5-18|Installed", $"{Entra}|installed" }));
    }

    [Fact]
    public void ReadsUsersAsPowerShellEmitsThem()
    {
        var json = JsonSerializer.Deserialize<Dictionary<string, object?>>(
            $"{{\"users\":\"{Ana}|Installed;S-1-5-18|Staged\"}}")!;
        Assert.Equal(new[] { $"{Ana}|Installed", "S-1-5-18|Staged" }, AppxInventoryShape.ReadUsers(json["users"]));

        var arr = JsonSerializer.Deserialize<Dictionary<string, object?>>($"{{\"users\":[\"{Ana}|Installed\"]}}")!;
        Assert.Equal(new[] { $"{Ana}|Installed" }, AppxInventoryShape.ReadUsers(arr["users"]));

        // Sin usuarios (cadena vacía, null o un objeto raro) → nadie.
        var vacio = JsonSerializer.Deserialize<Dictionary<string, object?>>("{\"a\":\"\",\"b\":null,\"c\":{\"value\":[]}}")!;
        Assert.Empty(AppxInventoryShape.ReadUsers(vacio["a"]));
        Assert.Empty(AppxInventoryShape.ReadUsers(vacio["b"]));
        Assert.Empty(AppxInventoryShape.ReadUsers(vacio["c"]));
    }

    private static Dictionary<string, object?> Pkg(string pfn, string version) =>
        new() { ["name"] = pfn.Split('_')[0], ["version"] = version, ["packageFamilyName"] = pfn };

    [Fact]
    public void OnePackagePerFamilyAtItsHighestVersion()
    {
        // Dos usuarios con Codex en versiones distintas: comparten install_id
        // en el agente, así que aquí se elige una, siempre la misma.
        var got = AppxInventoryShape.LatestPerFamily(new[]
        {
            Pkg("OpenAI.Codex_2p2nqsd0c76g0", "26.917.8451.0"),
            Pkg("SpotifyAB.SpotifyMusic_zpdnekdrzrea0", "1.2.0.0"),
            Pkg("OpenAI.Codex_2p2nqsd0c76g0", "26.924.1866.0"),
            Pkg("OpenAI.Codex_2p2nqsd0c76g0", "26.9.99999.0"),
        });
        Assert.Equal(2, got.Count);
        Assert.Equal("26.924.1866.0", got.Single(p => (string)p["name"]! == "OpenAI.Codex")["version"]);
    }

    [Fact]
    public void ResultDoesNotDependOnInputOrder()
    {
        var a = new[] { Pkg("B.App_x", "1.0.0.0"), Pkg("A.App_x", "2.0.0.0"), Pkg("A.App_x", "3.0.0.0") };
        var one = AppxInventoryShape.LatestPerFamily(a).Select(p => $"{p["name"]}@{p["version"]}");
        var two = AppxInventoryShape.LatestPerFamily(a.Reverse()).Select(p => $"{p["name"]}@{p["version"]}");
        Assert.Equal(one, two);
        Assert.Equal(new[] { "A.App@3.0.0.0", "B.App@1.0.0.0" }, one);
    }
}
