// privsvc/windows/Tracenium.PrivSvc.Tests/UserRegistryProbeShapeTests.cs
//
// Fase 1 del cierre de brecha CIS. Sondas de usuario: forma de la sonda,
// qué hives cuentan como perfil, y la agregación entre usuarios (todos
// iguales → valor; distintos → <mixed>; falta en alguno → omitida; sin
// hives → sin bloque).

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class UserRegistryProbeShapeTests
{
    private const string P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments:SaveZoneInformation";

    [Fact]
    public void ParsesRelativeProbeAndRejectsHivesAndWildcards()
    {
        var ok = UserRegistryProbeShape.Parse(P);
        Assert.NotNull(ok);
        Assert.Equal("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments", ok!.Value.SubKey);
        Assert.Equal("SaveZoneInformation", ok.Value.ValueName);
        Assert.Null(UserRegistryProbeShape.Parse("HKLM\\Software\\X:Y"));
        Assert.Null(UserRegistryProbeShape.Parse("HKU\\S-1-5-21-1\\Software\\X:Y"));
        Assert.Null(UserRegistryProbeShape.Parse("Software\\X*:Y"));
        Assert.Null(UserRegistryProbeShape.Parse("Software\\X"));
        Assert.Null(UserRegistryProbeShape.Parse("Software\\X:"));
        Assert.Null(UserRegistryProbeShape.Parse(""));
    }

    [Fact]
    public void OnlyUserProfileHivesCount()
    {
        Assert.True(UserRegistryProbeShape.IsUserProfileHive("S-1-5-21-1234567890-123456789-1234567890-1001"));
        Assert.False(UserRegistryProbeShape.IsUserProfileHive("S-1-5-21-1234567890-123456789-1234567890-1001_Classes"));
        Assert.False(UserRegistryProbeShape.IsUserProfileHive(".DEFAULT"));
        Assert.False(UserRegistryProbeShape.IsUserProfileHive("S-1-5-18"));
        Assert.False(UserRegistryProbeShape.IsUserProfileHive("S-1-5-19"));
    }

    [Fact]
    public void AggregatesAcrossHives()
    {
        var perHive = new Dictionary<string, Dictionary<string, object?>>
        {
            ["S-1-5-21-1-1-1-1001"] = new() { [P] = 2L, ["Software\\A:Same"] = "x", ["Software\\A:Diff"] = 1L },
            ["S-1-5-21-1-1-1-1002"] = new() { ["Software\\A:Same"] = "x", ["Software\\A:Diff"] = 0L },
        };
        var ev = UserRegistryProbeShape.Aggregate(perHive, new[] { P, "Software\\A:Same", "Software\\A:Diff", "Software\\A:Nowhere" })!;
        Assert.Equal(2, ev["hives"]);
        // Presente en los dos con el mismo valor.
        Assert.Equal("x", ev["Software\\A:Same"]);
        // Presente en los dos con valores distintos: <mixed>, para que equals falle.
        Assert.Equal(UserRegistryProbeShape.MixedMarker, ev["Software\\A:Diff"]);
        // Falta en un usuario: omitida (el catálogo dice onMissing: fail).
        Assert.False(ev.ContainsKey(P));
        Assert.False(ev.ContainsKey("Software\\A:Nowhere"));
    }

    [Fact]
    public void NoLoadedHivesMeansNoBlock()
    {
        Assert.Null(UserRegistryProbeShape.Aggregate(new Dictionary<string, Dictionary<string, object?>>(), new[] { P }));
    }
}
