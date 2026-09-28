// privsvc/windows/Tracenium.PrivSvc.Tests/UserHiveCoverageShapeTests.cs
//
// Qué perfiles se declaran NO leídos en software.inventory. De ellos el agente
// conserva las apps que ya conocía, en vez de darlas por desinstaladas cada
// vez que el usuario cierra sesión (T111, 25–27 sep).

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class UserHiveCoverageShapeTests
{
    private const string Ana = "S-1-5-21-1111111111-222222222-3333333333-1001";
    private const string Beto = "S-1-5-21-1111111111-222222222-3333333333-1002";

    [Fact]
    public void ProfileWithoutSessionIsUnread()
    {
        Assert.Equal(new[] { Beto }, UserHiveCoverageShape.Unread(new[] { Ana, Beto }, new[] { Ana }));
    }

    [Fact]
    public void EveryProfileReadMeansNothingToCarry()
    {
        Assert.Empty(UserHiveCoverageShape.Unread(new[] { Ana, Beto }, new[] { Beto, Ana }));
    }

    [Fact]
    public void ServiceAccountsAndClassesHivesNeverCount()
    {
        // ProfileList también lista SYSTEM, LocalService y NetworkService.
        var got = UserHiveCoverageShape.Unread(
            new[] { "S-1-5-18", "S-1-5-19", "S-1-5-20", Ana + "_Classes", Ana },
            Array.Empty<string>());
        Assert.Equal(new[] { Ana }, got);
    }

    [Fact]
    public void ComparesSidsIgnoringCaseAndDeduplicates()
    {
        Assert.Empty(UserHiveCoverageShape.Unread(new[] { Ana }, new[] { Ana.ToLowerInvariant() }));
        Assert.Equal(new[] { Ana }, UserHiveCoverageShape.Unread(new[] { Ana, Ana }, Array.Empty<string>()));
    }

    [Fact]
    public void EntraIdProfileWithoutSessionIsUnreadToo()
    {
        const string entra = "S-1-12-1-3570604255-1238987765-2263183267-4104715137";
        Assert.Equal(new[] { entra }, UserHiveCoverageShape.Unread(new[] { Ana, entra }, new[] { Ana }));
    }

    [Fact]
    public void UnreadableProfileListCarriesNothing()
    {
        // Sin la lista de perfiles no se inventa ninguno: vuelve la regla de antes.
        Assert.Empty(UserHiveCoverageShape.Unread(Array.Empty<string>(), new[] { Ana }));
    }
}
