// privsvc/windows/Tracenium.PrivSvc.Tests/BrowserPolicyListShapeTests.cs
//
// El primitivo que escribe las listas de extensiones de Chrome y Edge como
// LocalSystem. Lo que se fija aquí es lo estrecho que es: cuatro claves,
// valores numerados, y sólo ids válidos o entradas que ya estaban.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class BrowserPolicyListShapeTests
{
    private const string Id = "cjpalhdlnbpafiamejdnhcphjbkeiagm";

    [Fact]
    public void KeyFor_OnlyTheFourKnownKeys()
    {
        Assert.Equal(@"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist", BrowserPolicyListShape.KeyFor("chrome", "blocklist"));
        Assert.Equal(@"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist", BrowserPolicyListShape.KeyFor("edge", "allowlist"));
        Assert.Null(BrowserPolicyListShape.KeyFor("firefox", "blocklist"));
        Assert.Null(BrowserPolicyListShape.KeyFor("chrome", "forcelist"));
        Assert.Null(BrowserPolicyListShape.KeyFor(@"chrome\..\..\Windows", "blocklist"));
        Assert.Null(BrowserPolicyListShape.KeyFor(null, null));
    }

    [Fact]
    public void IndexOf_OnlyCanonicalPositiveIntegers()
    {
        Assert.Equal(1, BrowserPolicyListShape.IndexOf("1"));
        Assert.Equal(12, BrowserPolicyListShape.IndexOf("12"));
        Assert.Null(BrowserPolicyListShape.IndexOf("0"));
        Assert.Null(BrowserPolicyListShape.IndexOf("01"));
        Assert.Null(BrowserPolicyListShape.IndexOf("-1"));
        Assert.Null(BrowserPolicyListShape.IndexOf(" 1"));
        Assert.Null(BrowserPolicyListShape.IndexOf("(Default)"));
        Assert.Null(BrowserPolicyListShape.IndexOf(""));
    }

    [Fact]
    public void OrderedEntries_NumericOrder_StringsOnly()
    {
        var entries = BrowserPolicyListShape.OrderedEntries(new (string, object?)[]
        {
            ("10", "j"), ("2", "b"), ("1", "a"), ("note", "ignored"), ("3", 5), ("4", "d")
        });
        Assert.Equal(new[] { "a", "b", "d", "j" }, entries);
    }

    [Fact]
    public void RejectReason_AllowsIdsStarInBlocklistAndPreexistingForeignEntries()
    {
        Assert.Null(BrowserPolicyListShape.RejectReason("blocklist", new[] { "gpo-thing", Id, "*" }, new[] { "gpo-thing" }));
        Assert.NotNull(BrowserPolicyListShape.RejectReason("allowlist", new[] { "*" }, Array.Empty<string>()));
        Assert.NotNull(BrowserPolicyListShape.RejectReason("blocklist", new[] { "calc.exe" }, Array.Empty<string>()));
        Assert.NotNull(BrowserPolicyListShape.RejectReason("blocklist", new[] { "" }, Array.Empty<string>()));
        var tooMany = Enumerable.Repeat(Id, BrowserPolicyListShape.MaxEntries + 1).ToArray();
        Assert.NotNull(BrowserPolicyListShape.RejectReason("blocklist", tooMany, Array.Empty<string>()));
    }

    [Fact]
    public void NamesToDelete_NumericBeyondCount_KeepsForeignNames()
    {
        var names = new[] { "1", "2", "3", "7", "note", "(Default)" };
        Assert.Equal(new[] { "3", "7" }, BrowserPolicyListShape.NamesToDelete(names, 2));
        Assert.Equal(new[] { "1", "2", "3", "7" }, BrowserPolicyListShape.NamesToDelete(names, 0));
    }

    [Fact]
    public void Params_FromJsonElements_RejectMixedArrays()
    {
        var p = JsonSerializer.Deserialize<Dictionary<string, object>>(
            "{\"browser\":\"edge\",\"entries\":[\"a\",\"b\"],\"bad\":[\"a\",1],\"notList\":\"x\"}")!;
        Assert.Equal("edge", BrowserPolicyListShape.StringParam(p, "browser"));
        Assert.Equal(new[] { "a", "b" }, BrowserPolicyListShape.ListParam(p, "entries"));
        Assert.Null(BrowserPolicyListShape.ListParam(p, "bad"));
        Assert.Null(BrowserPolicyListShape.ListParam(p, "notList"));
        Assert.Null(BrowserPolicyListShape.ListParam(p, "missing"));
    }
}
