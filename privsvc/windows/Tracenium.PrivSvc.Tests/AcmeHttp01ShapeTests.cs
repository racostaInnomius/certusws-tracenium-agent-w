// privsvc/windows/Tracenium.PrivSvc.Tests/AcmeHttp01ShapeTests.cs
//
// ADR-0033 F2b — `cdp.acme.http01` es una primitiva de escritura en el webroot
// de un servidor. Lo que se fija: nombre y contenido de forma fija (no sirve
// para plantar una página), sólo bajo raíces permitidas y sin `..` ni rutas
// UNC, y las raíces extra sólo desde el fichero local del administrador.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AcmeHttp01ShapeTests
{
    private const string Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    private static readonly string Thumb = new string('a', 43);

    [Fact]
    public void Token_is_base64url_16_to_256()
    {
        Assert.True(AcmeHttp01Shape.IsValidToken(Token));
        Assert.False(AcmeHttp01Shape.IsValidToken("short"));
        Assert.False(AcmeHttp01Shape.IsValidToken("..\\..\\windows\\evil.aspx"));
        Assert.False(AcmeHttp01Shape.IsValidToken("abc/def0123456789abcdef"));
    }

    [Fact]
    public void Content_must_be_token_dot_thumbprint_of_the_same_token()
    {
        Assert.True(AcmeHttp01Shape.IsValidKeyAuthorization(Token, $"{Token}.{Thumb}"));
        // Un script o una página no tienen esa forma.
        Assert.False(AcmeHttp01Shape.IsValidKeyAuthorization(Token, "<%@ Page Language=\"C#\" %>"));
        // El contenido de OTRO token no vale para este nombre.
        Assert.False(AcmeHttp01Shape.IsValidKeyAuthorization(Token, $"otherToken1234567890.{Thumb}"));
        Assert.False(AcmeHttp01Shape.IsValidKeyAuthorization(Token, $"{Token}.{Thumb}x"));
    }

    [Fact]
    public void Webroot_is_normalized_and_must_be_local_absolute()
    {
        Assert.Equal(@"C:\inetpub\wwwroot", AcmeHttp01Shape.NormalizeWebroot(@"c:\inetpub\wwwroot\"));
        Assert.Equal(@"C:\inetpub\wwwroot", AcmeHttp01Shape.NormalizeWebroot("C:/inetpub/site/../wwwroot"));
        Assert.Null(AcmeHttp01Shape.NormalizeWebroot(@"\\fileserver\share\www"));
        Assert.Null(AcmeHttp01Shape.NormalizeWebroot(@"inetpub\wwwroot"));
        Assert.Null(AcmeHttp01Shape.NormalizeWebroot(@"C:\..\..\x"));
    }

    [Fact]
    public void Only_under_an_allowed_root_and_not_by_mere_prefix()
    {
        var roots = AcmeHttp01Shape.DefaultRoots("C:");
        Assert.True(AcmeHttp01Shape.IsUnderAllowedRoot(@"C:\inetpub\wwwroot", roots));
        Assert.True(AcmeHttp01Shape.IsUnderAllowedRoot(@"c:\INETPUB\sites\shop", roots));
        Assert.False(AcmeHttp01Shape.IsUnderAllowedRoot(@"C:\inetpub-evil\wwwroot", roots));
        // `..` normalizado fuera de la raíz ya no está debajo.
        Assert.False(AcmeHttp01Shape.IsUnderAllowedRoot(AcmeHttp01Shape.NormalizeWebroot(@"C:\inetpub\..\Windows\System32")!, roots));
    }

    [Fact]
    public void Extra_roots_come_only_as_absolute_local_lines()
    {
        var extra = AcmeHttp01Shape.ParseExtraRoots("# sitios\nD:\\sites\\\n\nrelative\\path\n\\\\srv\\share\n  E:\\www  ");
        Assert.Equal(new[] { @"D:\sites", @"E:\www" }, extra);
    }

    [Fact]
    public void The_file_goes_under_well_known_acme_challenge()
    {
        Assert.Equal(@"C:\inetpub\wwwroot\.well-known\acme-challenge", AcmeHttp01Shape.ChallengeDir(@"C:\inetpub\wwwroot"));
    }
}
