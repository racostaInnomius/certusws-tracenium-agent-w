// privsvc/windows/Tracenium.PrivSvc.Tests/SeceditShapeTests.cs
//
// Fase 1 del cierre de brecha CIS. Lo que se fija: el INI de secedit se
// parsea con BOM y CRLF, [System Access] sale tipado, los derechos
// resuelven SIDs a nombres sin BUILTIN\/NT AUTHORITY\ y conservan los
// SIDs crudos, y un derecho vacío es una lista vacía (no ausente).

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class SeceditShapeTests
{
    private const string Export =
        "﻿[Unicode]\r\nUnicode=yes\r\n" +
        "[System Access]\r\nMinimumPasswordAge = 1\r\nMaximumPasswordAge = 365\r\n" +
        "NewAdministratorName = \"Administrator\"\r\nLSAAnonymousNameLookup = 0\r\n" +
        "[Privilege Rights]\r\n" +
        "SeDebugPrivilege = *S-1-5-32-544\r\n" +
        "SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6\r\n" +
        "SeCreateTokenPrivilege = \r\n" +
        "SeBatchLogonRight = *S-1-5-21-1-2-3-1001,Backup Operators\r\n" +
        "[Registry Values]\r\nMACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=4,1\r\n";

    private static string? Resolve(string sid) => sid switch
    {
        "S-1-5-32-544" => "BUILTIN\\Administrators",
        "S-1-5-19" => "NT AUTHORITY\\LOCAL SERVICE",
        "S-1-5-20" => "NT AUTHORITY\\NETWORK SERVICE",
        "S-1-5-6" => "NT AUTHORITY\\SERVICE",
        _ => null
    };

    [Fact]
    public void ParsesSectionsWithBomAndCrlf()
    {
        var ini = SeceditShape.ParseIni(Export);
        Assert.Equal("1", ini["System Access"]["MinimumPasswordAge"]);
        Assert.Equal("*S-1-5-32-544", ini["Privilege Rights"]["SeDebugPrivilege"]);
        Assert.Equal("", ini["Privilege Rights"]["SeCreateTokenPrivilege"]);
    }

    [Fact]
    public void SystemAccessIsTypedAndUnquoted()
    {
        var ev = SeceditShape.Build(SeceditShape.ParseIni(Export), Resolve);
        var sa = (Dictionary<string, object?>)ev["systemAccess"]!;
        Assert.Equal(365L, sa["MaximumPasswordAge"]);
        Assert.Equal(0L, sa["LSAAnonymousNameLookup"]);
        Assert.Equal("Administrator", sa["NewAdministratorName"]);
        Assert.True((bool)ev["available"]!);
    }

    [Fact]
    public void PrivilegeRightsResolveToCisStyleNames()
    {
        var ev = SeceditShape.Build(SeceditShape.ParseIni(Export), Resolve);
        var rights = (Dictionary<string, string[]>)ev["privilegeRights"]!;
        var sids = (Dictionary<string, string[]>)ev["privilegeRightsSids"]!;
        Assert.Equal(new[] { "Administrators" }, rights["SeDebugPrivilege"]);
        Assert.Equal(new[] { "Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE" }, rights["SeCreateGlobalPrivilege"]);
        Assert.Equal(new[] { "S-1-5-32-544", "S-1-5-19", "S-1-5-20", "S-1-5-6" }, sids["SeCreateGlobalPrivilege"]);
        // Vacío = nadie lo tiene, y se dice explícitamente.
        Assert.Empty(rights["SeCreateTokenPrivilege"]);
        // Un SID que no resuelve se queda visible; un nombre literal pasa tal cual.
        Assert.Equal(new[] { "S-1-5-21-1-2-3-1001", "Backup Operators" }, rights["SeBatchLogonRight"]);
    }

    [Fact]
    public void StripsOnlyWellKnownDomains()
    {
        Assert.Equal("Administrators", SeceditShape.StripWellKnownDomain("BUILTIN\\Administrators"));
        Assert.Equal("LOCAL SERVICE", SeceditShape.StripWellKnownDomain("NT AUTHORITY\\LOCAL SERVICE"));
        Assert.Equal("NT SERVICE\\WdiServiceHost", SeceditShape.StripWellKnownDomain("NT SERVICE\\WdiServiceHost"));
        Assert.Equal("CONTOSO\\Domain Admins", SeceditShape.StripWellKnownDomain("CONTOSO\\Domain Admins"));
    }

    [Fact]
    public void EmptyOrGarbageIsEmpty()
    {
        Assert.Empty(SeceditShape.ParseIni(null));
        Assert.Empty(SeceditShape.ParseIni("no sections here = 1"));
    }
}
