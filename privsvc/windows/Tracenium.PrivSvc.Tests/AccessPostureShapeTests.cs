// privsvc/windows/Tracenium.PrivSvc.Tests/AccessPostureShapeTests.cs
//
// P2-10 — directorio (dsregcmd) y administradores locales. Lectura fallida =
// unknown, nunca "no unido" ni "sin administradores".

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AccessPostureShapeTests
{
    private const string EntraJoined = @"
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : NO
               Device Name : W11-JPR-LAB02

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Certus ITM LLC
                  TenantId : 00000000-1111-2222-3333-444444444444

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

                    NgcSet : NO
           WorkplaceJoined : NO
";

    [Fact]
    public void Entra_joined_device()
    {
        var b = AccessPostureShape.ParseDsregcmd(EntraJoined);
        Assert.Equal("collected", b["status"]);
        Assert.Equal(true, b["azureAdJoined"]);
        Assert.Equal(false, b["domainJoined"]);
        Assert.Equal(false, b["workplaceJoined"]);
        Assert.Equal(true, b["directoryJoined"]);
        Assert.Equal("Certus ITM LLC", b["tenantName"]);
    }

    [Fact]
    public void Standalone_device_is_not_directory_joined()
    {
        var b = AccessPostureShape.ParseDsregcmd("AzureAdJoined : NO\r\nDomainJoined : NO\r\nWorkplaceJoined : NO\r\n");
        Assert.Equal(false, b["directoryJoined"]);
    }

    [Fact]
    public void Ad_only_device_is_directory_joined()
    {
        var b = AccessPostureShape.ParseDsregcmd("AzureAdJoined : NO\nDomainJoined : YES\n DomainName : MSIG\n");
        Assert.Equal(true, b["directoryJoined"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("'dsregcmd' is not recognized as an internal or external command")]
    public void Unreadable_dsregcmd_is_unknown(string? output)
    {
        var b = AccessPostureShape.ParseDsregcmd(output);
        Assert.Equal("unknown", b["status"]);
        Assert.False(b.ContainsKey("directoryJoined"));
    }

    [Fact]
    public void Local_admins_members_and_count()
    {
        var b = AccessPostureShape.ParseLocalAdmins("{\"Ok\":true,\"Source\":\"Get-LocalGroupMember\",\"Members\":[{\"Name\":\"W11\\\\Administrador\",\"Class\":\"User\",\"Source\":\"Local\"},{\"Name\":\"MSIG\\\\Domain Admins\",\"Class\":\"Group\",\"Source\":\"ActiveDirectory\"}]}");
        Assert.Equal("collected", b["status"]);
        Assert.Equal(2, b["count"]);
        var members = Assert.IsType<List<Dictionary<string, object?>>>(b["members"]);
        Assert.Equal("MSIG\\Domain Admins", members[1]["name"]);
        Assert.Equal("Group", members[1]["class"]);
    }

    [Fact]
    public void A_single_member_serialized_as_an_object_still_counts()
    {
        var b = AccessPostureShape.ParseLocalAdmins("{\"Ok\":true,\"Source\":\"ADSI\",\"Members\":{\"Name\":\"W11/Administrador\",\"Class\":\"User\",\"Source\":null}}");
        Assert.Equal(1, b["count"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("{\"Ok\":false,\"Source\":null,\"Members\":[]}")]
    [InlineData("garbage")]
    public void Failed_admin_read_is_unknown_not_empty(string? json)
    {
        var b = AccessPostureShape.ParseLocalAdmins(json);
        Assert.Equal("unknown", b["status"]);
        Assert.False(b.ContainsKey("count"));
    }
}
