// privsvc/windows/Tracenium.PrivSvc.Tests/GenericWriteHiveTests.cs
//
// Escrituras de perfil de usuario (hive HKU = cada HKEY_USERS\S-1-5-21-*
// cargado). Lo que se fija: HKU se acepta y queda marcado como tal, HKCU
// se rechaza (un servicio no tiene "usuario actual"), una escritura HKU
// fuera de Software\ se rechaza, y las guardas de clave siguen aplicando
// también en el hive de usuario.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class GenericWriteHiveTests
{
    private static Dictionary<string, object> Params(string writesJson)
    {
        var doc = JsonDocument.Parse("{\"checkId\":\"windows.registry.set_value\",\"params\":{\"writes\":" + writesJson + "}}");
        return new Dictionary<string, object>
        {
            ["checkId"] = doc.RootElement.GetProperty("checkId"),
            ["params"] = doc.RootElement.GetProperty("params"),
        };
    }

    [Theory]
    [InlineData("HKU")]
    [InlineData("HKEY_USERS")]
    [InlineData("hku")]
    public void HKU_is_accepted_and_marked_as_a_user_profile_write(string hive)
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"" + hive + "\",\"keyPath\":\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Attachments\",\"valueName\":\"SaveZoneInformation\",\"valueType\":\"dword\",\"value\":2}]"));

        Assert.Empty(w.Rejected);
        var spec = Assert.Single(w.Registry);
        Assert.Equal(RegistryHiveKind.Users, spec.Hive);
        Assert.Equal("HKU\\*", spec.HiveLabel);
        Assert.Equal("HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments:SaveZoneInformation=2", spec.Describe());
    }

    [Fact]
    public void HKLM_stays_the_default_hive()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\Policies\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}]"));
        var spec = Assert.Single(w.Registry);
        Assert.Equal(RegistryHiveKind.LocalMachine, spec.Hive);
        Assert.StartsWith("HKLM\\SOFTWARE\\Policies\\A:X=", spec.Describe());
    }

    [Theory]
    [InlineData("HKCU")]
    [InlineData("HKEY_CURRENT_USER")]
    public void HKCU_is_still_refused(string hive)
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"" + hive + "\",\"keyPath\":\"Software\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}]"));
        Assert.Empty(w.Registry);
        Assert.Contains("hive", Assert.Single(w.Rejected));
    }

    [Theory]
    [InlineData("Control Panel\\\\Desktop")]
    [InlineData("Environment")]
    [InlineData("SoftwareX\\\\Policies")]
    public void An_HKU_write_outside_Software_is_refused(string keyPath)
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKU\",\"keyPath\":\"" + keyPath + "\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}]"));
        Assert.Empty(w.Registry);
        Assert.Contains("outside Software", Assert.Single(w.Rejected));
    }

    [Fact]
    public void Key_guards_apply_in_the_user_hive_too()
    {
        // Una directiva de RDP en el perfil del usuario bloquea igual que en la máquina.
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKU\",\"keyPath\":\"SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal Services\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}]"));
        Assert.Empty(w.Registry);
        var reason = Assert.Single(w.Rejected);
        Assert.Contains("guarded: HKU\\*\\", reason);
        Assert.Contains("Remote Desktop", reason);
    }

    [Fact]
    public void Machine_and_user_writes_can_travel_in_the_same_batch()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\Policies\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}," +
            " {\"kind\":\"registry\",\"hive\":\"HKU\",\"keyPath\":\"Software\\\\Policies\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}]"));
        Assert.Empty(w.Rejected);
        Assert.Equal(2, w.Registry.Count);
        Assert.Equal(RegistryHiveKind.LocalMachine, w.Registry[0].Hive);
        Assert.Equal(RegistryHiveKind.Users, w.Registry[1].Hive);
    }
}
