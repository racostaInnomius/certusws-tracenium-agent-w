// privsvc/windows/Tracenium.PrivSvc.Tests/GenericWriteShapeTests.cs
//
// Remediación genérica de Windows. Lo que se fija: el contrato de
// params.params.writes se parsea tipado, TODO lo que no cuadra se rechaza
// con motivo (hive, tipo, ".."), las guardas del backend se repiten aquí
// (un payload manipulado no toca LSA ni RDP ni renombra cuentas), y la
// plantilla .inf sólo lleva [System Access] con las claves pedidas.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class GenericWriteShapeTests
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

    [Fact]
    public void Parses_registry_writes_of_the_three_kinds()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\Policies\\\\A\",\"valueName\":\"D\",\"valueType\":\"dword\",\"value\":15}," +
            " {\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"\\\\SOFTWARE\\\\Policies\\\\A\\\\\",\"valueName\":\"S\",\"valueType\":\"sz\",\"value\":\"PCI\\\\CC_0C0A\"}," +
            " {\"kind\":\"registry\",\"hive\":\"HKEY_LOCAL_MACHINE\",\"keyPath\":\"SOFTWARE/Policies/A\",\"valueName\":\"M\",\"valueType\":\"multi_sz\",\"value\":[\"a\",\"b\"]}]"));

        Assert.Empty(w.Rejected);
        Assert.Equal(3, w.Registry.Count);
        Assert.Equal(GenericValueKind.DWord, w.Registry[0].Kind);
        Assert.Equal(15u, w.Registry[0].DwordValue);
        // La ruta se normaliza: sin barras al borde, con backslash.
        Assert.Equal("SOFTWARE\\Policies\\A", w.Registry[1].SubKey);
        Assert.Equal("PCI\\CC_0C0A", w.Registry[1].StringValue);
        Assert.Equal("SOFTWARE\\Policies\\A", w.Registry[2].SubKey);
        Assert.Equal(new[] { "a", "b" }, w.Registry[2].MultiValue);
    }

    [Theory]
    [InlineData("{\"kind\":\"registry\",\"hive\":\"HKCU\",\"keyPath\":\"Software\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}", "hive")]
    [InlineData("{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\..\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}", "keyPath")]
    [InlineData("{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":\"1\"}", "dword value")]
    [InlineData("{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\A\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":-1}", "dword value")]
    [InlineData("{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\A\",\"valueName\":\"X\",\"valueType\":\"binary\",\"value\":\"00\"}", "valueType")]
    [InlineData("{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\A\",\"valueName\":\"X\",\"valueType\":\"multi_sz\",\"value\":[1]}", "multi_sz")]
    [InlineData("{\"kind\":\"shell\",\"cmd\":\"whoami\"}", "unknown write kind")]
    public void Rejects_malformed_registry_writes_with_a_reason(string write, string reasonFragment)
    {
        var w = GenericWriteShape.FromParams(Params("[" + write + "]"));
        Assert.Empty(w.Registry);
        Assert.Single(w.Rejected);
        Assert.Contains(reasonFragment, w.Rejected[0]);
    }

    [Theory]
    [InlineData("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LSA")]
    [InlineData("system\\currentcontrolset\\control\\lsa\\MSV1_0", "LSA")]
    [InlineData("SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "Remote Desktop")]
    [InlineData("SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", "WinRM")]
    [InlineData("SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", "Netlogon")]
    [InlineData("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB server")]
    [InlineData("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "UAC")]
    public void Guarded_keys_are_refused_even_when_the_payload_asks(string keyPath, string reasonFragment)
    {
        Assert.Contains(reasonFragment, GenericWriteShape.GuardReasonForKey(keyPath));
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"" + keyPath.Replace("\\", "\\\\") + "\",\"valueName\":\"X\",\"valueType\":\"dword\",\"value\":1}]"));
        Assert.Empty(w.Registry);
        Assert.Contains("guarded", w.Rejected[0]);
    }

    [Fact]
    public void Unguarded_policy_keys_pass()
    {
        Assert.Null(GenericWriteShape.GuardReasonForKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"));
        Assert.Null(GenericWriteShape.GuardReasonForKey("SYSTEM\\CurrentControlSet\\Services\\mrxsmb10"));
    }

    [Fact]
    public void Parses_secedit_writes_and_refuses_account_renames()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"secedit\",\"section\":\"System Access\",\"key\":\"MinimumPasswordLength\",\"value\":14}," +
            " {\"kind\":\"secedit\",\"section\":\"System Access\",\"key\":\"NewGuestName\",\"value\":\"Visitor\"}," +
            " {\"kind\":\"secedit\",\"section\":\"Privilege Rights\",\"key\":\"SeDebugPrivilege\",\"value\":\"\"}," +
            " {\"kind\":\"secedit\",\"section\":\"System Access\",\"key\":\"Bad Key\",\"value\":1}]"));
        Assert.Single(w.Secedit);
        Assert.Equal("MinimumPasswordLength", w.Secedit[0].Key);
        Assert.Equal("14", w.Secedit[0].Value);
        Assert.True(w.Secedit[0].IsNumeric);
        Assert.Equal(3, w.Rejected.Count);
        Assert.Contains(w.Rejected, r => r.Contains("guarded") && r.Contains("Guest"));
        Assert.Contains(w.Rejected, r => r.Contains("section 'Privilege Rights'"));
        Assert.Contains(w.Rejected, r => r.Contains("key 'Bad Key'"));
    }

    [Fact]
    public void Parses_a_delete_without_a_value()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\Policies\\\\Google\\\\Chrome\",\"valueName\":\"ExtensionInstallForcelist\",\"valueType\":\"delete\"}]"));

        Assert.Empty(w.Rejected);
        var spec = Assert.Single(w.Registry);
        Assert.Equal(GenericValueKind.Delete, spec.Kind);
        Assert.Equal("SOFTWARE\\Policies\\Google\\Chrome", spec.SubKey);
        Assert.Contains("(deleted)", spec.Describe());
    }

    [Fact]
    public void A_delete_ignores_a_stray_value_instead_of_turning_into_a_write()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\Policies\\\\A\",\"valueName\":\"X\",\"valueType\":\"delete\",\"value\":1}]"));
        var spec = Assert.Single(w.Registry);
        Assert.Equal(GenericValueKind.Delete, spec.Kind);
        Assert.Equal(0u, spec.DwordValue);
    }

    [Fact]
    public void A_delete_goes_through_the_same_guards_as_a_write()
    {
        // Borrar un valor de LSA rompe los inicios de sesión igual que cambiarlo.
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\",\"valueName\":\"LmCompatibilityLevel\",\"valueType\":\"delete\"}," +
            " {\"kind\":\"registry\",\"hive\":\"HKCU\",\"keyPath\":\"Software\\\\A\",\"valueName\":\"X\",\"valueType\":\"delete\"}," +
            " {\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\..\\\\A\",\"valueName\":\"X\",\"valueType\":\"delete\"}]"));
        Assert.Empty(w.Registry);
        Assert.Equal(3, w.Rejected.Count);
        Assert.Contains(w.Rejected, r => r.Contains("guarded"));
        Assert.Contains(w.Rejected, r => r.Contains("hive"));
        Assert.Contains(w.Rejected, r => r.Contains("keyPath"));
    }

    [Fact]
    public void A_delete_matches_only_when_the_value_is_absent()
    {
        var spec = new RegistryWriteSpec { SubKey = "SOFTWARE\\A", ValueName = "X", Kind = GenericValueKind.Delete };
        Assert.True(GenericWriteShape.RegistryValueMatches(spec, null));
        Assert.False(GenericWriteShape.RegistryValueMatches(spec, 1L));
        Assert.False(GenericWriteShape.RegistryValueMatches(spec, ""));
    }

    [Fact]
    public void Missing_params_is_rejected_not_thrown()
    {
        var w = GenericWriteShape.FromParams(new Dictionary<string, object>());
        Assert.True(w.IsEmpty);
        Assert.Contains("params missing", w.Rejected[0]);
        var doc = JsonDocument.Parse("{\"params\":{\"writes\":\"nope\"}}");
        var w2 = GenericWriteShape.FromParams(new Dictionary<string, object> { ["params"] = doc.RootElement.GetProperty("params") });
        Assert.Contains("params.writes missing", w2.Rejected[0]);
    }

    [Fact]
    public void Caps_the_number_of_writes()
    {
        var many = string.Join(",", Enumerable.Range(0, GenericWriteShape.MaxWrites + 1).Select(i =>
            "{\"kind\":\"registry\",\"hive\":\"HKLM\",\"keyPath\":\"SOFTWARE\\\\A\",\"valueName\":\"V" + i + "\",\"valueType\":\"dword\",\"value\":1}"));
        var w = GenericWriteShape.FromParams(Params("[" + many + "]"));
        Assert.Equal(GenericWriteShape.MaxWrites, w.Registry.Count);
        Assert.Contains(w.Rejected, r => r.Contains("more than"));
    }

    [Fact]
    public void Renders_an_inf_with_only_system_access()
    {
        var inf = GenericWriteShape.RenderSeceditInf(new[]
        {
            new SeceditWriteSpec { Key = "MinimumPasswordLength", Value = "14", IsNumeric = true },
            new SeceditWriteSpec { Key = "NewGuestName", Value = "Vis\"itor", IsNumeric = false },
        });
        Assert.StartsWith("[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[System Access]\r\n", inf);
        Assert.Contains("MinimumPasswordLength = 14\r\n", inf);
        Assert.Contains("NewGuestName = \"Vis\"\"itor\"\r\n", inf);
        Assert.DoesNotContain("[Privilege Rights]", inf);
        // Y se vuelve a leer con el mismo parser que la exportación real.
        var ini = SeceditShape.ParseIni(inf);
        Assert.Equal("14", ini["System Access"]["MinimumPasswordLength"]);
    }

    [Fact]
    public void Registry_value_match_uses_the_probe_normalisation()
    {
        var dword = new RegistryWriteSpec { SubKey = "A", ValueName = "X", Kind = GenericValueKind.DWord, DwordValue = 15 };
        Assert.True(GenericWriteShape.RegistryValueMatches(dword, 15L));
        Assert.True(GenericWriteShape.RegistryValueMatches(dword, 15));
        Assert.False(GenericWriteShape.RegistryValueMatches(dword, 16L));
        Assert.False(GenericWriteShape.RegistryValueMatches(dword, null));
        var sz = new RegistryWriteSpec { SubKey = "A", ValueName = "X", Kind = GenericValueKind.String, StringValue = "abc" };
        Assert.True(GenericWriteShape.RegistryValueMatches(sz, "abc"));
        Assert.False(GenericWriteShape.RegistryValueMatches(sz, "ABC"));
        var multi = new RegistryWriteSpec { SubKey = "A", ValueName = "X", Kind = GenericValueKind.MultiString, MultiValue = new[] { "a", "b" } };
        Assert.True(GenericWriteShape.RegistryValueMatches(multi, new[] { "a", "b" }));
        Assert.False(GenericWriteShape.RegistryValueMatches(multi, new[] { "b", "a" }));
    }
}

public class GenericWriteShapeAuditpolTests
{
    private static Dictionary<string, object> Params(string writesJson)
    {
        var doc = JsonDocument.Parse("{\"params\":{\"writes\":" + writesJson + "}}");
        return new Dictionary<string, object> { ["params"] = doc.RootElement.GetProperty("params") };
    }

    [Fact]
    public void Parses_an_auditpol_write_by_guid_and_derives_the_canonical_name()
    {
        var w = GenericWriteShape.FromParams(Params(
            "[{\"kind\":\"auditpol\",\"subcategory\":\"{0CCE9239-69AE-11D9-BED3-505054503030}\",\"success\":true,\"failure\":true}," +
            " {\"kind\":\"auditpol\",\"subcategory\":\"0cce9249-69ae-11d9-bed3-505054503030\",\"success\":true,\"failure\":false}]"));
        Assert.Empty(w.Rejected);
        Assert.Equal(2, w.Auditpol.Count);
        // GUID normalizado: minúsculas, sin llaves.
        Assert.Equal("0cce9239-69ae-11d9-bed3-505054503030", w.Auditpol[0].Subcategory);
        Assert.Equal("Success and Failure", w.Auditpol[0].SettingName);
        Assert.Equal("Success", w.Auditpol[1].SettingName);
        Assert.Contains("/success:enable", w.Auditpol[0].Describe().Replace("success=enable", "/success:enable"));
    }

    [Theory]
    [InlineData("{\"kind\":\"auditpol\",\"subcategory\":\"not-a-guid\",\"success\":true,\"failure\":true}", "not a GUID")]
    [InlineData("{\"kind\":\"auditpol\",\"subcategory\":\"0cce9239-69ae-11d9-bed3-505054503030\",\"success\":\"yes\",\"failure\":true}", "booleans")]
    [InlineData("{\"kind\":\"auditpol\",\"subcategory\":\"0cce9239-69ae-11d9-bed3-505054503030\",\"success\":true}", "booleans")]
    public void Rejects_malformed_auditpol_writes(string write, string reason)
    {
        var w = GenericWriteShape.FromParams(Params("[" + write + "]"));
        Assert.Empty(w.Auditpol);
        Assert.Contains(reason, w.Rejected[0]);
    }
}
