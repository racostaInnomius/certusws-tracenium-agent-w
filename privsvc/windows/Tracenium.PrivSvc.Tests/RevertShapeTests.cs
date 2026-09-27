// privsvc/windows/Tracenium.PrivSvc.Tests/RevertShapeTests.cs
//
// pmp.revert — la parte pura. Lo que se fija: cada handler acepta sólo SUS
// claves y SUS tipos (todo lo demás es bad_request antes de escribir nada),
// null → borrar y entero → DWORD (con -1 intacto), el nombre de cifrado con
// barra no se parte, el firewall sólo apaga lo que estaba apagado, los
// nombres de recurso se escapan para PowerShell y un queryError no se
// restaura. Los genéricos no tienen revert aquí: los deshace el backend.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class RevertShapeTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static RevertPlan Ok(string checkId, string stateJson)
    {
        var (plan, error) = RevertShape.Plan(checkId, Json(stateJson));
        Assert.Null(error);
        Assert.NotNull(plan);
        return plan!;
    }

    private static string Bad(string checkId, string stateJson)
    {
        var (plan, error) = RevertShape.Plan(checkId, Json(stateJson));
        Assert.Null(plan);
        Assert.NotNull(error);
        return error!;
    }

    // ── Soportados / no soportados ───────────────────────────────────

    [Theory]
    [InlineData("windows.cryptography.legacy_tls_disabled")]
    [InlineData("windows.cryptography.weak_ciphers_disabled")]
    [InlineData("windows.network_sharing.smbv1_disabled")]
    [InlineData("windows.firewall.profiles_enabled")]
    [InlineData("windows.shares.no_everyone_full_control")]
    public void Dedicated_handlers_are_supported(string checkId) =>
        Assert.True(RevertShape.IsSupported(checkId));

    [Theory]
    [InlineData("windows.registry.set_value")]
    [InlineData("windows.secedit.set_value")]
    [InlineData("windows.auditpol.set_value")]
    [InlineData("windows.something.else")]
    [InlineData("")]
    public void Generic_and_unknown_handlers_are_unsupported(string checkId)
    {
        Assert.False(RevertShape.IsSupported(checkId));
        // Plan tampoco devuelve error: es «no hay handler», no «payload malo».
        var (plan, error) = RevertShape.Plan(checkId, Json("{\"a\":1}"));
        Assert.Null(plan);
        Assert.Null(error);
    }

    // ── stateBefore desde los params IPC ─────────────────────────────

    private static Dictionary<string, object> Params(string paramsJson)
    {
        var doc = JsonDocument.Parse("{\"checkId\":\"x\",\"params\":" + paramsJson + "}");
        return new Dictionary<string, object>
        {
            ["checkId"] = doc.RootElement.GetProperty("checkId"),
            ["params"] = doc.RootElement.GetProperty("params"),
        };
    }

    [Fact]
    public void StateBefore_is_read_from_params_params()
    {
        var (state, error) = RevertShape.StateBeforeFromParams(Params("{\"stateBefore\":{\"Domain\":false}}"));
        Assert.Null(error);
        Assert.Equal(JsonValueKind.Object, state!.Value.ValueKind);
        Assert.False(state.Value.GetProperty("Domain").GetBoolean());
    }

    [Theory]
    [InlineData("{}", "stateBefore missing")]
    [InlineData("{\"stateBefore\":null}", "stateBefore missing")]
    [InlineData("{\"stateBefore\":[1]}", "not an object")]
    [InlineData("{\"stateBefore\":\"x\"}", "not an object")]
    [InlineData("[]", "params is not an object")]
    public void StateBefore_missing_or_not_an_object_is_rejected(string paramsJson, string fragment)
    {
        var (state, error) = RevertShape.StateBeforeFromParams(Params(paramsJson));
        Assert.Null(state);
        Assert.Contains(fragment, error);
    }

    [Fact]
    public void StateBefore_without_params_is_rejected()
    {
        Assert.Equal("params missing", RevertShape.StateBeforeFromParams(null).Error);
        Assert.Equal("params missing", RevertShape.StateBeforeFromParams(new Dictionary<string, object>()).Error);
    }

    // ── 1) TLS 1.0/1.1 ───────────────────────────────────────────────

    [Fact]
    public void LegacyTls_null_deletes_and_integer_sets_dword_on_the_read_paths()
    {
        var plan = Ok(RevertShape.LegacyTlsCheck,
            "{\"TLS 1.0.Server.Enabled\":null,\"TLS 1.0.Server.DisabledByDefault\":null,\"TLS 1.0.Client.Enabled\":0,\"TLS 1.1.Client.DisabledByDefault\":1}");

        Assert.True(plan.RequiresReboot);
        Assert.Equal(4, plan.Ops.Count);
        const string root = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

        Assert.Equal(RevertOpKind.RegistryDeleteValue, plan.Ops[0].Kind);
        Assert.Equal(root + @"\TLS 1.0\Server", plan.Ops[0].SubKey);
        Assert.Equal("Enabled", plan.Ops[0].Name);

        Assert.Equal(RevertOpKind.RegistryDeleteValue, plan.Ops[1].Kind);
        Assert.Equal("DisabledByDefault", plan.Ops[1].Name);

        Assert.Equal(RevertOpKind.RegistrySetDword, plan.Ops[2].Kind);
        Assert.Equal(root + @"\TLS 1.0\Client", plan.Ops[2].SubKey);
        Assert.Equal("Enabled", plan.Ops[2].Name);
        Assert.Equal(0, plan.Ops[2].Dword);

        Assert.Equal(RevertOpKind.RegistrySetDword, plan.Ops[3].Kind);
        Assert.Equal(root + @"\TLS 1.1\Client", plan.Ops[3].SubKey);
        Assert.Equal("DisabledByDefault", plan.Ops[3].Name);
        Assert.Equal(1, plan.Ops[3].Dword);
    }

    [Fact]
    public void LegacyTls_accepts_all_eight_keys_in_canonical_order_whatever_the_json_order()
    {
        var keys = RevertShape.LegacyTlsKeys().ToList();
        Assert.Equal(8, keys.Count);
        var json = "{" + string.Join(",", keys.AsEnumerable().Reverse().Select(k => $"\"{k}\":1")) + "}";
        var plan = Ok(RevertShape.LegacyTlsCheck, json);
        Assert.Equal(8, plan.Ops.Count);
        Assert.Equal(@"\TLS 1.0\Server", plan.Ops[0].SubKey![^15..]);
        Assert.Equal("Enabled", plan.Ops[0].Name);
        Assert.Equal(@"\TLS 1.1\Client", plan.Ops[7].SubKey![^15..]);
        Assert.Equal("DisabledByDefault", plan.Ops[7].Name);
    }

    [Theory]
    [InlineData("{\"TLS 1.2.Server.Enabled\":1}", "unexpected key")]
    [InlineData("{\"tls 1.0.server.enabled\":1}", "unexpected key")]            // la lectura emite estas mayúsculas exactas
    [InlineData("{\"TLS 1.0.Server.Enabled\":1,\"x\":1}", "unexpected key")]    // una sola clave mala tumba todo
    [InlineData("{\"TLS 1.0.Server.Enabled\":\"0\"}", "32-bit integer")]
    [InlineData("{\"TLS 1.0.Server.Enabled\":true}", "32-bit integer")]
    [InlineData("{\"TLS 1.0.Server.Enabled\":1.5}", "32-bit integer")]
    [InlineData("{\"TLS 1.0.Server.Enabled\":4294967295}", "32-bit integer")]  // la lectura da -1, nunca esto
    [InlineData("{\"TLS 1.0.Server.Enabled\":[0]}", "32-bit integer")]
    [InlineData("{\"TLS 1.0.Server.Enabled\":0,\"TLS 1.0.Server.Enabled\":1}", "duplicate key")]
    [InlineData("{}", "no keys")]
    public void LegacyTls_rejects_bad_state(string json, string fragment) =>
        Assert.Contains(fragment, Bad(RevertShape.LegacyTlsCheck, json));

    [Fact]
    public void LegacyTls_rejects_a_non_object() =>
        Assert.Contains("not an object", Bad(RevertShape.LegacyTlsCheck, "[1]"));

    // ── 2) Cifrados débiles ──────────────────────────────────────────

    [Fact]
    public void WeakCiphers_keep_the_slash_in_the_subkey_name_and_minus_one_as_dword()
    {
        var plan = Ok(RevertShape.WeakCiphersCheck,
            "{\"RC4 128/128\":-1,\"NULL\":null,\"Triple DES 168\":0}");

        Assert.True(plan.RequiresReboot);
        Assert.Equal(3, plan.Ops.Count);
        const string root = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers";

        // Orden canónico de WeakCiphers: NULL, …, RC4 128/128, Triple DES 168.
        Assert.Equal(RevertOpKind.RegistryDeleteValue, plan.Ops[0].Kind);
        Assert.Equal(root + @"\NULL", plan.Ops[0].SubKey);
        Assert.Equal("Enabled", plan.Ops[0].Name);

        Assert.Equal(RevertOpKind.RegistrySetDword, plan.Ops[1].Kind);
        Assert.Equal(root + @"\RC4 128/128", plan.Ops[1].SubKey);   // barra literal, sin normalizar
        Assert.Equal(-1, plan.Ops[1].Dword);                         // 0xFFFFFFFF
        Assert.Contains("0xFFFFFFFF", plan.Ops[1].Describe());

        Assert.Equal(root + @"\Triple DES 168", plan.Ops[2].SubKey);
        Assert.Equal(0, plan.Ops[2].Dword);
    }

    [Theory]
    [InlineData("{\"RC4 128\\\\128\":0}")]   // backslash en vez de barra: no es un nombre de la lista
    [InlineData("{\"AES 128/128\":0}")]
    [InlineData("{\"rc4 128/128\":0}")]
    public void WeakCiphers_reject_names_outside_the_list(string json) =>
        Assert.Contains("unexpected key", Bad(RevertShape.WeakCiphersCheck, json));

    [Fact]
    public void WeakCiphers_reject_non_integer_values() =>
        Assert.Contains("32-bit integer", Bad(RevertShape.WeakCiphersCheck, "{\"NULL\":\"0xffffffff\"}"));

    // ── 3) SMBv1 ─────────────────────────────────────────────────────

    [Fact]
    public void SmbV1_restores_registry_then_enables_the_feature_when_it_was_on()
    {
        var plan = Ok(RevertShape.SmbV1Check,
            "{\"LanmanServer.SMB1\":null,\"OptionalFeature.SMB1Protocol.Enabled\":true}");
        Assert.True(plan.RequiresReboot);
        Assert.Equal(2, plan.Ops.Count);
        Assert.Equal(RevertOpKind.RegistryDeleteValue, plan.Ops[0].Kind);
        Assert.Equal(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", plan.Ops[0].SubKey);
        Assert.Equal("SMB1", plan.Ops[0].Name);
        Assert.Equal(RevertOpKind.EnableSmb1Feature, plan.Ops[1].Kind);
    }

    [Theory]
    [InlineData("false")]
    [InlineData("null")]
    public void SmbV1_leaves_the_feature_alone_when_it_was_off_or_unknown(string feature)
    {
        var plan = Ok(RevertShape.SmbV1Check,
            "{\"LanmanServer.SMB1\":1,\"OptionalFeature.SMB1Protocol.Enabled\":" + feature + "}");
        var op = Assert.Single(plan.Ops);
        Assert.Equal(RevertOpKind.RegistrySetDword, op.Kind);
        Assert.Equal(1, op.Dword);
    }

    [Theory]
    [InlineData("{\"OptionalFeature.SMB1Protocol.Enabled\":\"Enabled\"}", "boolean")]
    [InlineData("{\"OptionalFeature.SMB1Protocol.Enabled\":1}", "boolean")]
    [InlineData("{\"LanmanServer.SMB1\":false}", "32-bit integer")]
    [InlineData("{\"LanmanServer.SMB2\":0}", "unexpected key")]
    public void SmbV1_rejects_bad_state(string json, string fragment) =>
        Assert.Contains(fragment, Bad(RevertShape.SmbV1Check, json));

    // ── 4) Firewall ──────────────────────────────────────────────────

    [Fact]
    public void Firewall_only_disables_profiles_that_were_off()
    {
        var plan = Ok(RevertShape.FirewallCheck, "{\"Domain\":true,\"Private\":false,\"Public\":true}");
        Assert.False(plan.RequiresReboot);
        var op = Assert.Single(plan.Ops);
        Assert.Equal(RevertOpKind.DisableFirewallProfile, op.Kind);
        Assert.Equal("Private", op.Name);
        Assert.Equal("Set-NetFirewallProfile -Profile Private -Enabled False", op.Describe());
    }

    [Fact]
    public void Firewall_all_on_before_means_nothing_to_do()
    {
        var plan = Ok(RevertShape.FirewallCheck, "{\"Domain\":true,\"Private\":true,\"Public\":true}");
        Assert.Empty(plan.Ops);
    }

    [Theory]
    [InlineData("{\"Domain; Remove-Item C:\\\\\":false}", "unexpected key")]  // nunca se interpola una clave
    [InlineData("{\"domain\":false}", "unexpected key")]
    [InlineData("{\"Domain\":0}", "boolean")]
    [InlineData("{\"Domain\":null}", "boolean")]
    [InlineData("{\"Domain\":\"False\"}", "boolean")]
    [InlineData("{}", "no keys")]
    public void Firewall_rejects_bad_state(string json, string fragment) =>
        Assert.Contains(fragment, Bad(RevertShape.FirewallCheck, json));

    // ── 5) Recursos compartidos ──────────────────────────────────────

    [Fact]
    public void Shares_plan_one_grant_per_name_without_case_duplicates()
    {
        var plan = Ok(RevertShape.SharesCheck, "{\"sharesWithEveryoneFullControl\":[\"Public\",\"Juan's docs\",\"public\"]}");
        Assert.False(plan.RequiresReboot);
        Assert.Equal(2, plan.Ops.Count);
        Assert.All(plan.Ops, o => Assert.Equal(RevertOpKind.GrantShareEveryoneFull, o.Kind));
        Assert.Equal("Public", plan.Ops[0].Name);
        Assert.Equal("Juan's docs", plan.Ops[1].Name);
    }

    [Fact]
    public void Shares_empty_list_is_a_valid_nothing_to_restore()
    {
        var plan = Ok(RevertShape.SharesCheck, "{\"sharesWithEveryoneFullControl\":[]}");
        Assert.Empty(plan.Ops);
    }

    [Theory]
    [InlineData("{\"sharesWithEveryoneFullControl\":[],\"queryError\":true}", "queryError")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[\"A\"],\"queryError\":false}", "queryError")]
    [InlineData("{\"sharesWithEveryoneFullControl\":\"A\"}", "array of strings")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[1]}", "array of strings")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[null]}", "array of strings")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[\"\"]}", "empty")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[\"a\\\"; Stop-Computer; \\\"\"]}", "contains '\"'")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[\"a\\\\b\"]}", "contains '\\'")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[\"a\\nb\"]}", "control character")]
    [InlineData("{\"sharesWithEveryoneFullControl\":[\"a;b\"]}", "contains ';'")]
    [InlineData("{\"shares\":[\"A\"]}", "unexpected key")]
    [InlineData("{}", "no keys")]
    public void Shares_reject_bad_state(string json, string fragment) =>
        Assert.Contains(fragment, Bad(RevertShape.SharesCheck, json));

    [Fact]
    public void Shares_reject_overlong_names()
    {
        var name = new string('a', 81);
        Assert.Contains("80", Bad(RevertShape.SharesCheck, "{\"sharesWithEveryoneFullControl\":[\"" + name + "\"]}"));
    }

    [Fact]
    public void Shares_reject_too_many_names()
    {
        var names = string.Join(",", Enumerable.Range(0, RevertShape.MaxShares + 1).Select(i => $"\"s{i}\""));
        Assert.Contains("more than", Bad(RevertShape.SharesCheck, "{\"sharesWithEveryoneFullControl\":[" + names + "]}"));
    }

    [Theory]
    [InlineData("Juan's docs", "Juan''s docs")]
    [InlineData("it'''s", "it''''''s")]
    [InlineData("a\u2019b", "a\u2019\u2019b")]     // PowerShell también cierra con la comilla tipográfica
    [InlineData("a\u2018b\u201Ac\u201Bd", "a\u2018\u2018b\u201A\u201Ac\u201B\u201Bd")]
    [InlineData("plain $name `x", "plain $name `x")] // entre comillas simples $ y ` son literales
    public void Share_names_are_escaped_for_single_quoted_powershell(string name, string expected) =>
        Assert.Equal(expected, RevertShape.EscapePsSingleQuoted(name));

    [Theory]
    [InlineData("", 0)]
    [InlineData("null", 0)]
    [InlineData("\"Only\"", 1)]
    [InlineData("[\"A\",\"B c\"]", 2)]
    public void Share_list_output_is_parsed(string stdout, int count) =>
        Assert.Equal(count, RevertShape.ParseShareNames(stdout)!.Count);

    [Theory]
    [InlineData("Get-SmbShare : Access is denied")]
    [InlineData("[1,2]")]
    [InlineData("{\"Name\":\"A\"}")]
    public void Share_list_that_cannot_be_read_is_not_an_empty_list(string stdout) =>
        Assert.Null(RevertShape.ParseShareNames(stdout));

    [Fact]
    public void Shares_are_resolved_against_what_exists_today()
    {
        var (toGrant, already, missing) = RevertShape.ResolveShares(
            wanted: new[] { "public", "Data", "Gone" },
            currentShares: new[] { "Public", "Data", "Other" },
            currentlyGranted: new[] { "data" });

        // Se concede con el nombre que devuelve Get-SmbShare, no con el recibido.
        Assert.Equal(new[] { "Public" }, toGrant);
        Assert.Equal(new[] { "Data" }, already);
        Assert.Equal(new[] { "Gone" }, missing);
    }

    [Theory]
    [InlineData(0, 2, 0, RevertShape.SharesNothingRestoredExit)] // nada restaurado y faltan: fallo
    [InlineData(1, 2, 0, 0)]                                     // alguno volvió: éxito con aviso
    [InlineData(2, 0, 0, 0)]
    [InlineData(0, 0, 0, 0)]                                     // nada que restaurar
    [InlineData(1, 0, 5, 5)]                                     // un Grant que falla manda
    public void Shares_exit_code_is_non_zero_only_when_nothing_came_back(int restored, int missing, int failure, int expected) =>
        Assert.Equal(expected, RevertShape.SharesExitCode(restored, missing, failure));
}
