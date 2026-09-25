// privsvc/windows/Tracenium.PrivSvc.Tests/FirewallStatusShapeTests.cs
//
// 🔴 25-sep-2026: toda la flota Windows salía con el firewall APAGADO.
// `Enabled` llega de PowerShell 5.1 como número (enum GpoBoolean) y el
// colector lo leía con bool.TryParse("1") → false. En producción, 0 equipos en
// `pass` en los tres checks de perfil; una consulta en vivo del registro en T1
// dio 3 de 4 con todo encendido.
//
// Lo que se fija aquí: se entiende el número Y el texto, lo que no se entiende
// NO es `false` (el perfil se omite), el firewall de terceros se cuenta sin
// decodificar productState, y las reglas de bloqueo de entrada se ven.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class FirewallStatusShapeTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

    private static Dictionary<string, object?> Profiles(Dictionary<string, object?> shaped) =>
        (Dictionary<string, object?>)shaped["profiles"]!;

    private static Dictionary<string, object?> Settings(Dictionary<string, object?> shaped, string p) =>
        (Dictionary<string, object?>)((Dictionary<string, object?>)shaped["profileSettings"]!)[p]!;

    [Fact]
    public void El_bug_el_numero_1_es_encendido()
    {
        // La salida EXACTA del colector viejo en PS 5.1: el enum como número.
        // Antes esto daba los tres perfiles en false.
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"store\":\"PersistentStore\",\"profiles\":[{\"Name\":\"Domain\",\"Enabled\":1},{\"Name\":\"Private\",\"Enabled\":1},{\"Name\":\"Public\",\"Enabled\":0}],\"securityCenter\":true,\"products\":[]}");

        Assert.NotNull(shaped);
        Assert.Equal(true, Profiles(shaped!)["domain"]);
        Assert.Equal(true, Profiles(shaped!)["private"]);
        Assert.Equal(false, Profiles(shaped!)["public"]);
        Assert.Equal("enabled", shaped!["status"]);
    }

    [Fact]
    public void El_script_nuevo_manda_el_nombre_del_enum()
    {
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"store\":\"ActiveStore\",\"profiles\":[" +
            "{\"Name\":\"Domain\",\"Enabled\":\"True\",\"DefaultInboundAction\":\"Block\",\"DefaultOutboundAction\":\"Allow\",\"AllowLocalFirewallRules\":\"True\",\"LogBlocked\":\"True\",\"LogAllowed\":\"False\",\"LogFileName\":\"%systemroot%\\\\system32\\\\LogFiles\\\\Firewall\\\\pfirewall.log\"}," +
            "{\"Name\":\"Private\",\"Enabled\":\"False\",\"DefaultInboundAction\":\"NotConfigured\",\"DefaultOutboundAction\":\"NotConfigured\"}," +
            "{\"Name\":\"Public\",\"Enabled\":\"False\"}],\"securityCenter\":true,\"products\":[]}");

        Assert.Equal("ActiveStore", shaped!["store"]);
        Assert.Equal(true, Profiles(shaped)["domain"]);
        Assert.Equal(false, Profiles(shaped)["private"]);
        var d = Settings(shaped, "domain");
        Assert.Equal("block", d["defaultInboundAction"]);
        Assert.Equal("allow", d["defaultOutboundAction"]);
        Assert.Equal(true, d["allowLocalRules"]);
        Assert.Equal(true, d["logBlocked"]);
        Assert.Equal(false, d["logAllowed"]);
        // NotConfigured no es ni permitir ni bloquear: no se sabe.
        Assert.Null(Settings(shaped, "private")["defaultInboundAction"]);
    }

    [Fact]
    public void Lo_que_no_se_entiende_no_es_apagado()
    {
        // "NotConfigured" (2) o un valor raro: el perfil NO entra en
        // `profiles` y el check queda sin evaluar, en vez de un fail inventado.
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"profiles\":[{\"Name\":\"Domain\",\"Enabled\":2},{\"Name\":\"Private\",\"Enabled\":\"NotConfigured\"},{\"Name\":\"Public\",\"Enabled\":\"???\"}]}");

        Assert.NotNull(shaped);
        Assert.Empty(Profiles(shaped!));
        Assert.Equal("unknown", shaped!["status"]);
    }

    [Fact]
    public void Un_solo_perfil_llega_como_objeto_y_no_como_lista()
    {
        // ConvertTo-Json desenvuelve las listas de un elemento.
        var shaped = FirewallStatusShape.FromScriptOutput("{\"profiles\":{\"Name\":\"Public\",\"Enabled\":\"True\"}}");
        Assert.Equal(true, Profiles(shaped!)["public"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"profiles\":[]}")]
    public void Sin_perfiles_legibles_no_hay_bloque(string output)
    {
        Assert.Null(FirewallStatusShape.FromScriptOutput(output));
    }

    [Fact]
    public void Firewall_de_terceros_se_cuenta_sin_decodificar_el_estado()
    {
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"profiles\":[{\"Name\":\"Domain\",\"Enabled\":\"False\"}],\"securityCenter\":true," +
            "\"products\":[{\"displayName\":\"ESET Firewall\",\"productState\":266256},{\"displayName\":\"ESET Firewall\",\"productState\":266256},{\"displayName\":\"Windows Firewall\",\"productState\":1}]}");

        Assert.Equal("security_center", shaped!["thirdPartySource"]);
        // Duplicados y el propio firewall de Windows no cuentan.
        Assert.Equal(1, shaped["thirdPartyCount"]);
        Assert.Equal(new List<string> { "ESET Firewall" }, shaped["thirdPartyNames"]);
        // El estado crudo viaja para quien quiera mirarlo; no se interpreta.
        var products = (List<Dictionary<string, object?>>)shaped["thirdPartyProducts"]!;
        Assert.Equal(266256L, products[0]["productState"]);
    }

    [Fact]
    public void Un_servidor_sin_centro_de_seguridad_lo_dice()
    {
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"profiles\":[{\"Name\":\"Domain\",\"Enabled\":\"True\"}],\"securityCenter\":false,\"products\":[]}");

        Assert.Equal("unavailable", shaped!["thirdPartySource"]);
        // Nada registrado: los controles del firewall de Windows siguen aplicando.
        Assert.Equal(0, shaped["thirdPartyCount"]);
    }

    [Fact]
    public void La_directiva_de_grupo_se_une_por_perfil()
    {
        var gpo = new Dictionary<string, FirewallStatusShape.GpoProfile>
        {
            ["domain"] = new() { EnableFirewall = false, AnyValue = true },
        };
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"profiles\":[{\"Name\":\"Domain\",\"Enabled\":\"False\"},{\"Name\":\"Public\",\"Enabled\":\"True\"}]}", gpo);

        Assert.Equal(false, Settings(shaped!, "domain")["gpoEnabled"]);
        Assert.Equal(true, Settings(shaped!, "domain")["gpoManaged"]);
        Assert.Null(Settings(shaped!, "public")["gpoEnabled"]);
        Assert.Equal(false, Settings(shaped!, "public")["gpoManaged"]);
    }

    [Fact]
    public void Parsea_una_regla_del_registro()
    {
        var r = FirewallStatusShape.ParseRule(
            "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=5353|App=C:\\Program Files\\Foo\\foo.exe|Name=foo.exe|Desc=foo.exe|");

        Assert.NotNull(r);
        Assert.Equal("block", r!.Action);
        Assert.True(r.Active);
        Assert.Equal("in", r.Dir);
        Assert.Equal("udp", r.Protocol);
        Assert.Equal(new[] { "private", "public" }, r.Profiles);
        Assert.Equal(new[] { "5353" }, r.LocalPorts);
        Assert.Equal("C:\\Program Files\\Foo\\foo.exe", r.App);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Action=Allow|Dir=In")]
    [InlineData("basura")]
    public void Lo_que_no_es_una_regla_es_null(string? raw)
    {
        Assert.Null(FirewallStatusShape.ParseRule(raw));
    }

    [Fact]
    public void El_resumen_cuenta_solo_las_de_entrada_activas_y_detalla_las_de_bloqueo()
    {
        var s = FirewallStatusShape.SummarizeRules(new[]
        {
            ("local", "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=@FirewallAPI.dll,-28502|"),
            ("local", "v2.10|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3389|Name=RDP|"),
            ("local", "v2.10|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|Name=salida|"),
            ("local", "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=C:\\a.exe|Name=a.exe|"),
            ("gpo", "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=23|Profile=Domain|Name=Telnet|"),
            ("local", "no-es-una-regla"),
        });

        Assert.Equal(1, s["inboundAllow"]);
        Assert.Equal(2, s["inboundBlock"]);
        Assert.Equal(1, s["unparsed"]);
        Assert.Equal(false, s["truncated"]);
        var block = (List<Dictionary<string, object?>>)s["inboundBlockRules"]!;
        Assert.Equal(2, block.Count);
        // Sin `Profile=` aplica a todos los perfiles, y así se dice.
        Assert.Equal(new List<string> { "all" }, block[0]["profiles"]);
        Assert.Equal("gpo", block[1]["source"]);
        Assert.Equal(new List<string> { "23" }, block[1]["localPorts"]);
    }

    [Fact]
    public void El_detalle_de_bloqueo_tiene_tope_y_lo_dice()
    {
        var raws = Enumerable.Range(0, FirewallStatusShape.MaxBlockRules + 5)
            .Select(i => ("local", $"v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=C:\\p{i}.exe|Name=p{i}|"));
        var s = FirewallStatusShape.SummarizeRules(raws);

        Assert.Equal(FirewallStatusShape.MaxBlockRules + 5, s["inboundBlock"]);
        Assert.Equal(FirewallStatusShape.MaxBlockRules, ((List<Dictionary<string, object?>>)s["inboundBlockRules"]!).Count);
        Assert.Equal(true, s["truncated"]);
    }

    [Fact]
    public void El_resumen_de_reglas_viaja_en_el_bloque()
    {
        var rules = FirewallStatusShape.SummarizeRules(Array.Empty<(string, string)>());
        var shaped = FirewallStatusShape.FromScriptOutput("{\"profiles\":[{\"Name\":\"Domain\",\"Enabled\":\"True\"}]}", null, rules);
        Assert.Same(rules, shaped!["rules"]);
    }

    [Fact]
    public void El_bloque_se_serializa_con_las_rutas_que_lee_el_catalogo()
    {
        // Los checks leen firewall.profiles.<perfil> y firewall.thirdPartyCount.
        var shaped = FirewallStatusShape.FromScriptOutput(
            "{\"profiles\":[{\"Name\":\"Public\",\"Enabled\":1}],\"securityCenter\":true,\"products\":[]}");
        var json = J(JsonSerializer.Serialize(shaped));

        Assert.True(json.GetProperty("profiles").GetProperty("public").GetBoolean());
        Assert.Equal(0, json.GetProperty("thirdPartyCount").GetInt32());
        Assert.Equal("enabled", json.GetProperty("status").GetString());
    }
}
