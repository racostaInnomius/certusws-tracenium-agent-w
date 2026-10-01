// privsvc/windows/Tracenium.PrivSvc.Tests/LocalPolicyShapeTests.cs
//
// La política local como respaldo de una escritura que Windows bloquea
// (W11-JPR-LAB02, 1-oct-2026). Lo que se fija: el formato de Registry.pol
// (MS-GPREG) byte a byte, que añadir NUESTRO valor no toca ni reordena los
// demás, que un fichero que no se entiende no se reescribe, y que gpt.ini
// sube la versión de equipo y lista la extensión de registro.

using System.Text;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class LocalPolicyShapeTests
{
    private const string FeedsKey = @"Software\Policies\Microsoft\Windows\Windows Feeds";

    // Los bytes escritos A MANO según MS-GPREG, no con Serialize: si no, el
    // test sólo comprobaría que el serializador está de acuerdo consigo mismo.
    private static byte[] Pol(params (string key, string value, uint type, byte[] data)[] entries)
    {
        var b = new List<byte> { 0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00 };
        void C(char c) { b.Add((byte)c); b.Add(0); }
        foreach (var (key, value, type, data) in entries)
        {
            C('['); b.AddRange(Encoding.Unicode.GetBytes(key)); b.Add(0); b.Add(0);
            C(';'); b.AddRange(Encoding.Unicode.GetBytes(value)); b.Add(0); b.Add(0);
            C(';'); b.AddRange(BitConverter.GetBytes(type));
            C(';'); b.AddRange(BitConverter.GetBytes((uint)data.Length));
            C(';'); b.AddRange(data);
            C(']');
        }
        return b.ToArray();
    }

    private static byte[] Dword(uint v) => BitConverter.GetBytes(v);

    [Fact]
    public void Writes_the_EnableFeeds_entry_byte_for_byte_as_MS_GPREG_defines_it()
    {
        var bytes = LocalPolicyShape.Serialize(new[]
        {
            LocalPolicyShape.ValueEntry(FeedsKey, "EnableFeeds", LocalPolicyShape.RegDword, LocalPolicyShape.DwordData(0)),
        });
        Assert.Equal(Pol((FeedsKey, "EnableFeeds", 4, Dword(0))), bytes);
    }

    [Fact]
    public void Reads_back_what_it_writes_and_what_another_tool_wrote()
    {
        var original = Pol(
            (@"Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 4, Dword(1)),
            (@"Software\Policies\Microsoft\Windows\System", "Banner", 1, Encoding.Unicode.GetBytes("Hola\0")));
        var parsed = LocalPolicyShape.Parse(original);
        Assert.Equal(2, parsed.Count);
        Assert.Equal("Banner", parsed[1].ValueName);
        Assert.Equal(original, LocalPolicyShape.Serialize(parsed));
    }

    [Fact]
    public void Missing_or_empty_file_is_an_empty_policy()
    {
        Assert.Empty(LocalPolicyShape.Parse(null));
        Assert.Empty(LocalPolicyShape.Parse(Array.Empty<byte>()));
        Assert.Empty(LocalPolicyShape.Parse(Pol()));
        Assert.Equal(Pol(), LocalPolicyShape.Serialize(Array.Empty<PolEntry>()));
    }

    // 🔴 Ahí puede haber directivas configuradas a mano: perderlas en silencio
    // es peor que no aplicar la nuestra.
    [Fact]
    public void A_file_it_does_not_understand_is_refused_not_rewritten()
    {
        Assert.Throws<FormatException>(() => LocalPolicyShape.Parse(Encoding.ASCII.GetBytes("not a pol file")));
        var ok = Pol((FeedsKey, "EnableFeeds", 4, Dword(0)));
        Assert.Throws<FormatException>(() => LocalPolicyShape.Parse(ok[..^3]));
        // Entradas impecables, pero de una versión del formato que no es la 1:
        // sólo la cabecera lo detecta, y no se adivina.
        var otherVersion = (byte[])ok.Clone();
        otherVersion[4] = 2;
        Assert.Throws<FormatException>(() => LocalPolicyShape.Parse(otherVersion));
        var lyingSize = (byte[])ok.Clone();
        lyingSize[^8] = 0xFF; // tamaño de datos mayor que lo que queda
        Assert.Throws<FormatException>(() => LocalPolicyShape.Parse(lyingSize));
    }

    [Fact]
    public void Upsert_replaces_only_our_value_and_keeps_the_rest_in_order()
    {
        var entries = LocalPolicyShape.Parse(Pol(
            (@"Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 4, Dword(1)),
            (FeedsKey, "enablefeeds", 4, Dword(1)),          // otro valor anterior, con otra capitalización
            (FeedsKey, "**del.EnableFeeds", 1, Encoding.Unicode.GetBytes(" \0")),
            (FeedsKey, "OtherValue", 4, Dword(7))));
        var result = LocalPolicyShape.Upsert(entries,
            LocalPolicyShape.ValueEntry(@"\" + FeedsKey + @"\", "EnableFeeds", LocalPolicyShape.RegDword, LocalPolicyShape.DwordData(0)));

        Assert.Equal(new[] { "NoLockScreenCamera", "OtherValue", "EnableFeeds" }, result.Select(e => e.ValueName));
        Assert.Equal(FeedsKey, result[^1].Key); // sin barras sobrantes
        Assert.Equal(Dword(0), result[^1].Data);
    }

    [Fact]
    public void A_delete_is_written_as_a_del_entry_and_replaces_a_previous_value()
    {
        var entries = LocalPolicyShape.Parse(Pol((FeedsKey, "EnableFeeds", 4, Dword(0))));
        var result = LocalPolicyShape.Upsert(entries, LocalPolicyShape.DeleteEntry(FeedsKey, "EnableFeeds"));
        var only = Assert.Single(result);
        Assert.Equal("**del.EnableFeeds", only.ValueName);
        Assert.Equal(LocalPolicyShape.RegSz, only.Type);
    }

    [Fact]
    public void EntryFor_maps_each_generic_write_to_the_same_type_and_value()
    {
        RegistryWriteSpec W(GenericValueKind k) => new()
        {
            SubKey = FeedsKey, ValueName = "V", Kind = k,
            DwordValue = 5, StringValue = "x", MultiValue = new[] { "a", "b" },
        };
        var dword = LocalPolicyShape.EntryFor(W(GenericValueKind.DWord));
        Assert.Equal(LocalPolicyShape.RegDword, dword.Type);
        Assert.Equal(Dword(5), dword.Data);
        Assert.Equal(Encoding.Unicode.GetBytes("x\0"), LocalPolicyShape.EntryFor(W(GenericValueKind.String)).Data);
        Assert.Equal(Encoding.Unicode.GetBytes("a\0b\0\0"), LocalPolicyShape.EntryFor(W(GenericValueKind.MultiString)).Data);
        Assert.Equal("**del.V", LocalPolicyShape.EntryFor(W(GenericValueKind.Delete)).ValueName);
    }

    // ── gpt.ini ───────────────────────────────────────────────────────

    [Fact]
    public void A_missing_gpt_ini_is_created_with_the_registry_extension_and_version_1()
    {
        Assert.Equal(
            "[General]\r\ngPCMachineExtensionNames=[" + LocalPolicyShape.RegistryCsePair + "]\r\nVersion=1\r\n",
            LocalPolicyShape.UpdateGptIni(null));
    }

    [Fact]
    public void Only_the_machine_half_of_Version_goes_up_and_it_wraps_without_touching_the_user_half()
    {
        string V(string ini) => ini.Split("\r\n").Single(l => l.StartsWith("Version="));
        // usuario 1 (alto) + equipo 1 (bajo) = 65537
        Assert.Equal("Version=65538", V(LocalPolicyShape.UpdateGptIni("[General]\r\nVersion=65537\r\n")));
        Assert.Equal($"Version={(1u << 16) | 1u}", V(LocalPolicyShape.UpdateGptIni($"[General]\r\nVersion={(1u << 16) | 0xFFFFu}\r\n")));
    }

    [Fact]
    public void The_registry_extension_is_added_in_GUID_order_once_and_other_lines_survive()
    {
        const string audit = "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}";
        var ini = "[General]\r\ndisplayName=Local\r\ngPCMachineExtensionNames=[" + audit + "]\r\nVersion=3\r\n";
        var once = LocalPolicyShape.UpdateGptIni(ini);
        Assert.Contains("gPCMachineExtensionNames=[" + LocalPolicyShape.RegistryCsePair + "][" + audit + "]", once);
        Assert.Contains("displayName=Local", once);
        // Otra vez: no se duplica.
        var twice = LocalPolicyShape.UpdateGptIni(once);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(twice, "35378EAC").Cast<object>());
    }
}
