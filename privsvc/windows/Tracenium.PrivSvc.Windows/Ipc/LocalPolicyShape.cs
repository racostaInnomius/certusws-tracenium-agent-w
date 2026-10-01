// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/LocalPolicyShape.cs
//
// La política de grupo LOCAL, la parte PURA: leer y escribir `Registry.pol`
// y `gpt.ini`. Abrir ficheros y lanzar gpupdate queda en LocalPolicy.cs. Sin
// Microsoft.Win32 dentro para compilarse y probarse fuera de Windows, como
// GenericWriteShape.
//
// ── Por qué existe ───────────────────────────────────────────────────
//
// W11-JPR-LAB02 (Windows 11 26300, 1-oct-2026): Windows deniega escribir
// directamente `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds\
// EnableFeeds` —a SYSTEM y a un administrador con `reg add`, con la ACL
// normal—, un filtro del kernel (probablemente UCPD). Escrito como política
// local (LGPO.exe + gpupdate) el MISMO valor SÍ queda: lo escribe el cliente
// de directivas de Windows, y el bloqueo le deja pasar. Y no hace falta la
// plantilla .admx: el cliente aplica Registry.pol aunque gpedit no sepa
// enseñar el ajuste.
//
// ── Formato de Registry.pol (MS-GPREG 2.2.1) ─────────────────────────
//
//   cabecera   "PReg" + versión 1 (uint32 LE)
//   entradas   [clave;valor;tipo;tamaño;datos]
//
// Los corchetes y los punto y coma son caracteres UTF-16LE; clave y valor,
// UTF-16LE terminados en NUL; tipo y tamaño, uint32 LE; datos, `tamaño`
// bytes tal cual. Un valor llamado `**del.<nombre>` significa «este valor
// no debe existir» y el cliente lo borra en cada aplicación.
//
// ⚠️ Un fichero que no se entiende NO se sobrescribe: se lanza
// FormatException y el llamante no toca nada. Ahí puede haber directivas que
// alguien configuró a mano, y perderlas en silencio es peor que no aplicar
// la nuestra.

using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed record PolEntry(string Key, string ValueName, uint Type, byte[] Data);

public static class LocalPolicyShape
{
    public const uint RegSz = 1;
    public const uint RegDword = 4;
    public const uint RegMultiSz = 7;

    /// <summary>Extensión de registro + herramienta de plantillas administrativas.</summary>
    public const string RegistryCseGuid = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}";
    public const string RegistryCsePair = RegistryCseGuid + "{D02B1F72-3407-48AE-BA88-E8213C6761F1}";

    public const string DeletePrefix = "**del.";

    private static readonly byte[] Header = { 0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00 };

    // ── Registry.pol ──────────────────────────────────────────────────

    public static List<PolEntry> Parse(byte[]? bytes)
    {
        var entries = new List<PolEntry>();
        if (bytes is null || bytes.Length == 0) return entries;
        if (bytes.Length < Header.Length || !bytes.AsSpan(0, Header.Length).SequenceEqual(Header))
            throw new FormatException("Registry.pol: unexpected header");

        var p = Header.Length;
        while (p < bytes.Length)
        {
            Expect(bytes, ref p, '[');
            var key = ReadZ(bytes, ref p);
            Expect(bytes, ref p, ';');
            var value = ReadZ(bytes, ref p);
            Expect(bytes, ref p, ';');
            var type = ReadU32(bytes, ref p);
            Expect(bytes, ref p, ';');
            var size = ReadU32(bytes, ref p);
            Expect(bytes, ref p, ';');
            if (size > (uint)(bytes.Length - p)) throw new FormatException("Registry.pol: data runs past the end");
            var data = bytes.AsSpan(p, (int)size).ToArray();
            p += (int)size;
            Expect(bytes, ref p, ']');
            entries.Add(new PolEntry(key, value, type, data));
        }
        return entries;
    }

    public static byte[] Serialize(IEnumerable<PolEntry> entries)
    {
        using var ms = new MemoryStream();
        ms.Write(Header);
        foreach (var e in entries)
        {
            WriteChar(ms, '[');
            ms.Write(Encoding.Unicode.GetBytes(e.Key + "\0"));
            WriteChar(ms, ';');
            ms.Write(Encoding.Unicode.GetBytes(e.ValueName + "\0"));
            WriteChar(ms, ';');
            ms.Write(BitConverter.GetBytes(e.Type));
            WriteChar(ms, ';');
            ms.Write(BitConverter.GetBytes((uint)e.Data.Length));
            WriteChar(ms, ';');
            ms.Write(e.Data);
            WriteChar(ms, ']');
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Fija el valor: quita cualquier entrada anterior de ESE valor en ESA
    /// clave (también un `**del.` que lo borraría) y añade la nueva al final.
    /// El resto del fichero no se toca, en el mismo orden.
    /// </summary>
    public static List<PolEntry> Upsert(IEnumerable<PolEntry> entries, PolEntry entry)
    {
        var name = BareName(entry.ValueName);
        var kept = entries.Where(e => !(SameKey(e.Key, entry.Key) && SameName(BareName(e.ValueName), name))).ToList();
        kept.Add(entry);
        return kept;
    }

    /// <summary>«Este valor no debe existir», como lo dice una directiva.</summary>
    public static PolEntry DeleteEntry(string key, string valueName) =>
        new(NormalizeKey(key), DeletePrefix + valueName, RegSz, Encoding.Unicode.GetBytes(" \0"));

    public static PolEntry ValueEntry(string key, string valueName, uint type, byte[] data) =>
        new(NormalizeKey(key), valueName, type, data);

    public static byte[] DwordData(uint v) => BitConverter.GetBytes(v);
    public static byte[] StringData(string s) => Encoding.Unicode.GetBytes(s + "\0");
    public static byte[] MultiStringData(IEnumerable<string> items) =>
        Encoding.Unicode.GetBytes(string.Concat(items.Select(i => i + "\0")) + "\0");

    /// <summary>
    /// La entrada de política que equivale a una escritura genérica de HKLM:
    /// mismo valor y mismo tipo, o `**del.` para un borrado.
    /// </summary>
    public static PolEntry EntryFor(RegistryWriteSpec w) => w.Kind switch
    {
        GenericValueKind.Delete => DeleteEntry(w.SubKey, w.ValueName),
        GenericValueKind.DWord => ValueEntry(w.SubKey, w.ValueName, RegDword, DwordData(w.DwordValue)),
        GenericValueKind.String => ValueEntry(w.SubKey, w.ValueName, RegSz, StringData(w.StringValue ?? "")),
        _ => ValueEntry(w.SubKey, w.ValueName, RegMultiSz, MultiStringData(w.MultiValue ?? Array.Empty<string>())),
    };

    /// <summary>Registry.pol guarda la clave relativa al hive, sin barras sobrantes.</summary>
    public static string NormalizeKey(string key) => key.Trim().Trim('\\');

    // ── gpt.ini ───────────────────────────────────────────────────────

    /// <summary>
    /// Sube la versión de EQUIPO (los 16 bits bajos; los altos son la de
    /// usuario) y se asegura de que `gPCMachineExtensionNames` incluye la
    /// extensión de registro. Sin lo primero el cliente puede dar la
    /// directiva por ya aplicada; sin lo segundo, no procesa Registry.pol.
    /// Conserva cualquier otra línea.
    /// </summary>
    public static string UpdateGptIni(string? existing)
    {
        var lines = (existing ?? "").Replace("\r\n", "\n").Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        while (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);

        var general = lines.FindIndex(l => l.Trim().Equals("[General]", StringComparison.OrdinalIgnoreCase));
        if (general < 0)
        {
            lines.Insert(0, "[General]");
            general = 0;
        }
        var end = lines.FindIndex(general + 1, l => l.TrimStart().StartsWith('['));
        if (end < 0) end = lines.Count;

        int Find(string name) =>
            lines.FindIndex(general + 1, end - general - 1, l => l.TrimStart().StartsWith(name + "=", StringComparison.OrdinalIgnoreCase));

        var v = Find("Version");
        uint current = 0;
        if (v >= 0) uint.TryParse(lines[v][(lines[v].IndexOf('=') + 1)..].Trim(), out current);
        var machine = (current & 0xFFFF) + 1;
        if (machine > 0xFFFF) machine = 1;
        var next = $"Version={(current & 0xFFFF0000) | machine}";
        if (v >= 0) lines[v] = next;
        else { lines.Insert(end, next); end++; }

        var x = Find("gPCMachineExtensionNames");
        var groups = new List<string>();
        if (x >= 0)
        {
            var raw = lines[x][(lines[x].IndexOf('=') + 1)..];
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(raw, @"\[([^\]]*)\]"))
                groups.Add(m.Groups[1].Value);
        }
        if (!groups.Any(g => g.StartsWith(RegistryCseGuid, StringComparison.OrdinalIgnoreCase)))
        {
            groups.Add(RegistryCsePair);
            // La lista va ordenada por el GUID de la extensión.
            groups = groups.OrderBy(g => g, StringComparer.OrdinalIgnoreCase).ToList();
        }
        var ext = "gPCMachineExtensionNames=" + string.Concat(groups.Select(g => "[" + g + "]"));
        if (x >= 0) lines[x] = ext;
        else lines.Insert(general + 1, ext);

        return string.Join("\r\n", lines) + "\r\n";
    }

    // ── Auxiliares ────────────────────────────────────────────────────

    private static string BareName(string valueName) =>
        valueName.StartsWith(DeletePrefix, StringComparison.OrdinalIgnoreCase) ? valueName[DeletePrefix.Length..] : valueName;

    private static bool SameKey(string a, string b) =>
        string.Equals(NormalizeKey(a), NormalizeKey(b), StringComparison.OrdinalIgnoreCase);

    private static bool SameName(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static void Expect(byte[] b, ref int p, char c)
    {
        if (p + 2 > b.Length || b[p] != (byte)c || b[p + 1] != 0)
            throw new FormatException($"Registry.pol: expected '{c}' at byte {p}");
        p += 2;
    }

    private static string ReadZ(byte[] b, ref int p)
    {
        var start = p;
        while (p + 1 < b.Length && !(b[p] == 0 && b[p + 1] == 0)) p += 2;
        if (p + 1 >= b.Length) throw new FormatException("Registry.pol: unterminated string");
        var s = Encoding.Unicode.GetString(b, start, p - start);
        p += 2;
        return s;
    }

    private static uint ReadU32(byte[] b, ref int p)
    {
        if (p + 4 > b.Length) throw new FormatException("Registry.pol: truncated number");
        var v = BitConverter.ToUInt32(b, p);
        p += 4;
        return v;
    }

    private static void WriteChar(Stream s, char c)
    {
        s.WriteByte((byte)c);
        s.WriteByte(0);
    }
}
