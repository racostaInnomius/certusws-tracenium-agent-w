// privsvc/windows/Tracenium.PrivSvc.Tests/FactsChunkAssemblerTests.cs
//
// Reensamblar lo que el control plane acepta (16 MiB) y rechazar con su
// propio código lo que no. TNS-OPER-SNOC04 (Server 2022), 28-sep-2026: un
// compliance de 17 trozos de ~32 KiB pasaba del tope viejo de 512 KiB y el
// agente lo reenvió en bucle cuatro días. Ver FactsChunkAssembler.cs.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class FactsChunkAssemblerTests
{
    private static readonly DateTime T0 = new(2026, 10, 2, 12, 0, 0, DateTimeKind.Utc);

    // Los trozos del agente: 32 KiB de la cadena (grpc-client.ts FACTS_CHUNK_SIZE).
    private static List<string> Trocear(string s, int size = 32 * 1024)
    {
        var out_ = new List<string>();
        for (var i = 0; i < s.Length; i += size)
            out_.Add(s.Substring(i, Math.Min(size, s.Length - i)));
        return out_;
    }

    private static (FactsChunkAssembler.Result last, int sent) Send(FactsChunkAssembler a, string eventId, string payload)
    {
        var chunks = Trocear(payload);
        FactsChunkAssembler.Result r = new(FactsChunkAssembler.Outcome.Pending);
        for (var i = 0; i < chunks.Count; i++)
        {
            r = a.Add(eventId, i, chunks.Count, chunks[i], "multi", new List<string> { "scp" }, T0);
            if (r.Outcome != FactsChunkAssembler.Outcome.Pending) return (r, i + 1);
        }
        return (r, chunks.Count);
    }

    [Fact]
    public void Un_compliance_como_el_de_SNOC04_se_reensambla_entero()
    {
        var a = new FactsChunkAssembler();
        var payload = new string('a', 17 * 32_933);

        var (r, _) = Send(a, "device-1:756", payload);

        Assert.Equal(FactsChunkAssembler.Outcome.Complete, r.Outcome);
        Assert.Equal(payload, r.Payload);
        Assert.Equal("multi", r.Namespace);
        Assert.Equal(new[] { "scp" }, r.Namespaces);
        Assert.Equal(0, a.PendingCount);
    }

    [Fact]
    public void Justo_en_el_tope_se_acepta()
    {
        var a = new FactsChunkAssembler();
        var (r, _) = Send(a, "device-1:1", new string('a', (int)FactsChunkAssembler.MaxPayloadBytes));
        Assert.Equal(FactsChunkAssembler.Outcome.Complete, r.Outcome);
    }

    [Fact]
    public void Un_byte_mas_del_tope_se_rechaza_con_su_codigo_y_libera_el_buffer()
    {
        var a = new FactsChunkAssembler();
        var (r, _) = Send(a, "device-1:2", new string('a', (int)FactsChunkAssembler.MaxPayloadBytes + 1));

        Assert.Equal(FactsChunkAssembler.Outcome.TooLarge, r.Outcome);
        Assert.Equal("facts_too_large", FactsChunkAssembler.TooLargeCode);
        Assert.Contains("exceeds", r.Reason);
        Assert.Equal(0, a.PendingCount);
    }

    [Fact]
    public void Cuenta_bytes_UTF8_no_caracteres_y_corta_en_cuanto_pasa()
    {
        // 9 M de «é» son 9 M de caracteres pero 18 MiB en UTF-8.
        var a = new FactsChunkAssembler();
        var payload = new string('é', 9 * 1024 * 1024);
        var total = Trocear(payload).Count;

        var (r, sent) = Send(a, "device-1:3", payload);

        Assert.Equal(FactsChunkAssembler.Outcome.TooLarge, r.Outcome);
        Assert.True(sent < total, $"cortó en el trozo {sent} de {total}");
    }

    [Fact]
    public void Demasiados_trozos_anunciados_se_rechazan_sin_guardar_nada()
    {
        var a = new FactsChunkAssembler();
        var r = a.Add("device-1:4", 0, 10_000_000, "x", null, new List<string>(), T0);
        Assert.Equal(FactsChunkAssembler.Outcome.TooLarge, r.Outcome);
        Assert.Equal(0, a.PendingCount);
    }

    [Fact]
    public void Fuera_de_orden_y_con_repetidos_reensambla_igual()
    {
        var a = new FactsChunkAssembler();
        var ns = new List<string> { "cdp" };

        Assert.Equal(FactsChunkAssembler.Outcome.Pending, a.Add("e", 2, 3, "C", "cdp", ns, T0).Outcome);
        Assert.Equal(FactsChunkAssembler.Outcome.Pending, a.Add("e", 0, 3, "A", "cdp", ns, T0).Outcome);
        var dup = a.Add("e", 0, 3, "Z", "cdp", ns, T0);
        Assert.True(dup.Duplicate);
        var r = a.Add("e", 1, 3, "B", "cdp", ns, T0);

        Assert.Equal(FactsChunkAssembler.Outcome.Complete, r.Outcome);
        Assert.Equal("ABC", r.Payload);
    }

    [Fact]
    public void Parametros_invalidos_son_error_del_llamador_no_tamano()
    {
        var a = new FactsChunkAssembler();
        Assert.Throws<ArgumentException>(() => a.Add("e", 5, 2, "x", null, new List<string>(), T0));
        Assert.Throws<ArgumentException>(() => a.Add("e", 0, 0, "x", null, new List<string>(), T0));
        a.Add("f", 0, 2, "x", null, new List<string>(), T0);
        Assert.Throws<ArgumentException>(() => a.Add("f", 1, 3, "y", null, new List<string>(), T0));
    }

    [Fact]
    public void Un_envio_abandonado_se_barre_a_los_dos_minutos()
    {
        var a = new FactsChunkAssembler();
        a.Add("viejo", 0, 2, "x", null, new List<string>(), T0);

        Assert.Empty(a.SweepStale(T0.AddMinutes(1)));
        Assert.Equal(new[] { "viejo" }, a.SweepStale(T0.AddMinutes(3)));
        Assert.Equal(0, a.PendingCount);
    }
}
