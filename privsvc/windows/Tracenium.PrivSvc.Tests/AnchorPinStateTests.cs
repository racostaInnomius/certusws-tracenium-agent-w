// privsvc/windows/Tracenium.PrivSvc.Tests/AnchorPinStateTests.cs
//
// ADR-0011 fase 0, paso 1 — que la observacion SALGA del equipo.
//
// Windows es la plataforma que mas importa aqui: es donde se midio el
// hallazgo original —`rootStore.Add()` sobre `LocalMachine\Root` en la
// ruta de renovacion— y donde una raiz plantada afecta a todo lo que
// haya en el equipo, no solo al agente. Enviar este codigo sin ejecutar
// una sola vez seria repetir el patron que ya costo caro: escribirlo,
// desplegarlo, y descubrir en produccion que no hacia lo que decia.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AnchorPinStateTests : IDisposable
{
    // `AnchorPin` guarda junto al binario (`AppContext.BaseDirectory`),
    // que en un test es el directorio de salida. Se limpia entre casos
    // para que el contador no arrastre valores de otra prueba — que es
    // justo el tipo de falso verde que este fichero existe para evitar.
    private static string StatePath =>
        Path.Combine(AppContext.BaseDirectory, "anchor-pin-last.json");

    public AnchorPinStateTests() => Limpiar();
    public void Dispose() => Limpiar();

    private static void Limpiar()
    {
        try { File.Delete(StatePath); } catch { }
    }

    private static AnchorPinVerdict Veredicto(string[] pinned, string[] incoming, bool enforcing = false)
        => AnchorPin.Evaluate(pinned.ToList(), incoming.ToList(), enforcing);

    [Fact]
    public void Sin_fichero_es_null_que_es_no_ha_evaluado()
    {
        // Distinto de «no vio nada». Confundirlos convertiria una flota
        // sin renovar en una flota «limpia».
        Assert.Null(AnchorPin.LoadState());
    }

    [Fact]
    public void Guarda_el_veredicto_con_su_origen()
    {
        AnchorPin.SaveState(Veredicto(new[] { "aa" }, new[] { "bb" }), "renew");

        var s = AnchorPin.LoadState();
        Assert.NotNull(s);
        Assert.Equal("renew", s!.source);
        Assert.Equal(new List<string> { "bb" }, s.unpinned);
        Assert.False(s.firstRun);
    }

    [Fact]
    public void Estrella_el_contador_solo_crece_aunque_el_detalle_se_pise()
    {
        // El resto del fichero es el ultimo veredicto y se sobrescribe.
        // Si ocurren dos hallazgos entre dos ciclos de facts, del primero
        // solo queda este numero — y el criterio de salida del paso 2
        // («cero anclas no fijadas») seria indemostrable sin el.
        AnchorPin.SaveState(Veredicto(new[] { "aa" }, new[] { "bb" }), "renew");
        AnchorPin.SaveState(Veredicto(new[] { "aa", "bb" }, new[] { "cc" }), "renew");
        Assert.Equal(2, AnchorPin.LoadState()!.unpinnedSeenTotal);

        // Y un veredicto limpio no lo reinicia: que despues fuera bien no
        // borra que antes paso algo.
        AnchorPin.SaveState(Veredicto(new[] { "aa" }, new[] { "aa" }), "renew");
        var s = AnchorPin.LoadState()!;
        Assert.Equal(2, s.unpinnedSeenTotal);
        Assert.Empty(s.unpinned);
    }

    [Fact]
    public void La_primera_vez_no_cuenta_como_hallazgo()
    {
        // `firstRun` establece la linea base y a proposito no acusa a
        // nadie. Si contara, cada enrolamiento de la flota entraria como
        // un ancla sospechosa y el dato del paso 2 naceria inservible.
        AnchorPin.SaveState(Veredicto(Array.Empty<string>(), new[] { "aa", "bb" }), "enroll");
        var s = AnchorPin.LoadState()!;
        Assert.True(s.firstRun);
        Assert.Equal(0, s.unpinnedSeenTotal);
        Assert.Equal("enroll", s.source);
    }

    [Fact]
    public void Un_ancla_RECHAZADA_tambien_se_reporta()
    {
        // En `enforce` el ancla no se instala — y ese es precisamente el
        // evento que hay que poder ver desde el control plane. Reportar
        // solo las aceptadas dejaria invisible el unico caso que importa.
        AnchorPin.SaveState(Veredicto(new[] { "aa" }, new[] { "bb" }, enforcing: true), "renew");
        var s = AnchorPin.LoadState()!;
        Assert.Equal(new List<string> { "bb" }, s.rejected);
        Assert.Equal(1, s.unpinnedSeenTotal);
    }

    [Fact]
    public void Un_fichero_corrupto_no_es_una_alarma()
    {
        // Mismo fallo seguro que los pines: un JSON roto no puede
        // convertirse en un hallazgo para toda la flota.
        File.WriteAllText(StatePath, "{ esto no es json");
        Assert.Null(AnchorPin.LoadState());
    }

    [Fact]
    public void Estrella_el_modo_queda_registrado()
    {
        // Medir el despliegue por anillos del paso 3 exige distinguir un
        // equipo en `enforce` de uno en `observe`. Sin esto, encender el
        // primer anillo seria indistinguible de no haberlo encendido.
        AnchorPin.SaveState(Veredicto(new[] { "aa" }, new[] { "aa" }), "renew");
        Assert.Equal(AnchorPin.IsEnforcing() ? "enforce" : "observe", AnchorPin.LoadState()!.mode);
    }
}
