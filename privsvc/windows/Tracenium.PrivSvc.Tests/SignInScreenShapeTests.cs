// privsvc/windows/Tracenium.PrivSvc.Tests/SignInScreenShapeTests.cs
//
// Entrar a un servidor por su pantalla de Windows — la parte pura. Lo que se
// fija: la directiva de Ctrl+Alt+Supr sólo se pone si NO estaba configurada
// (una GPO explícita no se pelea); sólo el flag 0 es «bloqueada»; al salir se
// bloquea sólo si se entró por la pantalla y hay alguien dentro; el texto va
// como caracteres y no como teclas físicas; y WTSINFOEX se lee del byte que
// toca.

using System.Runtime.InteropServices;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class SignInScreenShapeTests
{
    // ── Ctrl+Alt+Supr ───────────────────────────────────────────────

    [Fact]
    public void Directiva_no_configurada_se_pone_y_se_manda()
    {
        // Decisión del usuario, 29-sep-2026: en un servidor clasificado la
        // ponemos nosotros. Autoriza a SERVICIOS, que ya corren como SYSTEM.
        Assert.Equal(SasPolicyAction.ConfigureThenSend, SignInScreenShape.DecideSasPolicy(null));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void Directiva_que_ya_permite_servicios_se_manda_sin_tocar(int v) =>
        Assert.Equal(SasPolicyAction.Send, SignInScreenShape.DecideSasPolicy(v));

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(7)]
    public void Directiva_explicita_sin_servicios_NO_se_pisa(int v)
    {
        // Alguien lo decidió —casi siempre una GPO, que además la reescribe en
        // el siguiente refresco—. Pisarla sería quitarle al cliente una
        // decisión suya, y encima no duraría.
        Assert.Equal(SasPolicyAction.RefuseExplicit, SignInScreenShape.DecideSasPolicy(v));
    }

    // ── Consola bloqueada ───────────────────────────────────────────

    [Fact]
    public void Solo_el_cero_es_bloqueada()
    {
        Assert.True(SignInScreenShape.IsLocked(0));
        Assert.False(SignInScreenShape.IsLocked(1));
        // WTS_SESSIONSTATE_UNKNOWN: ante la duda NO se toma la pantalla de
        // bloqueo de nadie.
        Assert.False(SignInScreenShape.IsLocked(-1));
    }

    // ── Bloquear al salir ───────────────────────────────────────────

    [Fact]
    public void Se_bloquea_si_se_entro_por_la_pantalla_y_queda_sesion_abierta() =>
        Assert.True(SignInScreenShape.ShouldLockOnEnd(sawSignInScreen: true, consoleHasUser: true, consoleLocked: false));

    [Fact]
    public void No_se_bloquea_la_sesion_de_quien_ya_estaba_trabajando()
    {
        // Soporte normal en un equipo con alguien dentro: no se pasó por
        // ninguna pantalla de Windows, y bloquearle al terminar sería echarle.
        Assert.False(SignInScreenShape.ShouldLockOnEnd(sawSignInScreen: false, consoleHasUser: true, consoleLocked: false));
    }

    [Fact]
    public void Nada_que_bloquear_si_nunca_se_llego_a_entrar_o_ya_esta_bloqueada()
    {
        Assert.False(SignInScreenShape.ShouldLockOnEnd(sawSignInScreen: true, consoleHasUser: false, consoleLocked: false));
        Assert.False(SignInScreenShape.ShouldLockOnEnd(sawSignInScreen: true, consoleHasUser: true, consoleLocked: true));
    }

    // ── Escribir texto ──────────────────────────────────────────────

    [Fact]
    public void La_arroba_va_como_caracter_no_como_Alt_2()
    {
        // 🔴 El motivo de todo esto: desde un Mac con teclado español `@` es
        // Option+2, y por teclas físicas al servidor le llegaba Alt+2.
        var (units, error) = SignInScreenShape.PlanTypeText("admin@corp.local");
        Assert.Null(error);
        Assert.All(units!, u => Assert.True(u.IsUnicode));
        Assert.Equal("admin@corp.local", new string(units!.Select(u => u.Char).ToArray()));
    }

    [Fact]
    public void Tab_y_Enter_van_como_teclas_y_CRLF_es_un_solo_Enter()
    {
        var (units, _) = SignInScreenShape.PlanTypeText("usr\tpw\r\n");
        Assert.Equal(new ushort[] { 0, 0, 0, 0x09, 0, 0, 0x0D }, units!.Select(u => u.Vk).ToArray());
    }

    [Fact]
    public void Los_pares_suplentes_viajan_enteros()
    {
        var (units, _) = SignInScreenShape.PlanTypeText("a😀");
        Assert.Equal(3, units!.Count); // 'a' + dos unidades UTF-16
        Assert.True(char.IsHighSurrogate(units[1].Char));
        Assert.True(char.IsLowSurrogate(units[2].Char));
    }

    [Fact]
    public void Nada_vacio_ni_desmesurado_ni_invisible()
    {
        Assert.NotNull(SignInScreenShape.PlanTypeText("").error);
        Assert.NotNull(SignInScreenShape.PlanTypeText(null).error);
        Assert.NotNull(SignInScreenShape.PlanTypeText(new string('x', SignInScreenShape.TypeTextMaxChars + 1)).error);
        Assert.Null(SignInScreenShape.PlanTypeText(new string('x', SignInScreenShape.TypeTextMaxChars)).error);
        // Un carácter de control suelto no se manda como «carácter».
        Assert.NotNull(SignInScreenShape.PlanTypeText("\u0007").error);
    }

    // ── WTSINFOEX ───────────────────────────────────────────────────

    [Fact]
    public void SessionFlags_se_lee_del_byte_16()
    {
        // ⚠️ La unión de nivel 1 lleva LARGE_INTEGER y se alinea a 8: `Data`
        // empieza en el 8, no en el 4. Si alguien trunca la estructura
        // después de SessionFlags, la alineación cambia y se lee el campo de
        // al lado — y ese campo decide si se toma una pantalla de bloqueo.
        var data = (int)Marshal.OffsetOf<WtsInfoEx>(nameof(WtsInfoEx.Data));
        var flags = (int)Marshal.OffsetOf<WtsInfoExLevel1>(nameof(WtsInfoExLevel1.SessionFlags));
        Assert.Equal(8, data);
        Assert.Equal(16, data + flags);
    }
}
