// privsvc/windows/Tracenium.PrivSvc.Tests/UserUninstallShapeTests.cs
//
// ADR-0019 paso 3 — desinstalar lo que un usuario instaló en SU perfil.
//
// Las dos decisiones que se equivocan sin dar error: qué comando se ejecuta
// (sólo uno silencioso: con ventana, se le abre un diálogo al usuario que no
// pidió) y cómo se resume un equipo con varios perfiles.
//
// Los comandos de abajo son los REALES del inventario de T111 (21-sep).

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;
using static Tracenium.PrivSvc.Windows.Ipc.UserUninstallShape;

public class UserUninstallShapeTests
{
    private static UserEntry Entry(string? quiet = null, string? plain = null, string key = "RingCentral", bool msi = false) =>
        new("S-1-5-21-1-2-3-1001", key, "RingCentral", plain, quiet, msi);

    // ── Qué comando ─────────────────────────────────────────────────────

    [Fact]
    public void Usa_la_linea_silenciosa_ENTERA_tal_cual_la_registro_el_instalador()
    {
        // Ruta con espacios y comillas: partirla y volver a unirla es donde se
        // rompen. Se pasa entera a CreateProcessAsUser.
        const string quiet = "\"C:\\Users\\vanessad\\AppData\\Local\\Programs\\RingCentral\\Uninstall RingCentral.exe\" /currentuser /S";
        var c = ChooseCommand(Entry(quiet: quiet, plain: "\"C:\\...\\Uninstall RingCentral.exe\" /currentuser"));
        Assert.Equal(quiet, c.CommandLine);
        Assert.Null(c.Refusal);
    }

    [Fact]
    public void Sin_linea_silenciosa_se_niega_aunque_haya_una_normal()
    {
        // GoToMeeting per-user registra sólo «G2MUninstall.exe /uninstall», sin
        // forma silenciosa documentada. Como el usuario, le saldría en su
        // escritorio. (Zoom era el ejemplo antes de la tabla de fabricantes.)
        var c = ChooseCommand(Entry(plain: "\"C:\\Users\\berthac\\AppData\\Local\\GoToMeeting\\19992\\G2MUninstall.exe\" /uninstall"));
        Assert.Null(c.CommandLine);
        Assert.Equal(NoSilentUninstall, c.Refusal);
    }

    [Fact]
    public void Un_MSI_por_usuario_tiene_forma_silenciosa_con_su_ProductCode()
    {
        var c = ChooseCommand(Entry(key: "{E5D37376-9D50-4461-B4DE-F3A72A4E82B5}", msi: true, plain: "MsiExec.exe /X{E5D37376-9D50-4461-B4DE-F3A72A4E82B5}"));
        Assert.Equal("msiexec.exe /x {E5D37376-9D50-4461-B4DE-F3A72A4E82B5} /qn /norestart", c.CommandLine);
    }

    [Fact]
    public void Marcado_como_MSI_pero_sin_ProductCode_en_la_clave_no_se_inventa_uno()
    {
        // `msiexec /x` con basura no falla ruidosamente: quita otra cosa o nada.
        var c = ChooseCommand(Entry(key: "OneDriveSetup.exe", msi: true, plain: "x"));
        Assert.Equal(NoSilentUninstall, c.Refusal);
    }

    [Fact]
    public void Una_linea_silenciosa_en_blanco_no_cuenta_como_silenciosa()
    {
        Assert.Equal(NoSilentUninstall, ChooseCommand(Entry(quiet: "   ", plain: "x")).Refusal);
    }

    // ── Código de salida ────────────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(3010)]
    [InlineData(1641)]
    public void Cero_y_los_de_reinicio_son_quitado(int code) =>
        Assert.Equal(ProfileStatus.Removed, ClassifyExit(code));

    [Theory]
    [InlineData(1)]
    [InlineData(1603)]
    [InlineData(-1)]
    public void Lo_demas_es_fallo(int code) =>
        Assert.Equal(ProfileStatus.Failed, ClassifyExit(code));

    // ── Varios perfiles, un veredicto ───────────────────────────────────

    [Fact]
    public void Todos_quitados_es_exito()
    {
        var o = Aggregate(new[] { new ProfileResult("T111\\ana", ProfileStatus.Removed, 0) });
        Assert.Null(o.ErrorCode);
        Assert.Equal(0, o.ExitCode);
        Assert.Contains("T111\\ana: removed", o.Summary);
    }

    [Fact]
    public void Un_reinicio_pendiente_no_se_pierde_al_resumir()
    {
        var o = Aggregate(new[]
        {
            new ProfileResult("a", ProfileStatus.Removed, 0),
            new ProfileResult("b", ProfileStatus.Removed, 3010),
        });
        Assert.Equal(3010, o.ExitCode);
    }

    [Fact]
    public void Un_fallo_real_manda_sobre_un_perfil_sin_sesion()
    {
        // Lo que falló es un fallo; el perfil sin sesión detrás no lo tapa.
        var o = Aggregate(new[]
        {
            new ProfileResult("a", ProfileStatus.NotLoggedOn, null),
            new ProfileResult("b", ProfileStatus.Failed, 1603),
        });
        Assert.Null(o.ErrorCode);
        Assert.Equal(1603, o.ExitCode);
    }

    [Fact]
    public void Sin_sesion_es_una_negativa_y_dice_en_que_perfil_si_se_quito()
    {
        // Zoom estaba en dos perfiles de un equipo de T111. Si uno no tiene
        // sesión, el operador tiene que saber que en el otro SÍ se quitó.
        var o = Aggregate(new[]
        {
            new ProfileResult("T111\\ana", ProfileStatus.Removed, 0),
            new ProfileResult("T111\\luis", ProfileStatus.NotLoggedOn, null),
        });
        Assert.Equal(UserNotLoggedOn, o.ErrorCode);
        Assert.Contains("T111\\ana: removed", o.Summary);
        Assert.Contains("T111\\luis: not signed in", o.Summary);
    }

    [Fact]
    public void Sin_silencioso_pesa_mas_que_sin_sesion()
    {
        // Sin silencioso no se arregla esperando a que el usuario entre; es la
        // causa que hay que contar primero.
        var o = Aggregate(new[]
        {
            new ProfileResult("a", ProfileStatus.NotLoggedOn, null),
            new ProfileResult("b", ProfileStatus.NoSilentUninstall, null),
        });
        Assert.Equal(NoSilentUninstall, o.ErrorCode);
    }

    [Fact]
    public void Sin_entradas_es_exito_y_lo_confirma_el_post_detect()
    {
        // El pre-detect dijo que estaba: si ya no, se fue entre medias.
        var o = Aggregate(Array.Empty<ProfileResult>());
        Assert.Null(o.ErrorCode);
        Assert.Equal(0, o.ExitCode);
    }
}

public class KnownSilentUninstallTests
{
    // Líneas REALES del inventario de T111 (22-sep). El gemelo del backend
    // (known-silent-uninstall.test.ts) usa exactamente las mismas: si las dos
    // tablas divergen, uno de los dos lados cae.
    private const string OneDrive = "\"C:\\Users\\trustonepc\\AppData\\Local\\Microsoft\\OneDrive\\26.163.0823.0004\\OneDriveSetup.exe\"  /uninstall ";
    private const string Zoom = "\"C:\\Users\\warehouse\\AppData\\Roaming\\Zoom\\uninstall\\Installer.exe\" /uninstall";
    private const string Chrome = "\"C:\\Users\\santiagof\\AppData\\Local\\Google\\Chrome\\Application\\153.0.8010.50\\Installer\\setup.exe\" --uninstall --channel=stable --verbose-logging";

    [Fact]
    public void OneDrive_desinstala_en_silencio_tal_cual() =>
        Assert.Equal(OneDrive.Trim(), KnownSilentUninstall.For(OneDrive));

    [Fact]
    public void Zoom_desinstala_en_silencio_tal_cual() =>
        Assert.Equal(Zoom, KnownSilentUninstall.For(Zoom));

    [Fact]
    public void Chrome_por_usuario_gana_force_uninstall_para_no_preguntar() =>
        Assert.Equal(Chrome + " --force-uninstall", KnownSilentUninstall.For(Chrome));

    [Fact]
    public void Chrome_que_ya_lo_trae_no_lo_repite()
    {
        var ya = Chrome + " --force-uninstall";
        Assert.Equal(ya, KnownSilentUninstall.For(ya));
    }

    [Theory]
    // Sin parámetro documentado: añadir /S a ciegas abriría una ventana al usuario.
    [InlineData("\"C:\\Users\\berthac\\AppData\\Local\\GoToMeeting\\19992\\G2MUninstall.exe\" /uninstall")]
    [InlineData("C:\\Users\\santiagof\\AppData\\Local\\CapCut\\Apps\\uninst.exe")]
    [InlineData("\"C:\\Users\\daniela\\AppData\\Local\\Programs\\Cisco Spark\\WebexUninstaller.exe\" /uninstall")]
    // Una PWA de Chrome NO es el instalador de Chrome aunque diga «uninstall».
    [InlineData("\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" --profile-directory=Default --uninstall-app-id=mpnpojknpmm")]
    // OneDrive sin el verbo es instalar, no desinstalar.
    [InlineData("\"C:\\Users\\x\\AppData\\Local\\Microsoft\\OneDrive\\26.1\\OneDriveSetup.exe\"")]
    [InlineData("")]
    [InlineData(null)]
    public void Lo_que_no_esta_documentado_sigue_sin_forma_silenciosa(string? cmd) =>
        Assert.Null(KnownSilentUninstall.For(cmd));

    [Fact]
    public void ChooseCommand_usa_la_tabla_cuando_no_hay_QuietUninstallString()
    {
        var e = new UserUninstallShape.UserEntry("S-1-5-21-1-2-3-1001", "ZoomUMX", "Zoom Workplace", Zoom, null, false);
        Assert.Equal(Zoom, UserUninstallShape.ChooseCommand(e).CommandLine);
    }

    [Fact]
    public void Con_QuietUninstallString_manda_la_del_instalador_no_la_tabla()
    {
        var e = new UserUninstallShape.UserEntry("S-1-5-21-1-2-3-1001", "ZoomUMX", "Zoom", Zoom, "\"C:\\z.exe\" /quiet", false);
        Assert.Equal("\"C:\\z.exe\" /quiet", UserUninstallShape.ChooseCommand(e).CommandLine);
    }
}
