// privsvc/windows/Tracenium.PrivSvc.Tests/UninstallCommandParseTests.cs
//
// 🔴 CAMPO, T111: TODAS las desinstalaciones de WinRAR fallaron con
// «An error occurred trying to start process 'C:\Program'». La causa no era el
// inventario ni el despliegue: el UninstallString de WinRAR va SIN COMILLAS y
// el parseo cortaba por el primer espacio.
//
// Las líneas de abajo son las REALES del inventario de T111 (24-sep).

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class UninstallCommandParseTests
{
    // Un disco de mentira: existen sólo las rutas que se le declaran.
    private static Func<string, bool> Disk(params string[] paths) =>
        p => paths.Contains(p, StringComparer.OrdinalIgnoreCase);

    private const string WinRar64 = @"C:\Program Files\WinRAR\uninstall.exe";
    private const string WinRar32 = @"C:\Program Files (x86)\WinRAR\uninstall.exe";

    [Fact]
    public void Ruta_sin_comillas_CON_ESPACIOS_no_se_parte_por_el_primer_espacio()
    {
        var (file, args) = UninstallCommandParse.Split(WinRar64, Disk(WinRar64));
        Assert.Equal(WinRar64, file);
        Assert.Empty(args);
    }

    [Fact]
    public void La_de_32_bits_tambien()
    {
        var (file, _) = UninstallCommandParse.Split(WinRar32, Disk(WinRar32));
        Assert.Equal(WinRar32, file);
    }

    [Fact]
    public void Sin_comillas_con_argumentos_detras()
    {
        var (file, args) = UninstallCommandParse.Split($"{WinRar64} /S", Disk(WinRar64));
        Assert.Equal(WinRar64, file);
        Assert.Equal(new[] { "/S" }, args);
    }

    // ⚠️ El corte lo decide el DISCO: la misma línea significa cosas distintas
    // según lo que exista en el equipo.
    [Fact]
    public void Si_existe_el_prefijo_corto_ese_es_el_ejecutable()
    {
        var (file, args) = UninstallCommandParse.Split(@"C:\Program Files\X\u.exe", Disk(@"C:\Program.exe"));
        Assert.Equal(@"C:\Program.exe", file);
        Assert.Equal(new[] { @"Files\X\u.exe" }, args);
    }

    [Fact]
    public void Entrecomillado_manda_el_instalador_no_el_disco()
    {
        var (file, args) = UninstallCommandParse.Split(
            "\"C:\\Users\\ana\\AppData\\Local\\Programs\\RingCentral\\Uninstall RingCentral.exe\" /currentuser /S",
            Disk());
        Assert.Equal(@"C:\Users\ana\AppData\Local\Programs\RingCentral\Uninstall RingCentral.exe", file);
        Assert.Equal(new[] { "/currentuser", "/S" }, args);
    }

    [Fact]
    public void MsiExec_sin_comillas_sigue_funcionando()
    {
        // No existe como fichero suelto (está en el PATH): cae al camino de
        // «ningún corte existe»… salvo que el disco lo resuelva con .exe.
        var (file, args) = UninstallCommandParse.Split(
            "MsiExec.exe /X{D73883EB-7167-37B2-A69C-06A4744F64D2}", Disk("MsiExec.exe"));
        Assert.Equal("MsiExec.exe", file);
        Assert.Equal(new[] { "/X{D73883EB-7167-37B2-A69C-06A4744F64D2}" }, args);
    }

    [Fact]
    public void Un_prefijo_sin_extension_se_prueba_tambien_con_exe()
    {
        var (file, args) = UninstallCommandParse.Split(@"C:\Tools\uninst /quiet", Disk(@"C:\Tools\uninst.exe"));
        Assert.Equal(@"C:\Tools\uninst.exe", file);
        Assert.Equal(new[] { "/quiet" }, args);
    }

    // ⚠️ Si el ejecutable ya no está, el error tiene que nombrar la ruta
    // ENTERA. Un «C:\Program» no le dice nada a nadie — fue exactamente lo que
    // se vio en T111.
    [Fact]
    public void Si_no_existe_nada_devuelve_la_linea_entera_como_ejecutable()
    {
        var (file, args) = UninstallCommandParse.Split(WinRar64, Disk());
        Assert.Equal(WinRar64, file);
        Assert.Empty(args);
    }

    [Fact]
    public void Vacio_no_revienta()
    {
        var (file, args) = UninstallCommandParse.Split("   ", Disk());
        Assert.Equal("", file);
        Assert.Empty(args);
    }

    [Theory]
    [InlineData("/D=\"C:\\Program Files\\X\" /S", new[] { "/D=C:\\Program Files\\X", "/S" })]
    [InlineData("  /S   /norestart ", new[] { "/S", "/norestart" })]
    public void Los_argumentos_respetan_las_comillas(string raw, string[] esperado) =>
        Assert.Equal(esperado, UninstallCommandParse.SplitArgs(raw));
}

public class WinRarSilentTests
{
    private const string WinRar = @"C:\Program Files\WinRAR\uninstall.exe";

    // 🔴 Sin /S, el desinstalador abre ventana. En una desinstalación de
    // MÁQUINA corre como SYSTEM en la sesión 0: no la ve nadie y el job se
    // cuelga hasta agotar el tiempo.
    [Fact]
    public void WinRAR_gana_el_modificador_silencioso() =>
        Assert.Equal(WinRar + " /S", KnownSilentUninstall.For(WinRar));

    [Fact]
    public void Si_ya_lo_trae_no_se_repite() =>
        Assert.Equal(WinRar + " /S", KnownSilentUninstall.For(WinRar + " /S"));

    [Fact]
    public void La_de_32_bits_tambien() =>
        Assert.Equal(@"C:\Program Files (x86)\WinRAR\uninstall.exe /S",
            KnownSilentUninstall.For(@"C:\Program Files (x86)\WinRAR\uninstall.exe"));
}
