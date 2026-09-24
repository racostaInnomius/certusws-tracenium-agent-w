// privsvc/windows/Tracenium.PrivSvc.Tests/InstallerKindTests.cs
//
// Reconocer NSIS por la FIRMA del binario.
//
// ⚠️ Por qué no por el nombre: «uninstall.exe» lo usan NSIS, InstallShield y
// cualquiera. En T111, de las 775 filas sin silencioso conocido, 58 son
// `uninstall.exe`, 31 `uninstaller.exe` y 17 `uninst.exe` — mezcladas. Añadir
// `/S` por el nombre abriría una ventana en la mitad: en una desinstalación de
// máquina, en la sesión 0, donde no la ve NADIE y el job se cuelga.

using System.Text;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class InstallerKindTests
{
    /// Un PE de mentira con la cabecera de datos de NSIS donde va: detrás del
    /// ejecutable, precedida de la firma 0xDEADBEEF.
    private static byte[] NsisBinary(int padding = 4096)
    {
        var head = new byte[padding];
        head[0] = (byte)'M'; head[1] = (byte)'Z';
        var sig = new byte[] { 0xEF, 0xBE, 0xAD, 0xDE };
        var marker = Encoding.ASCII.GetBytes("NullsoftInst");
        return head.Concat(sig).Concat(marker).Concat(new byte[64]).ToArray();
    }

    [Fact]
    public void Reconoce_la_cabecera_de_datos_de_NSIS() =>
        Assert.Equal(InstallerKind.Kind.Nsis, InstallerKind.Detect(NsisBinary()));

    [Fact]
    public void Reconoce_tambien_el_nombre_del_recurso_de_version_en_UTF16()
    {
        // Algunos desinstaladores no traen el bloque dentro de los bytes que
        // leemos, pero sí el nombre del producto en el recurso de versión.
        var head = new byte[512];
        head[0] = (byte)'M'; head[1] = (byte)'Z';
        var vi = Encoding.Unicode.GetBytes("Nullsoft Install System v3.09");
        Assert.Equal(InstallerKind.Kind.Nsis, InstallerKind.Detect(head.Concat(vi).ToArray()));
    }

    [Fact]
    public void Un_binario_cualquiera_no_es_NSIS()
    {
        var head = Encoding.ASCII.GetBytes("MZ......InstallShield Setup Launcher......");
        Assert.Equal(InstallerKind.Kind.Unknown, InstallerKind.Detect(head));
    }

    [Fact]
    public void Vacio_o_nulo_es_desconocido()
    {
        Assert.Equal(InstallerKind.Kind.Unknown, InstallerKind.Detect(null));
        Assert.Equal(InstallerKind.Kind.Unknown, InstallerKind.Detect(Array.Empty<byte>()));
    }

    // Una marca partida entre dos lecturas no existe: se busca en UN búfer.
    // Este test fija que la búsqueda no se sale del búfer.
    [Fact]
    public void Una_marca_cortada_al_final_no_casa_ni_revienta()
    {
        var cortado = Encoding.ASCII.GetBytes("MZ....Nullsoft");
        Assert.Equal(InstallerKind.Kind.Unknown, InstallerKind.Detect(cortado));
    }

    [Fact]
    public void NSIS_desinstala_con_S_mayuscula() =>
        Assert.Equal(@"C:\Program Files\VLC\uninstall.exe /S",
            InstallerKind.SilentCommandFor(@"C:\Program Files\VLC\uninstall.exe", InstallerKind.Kind.Nsis));

    [Fact]
    public void Si_ya_trae_S_no_se_repite() =>
        Assert.Equal(@"C:\App\uninst.exe /S",
            InstallerKind.SilentCommandFor(@"C:\App\uninst.exe /S", InstallerKind.Kind.Nsis));

    // ⚠️ `/S` es distinto de `/SILENT` o `/s`: el parser de NSIS distingue
    // mayúsculas, y un `/silent` suelto no lo hace silencioso.
    [Fact]
    public void Un_modificador_parecido_no_cuenta_como_silencioso() =>
        Assert.Equal(@"C:\App\uninst.exe /SILENT /S",
            InstallerKind.SilentCommandFor(@"C:\App\uninst.exe /SILENT", InstallerKind.Kind.Nsis));

    [Fact]
    public void De_lo_desconocido_no_se_inventa_modificador() =>
        Assert.Null(InstallerKind.SilentCommandFor(@"C:\App\uninst.exe", InstallerKind.Kind.Unknown));
}

public class EdgeSilentTests
{
    private const string EDGE = "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\131.0.2903.86\\Installer\\setup.exe\" --uninstall --system-level --verbose-logging";

    // 102 filas de «setup.exe» en T111 son de Edge: el mismo instalador de
    // Chromium, el mismo modificador.
    [Fact]
    public void Edge_gana_force_uninstall() =>
        Assert.Equal(EDGE + " --force-uninstall", KnownSilentUninstall.For(EDGE));

    [Fact]
    public void Si_ya_lo_trae_no_se_repite() =>
        Assert.Equal(EDGE + " --force-uninstall", KnownSilentUninstall.For(EDGE + " --force-uninstall"));
}
