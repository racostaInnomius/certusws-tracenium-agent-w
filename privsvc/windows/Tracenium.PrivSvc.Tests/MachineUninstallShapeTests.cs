using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

namespace Tracenium.PrivSvc.Tests;

/// <summary>
/// Con qué se desinstala una app DE MÁQUINA — y cuándo no se desinstala.
///
/// 🔴 EL CASO DE CAMPO (26-sep, W11-JPR-LAB02). AnyDesk registró
/// <c>"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --uninstall</c> y ningún
/// QuietUninstallString. <c>--uninstall</c> pide confirmación; como la app es
/// de máquina, el desinstalador corre como SYSTEM en la sesión 0 y esa ventana
/// no la ve NADIE. El job estuvo 1740 s colgado, se reintentó cinco veces
/// (~2,5 h de instalador muerto en ese PC) y AnyDesk siguió instalado.
///
/// Estas pruebas existen porque la decisión estaba enterrada en un método
/// async que toca el registro y lanza procesos: no había forma de escribirlas,
/// y por eso nadie vio que el último recurso era ejecutar la cadena desnuda.
/// </summary>
public class MachineUninstallShapeTests
{
    private const string AnyDesk = "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --uninstall";

    [Fact]
    public void SinFormaSilenciosa_SeNiega_NoEjecutaLaCadenaDesnuda()
    {
        var c = MachineUninstallShape.ChooseCommand(AnyDesk, null, null, null);

        Assert.Equal(MachineUninstallShape.NoSilentUninstall, c.ErrorCode);
        // Lo que importa no es sólo el código: es que no quede un comando que
        // alguien pueda ejecutar más abajo.
        Assert.Null(c.Command);
    }

    [Fact]
    public void ElQuietDelRegistroManda()
    {
        var c = MachineUninstallShape.ChooseCommand(AnyDesk, "\"C:\\...\\AnyDesk.exe\" --remove", null, null);

        Assert.Null(c.ErrorCode);
        Assert.Equal("\"C:\\...\\AnyDesk.exe\" --remove", c.Command);
    }

    [Fact]
    public void LoQueResuelveLaTablaOLaSondaTambienVale()
    {
        // WinRAR y la cola larga de NSIS entran por aquí: el llamador ya
        // consultó KnownSilentUninstall y UninstallerProbe.
        var c = MachineUninstallShape.ChooseCommand(
            "C:\\Program Files\\WinRAR\\uninstall.exe", null, "C:\\Program Files\\WinRAR\\uninstall.exe /S", null);

        Assert.Null(c.ErrorCode);
        Assert.Equal("C:\\Program Files\\WinRAR\\uninstall.exe /S", c.Command);
    }

    [Fact]
    public void UnQuietDelRegistroGanaALaSonda()
    {
        // El instalador sabe más de sí mismo que nuestra heurística.
        var c = MachineUninstallShape.ChooseCommand(AnyDesk, "quiet.exe /q", "sonda.exe /S", null);

        Assert.Equal("quiet.exe /q", c.Command);
    }

    [Fact]
    public void LosArgumentosDelOperadorRescatanElCaso()
    {
        // ⚠️ Que una persona haya escrito `/S` en el paquete del catálogo es
        // una afirmación deliberada sobre ESE desinstalador. Negarse ahí sería
        // quitar una capacidad que alguien pidió a mano.
        var c = MachineUninstallShape.ChooseCommand(AnyDesk, null, null, "--remove");

        Assert.Null(c.ErrorCode);
        Assert.Equal(AnyDesk, c.Command);
        Assert.Equal("--remove", c.ExtraArgs);
    }

    [Fact]
    public void PeroLaSondaSePrefiereALosArgumentosDelOperador()
    {
        // Lo que el binario dice de sí mismo hoy pesa más que lo que alguien
        // escribió hace meses en un paquete.
        var c = MachineUninstallShape.ChooseCommand("u.exe", null, "u.exe /S", "/VERYSILENT");

        Assert.Equal("u.exe /S", c.Command);
        Assert.Null(c.ExtraArgs);
    }

    [Fact]
    public void SinCadenaNingunaNoEsUnaNegativaDeSilencio_EsFaltaDeIdENTIDAD()
    {
        // Son dos problemas distintos y mandan al operador a sitios distintos:
        // aquí no sabemos QUÉ quitar; en el otro lo sabemos y no podemos.
        var c = MachineUninstallShape.ChooseCommand(null, null, null, null);

        Assert.Null(c.ErrorCode);
        Assert.Null(c.Command);
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("")]
    public void UnQuietEnBlancoNoCuentaComoSilencioso(string quiet)
    {
        // El registro guarda cadenas vacías con normalidad; tratarlas como
        // comando lanzaría un proceso sin nombre, o peor, dejaría pasar el caso.
        var c = MachineUninstallShape.ChooseCommand(AnyDesk, quiet, null, null);

        Assert.Equal(MachineUninstallShape.NoSilentUninstall, c.ErrorCode);
    }
}
