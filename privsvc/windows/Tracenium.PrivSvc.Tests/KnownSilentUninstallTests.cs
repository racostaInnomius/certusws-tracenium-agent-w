using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

namespace Tracenium.PrivSvc.Tests;

/// <summary>
/// La tabla de desinstaladores silenciosos documentados.
///
/// ⚠️ ES UN GEMELO del `known-silent-uninstall.ts` del backend, que aplica la
/// misma regla en la vista previa. Si divergen, el portal enseña un comando y
/// el equipo ejecuta otro — o el portal bloquea una fila que el equipo sabría
/// quitar. Las líneas de abajo son las MISMAS que usan los tests del otro lado.
/// </summary>
public class KnownSilentUninstallTests
{
    // ── AnyDesk — el caso de campo del 26-sep (W11-JPR-LAB02) ───────
    //
    // 🔴 UninstallString REAL leída del equipo. Tiene comillas y tiene un
    // verbo… que abre una ventana: el fabricante documenta `--uninstall` como
    // «opens a user interface to guide the uninstallation process». Como
    // SYSTEM esa ventana sale en la sesión 0, no la ve nadie, y el job se
    // colgó 1740 s en cada uno de sus cinco intentos sin quitar nada.

    private const string AnyDesk = "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --uninstall";
    private const string AnyDeskSilent = "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --silent --remove";

    [Fact]
    public void AnyDesk_SustituyeElVerbo_NoAnadeUnModificador()
    {
        // A WinRAR y Chrome se les AÑADE un modificador a lo que ya hay. Aquí
        // `--uninstall` es justo la parte mala: dejarlo y añadir `--silent`
        // seguiría abriendo la ventana.
        var outp = KnownSilentUninstall.For(AnyDesk);

        Assert.Equal(AnyDeskSilent, outp);
        Assert.DoesNotContain("--uninstall", outp);
    }

    [Fact]
    public void AnyDesk_ConservaLaRutaEntreComillas()
    {
        // La leccion de WinRAR: partir mal una ruta con espacios deja
        // «C:\Program», y el proceso no arranca.
        Assert.Contains("\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\"", KnownSilentUninstall.For(AnyDesk));
    }

    [Fact]
    public void AnyDesk_EsIdempotente()
    {
        // Se reconstruye desde cero justamente para esto; concatenar daria
        // `--silent --remove --silent --remove`.
        Assert.Equal(AnyDeskSilent, KnownSilentUninstall.For(AnyDeskSilent));
    }

    [Fact]
    public void AnyDesk_ConRemoveYaPuesto_SeNormaliza()
    {
        var conRemove = "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --remove";

        Assert.Equal(AnyDeskSilent, KnownSilentUninstall.For(conRemove));
    }

    [Fact]
    public void AnyDesk_SinOrdenDeQuitar_NoSeReclama()
    {
        // ⚠️ `AnyDesk.exe` tambien arranca la aplicacion. Convertir cualquier
        // linea suya en un `--remove` seria desinstalar por parecido.
        Assert.Null(KnownSilentUninstall.For("\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --start-with-win"));
    }

    [Fact]
    public void LoQueNoEstaEnLaTabla_SigueSiendoNull()
    {
        // La tabla es SOLO lo documentado: lo que no reconoce lo bloquea la
        // guarda de MachineUninstallShape, no se ejecuta a la aventura.
        Assert.Null(KnownSilentUninstall.For("\"C:\\Vendor\\Otra.exe\" --uninstall"));
        Assert.Null(KnownSilentUninstall.For(null));
        Assert.Null(KnownSilentUninstall.For("   "));
    }

    // ── Los que ya estaban: no se rompen ────────────────────────────

    [Fact]
    public void WinRar_GanaSuModificadorSilencioso()
    {
        const string winrar = "C:\\Program Files\\WinRAR\\uninstall.exe";

        Assert.Equal(winrar + " /S", KnownSilentUninstall.For(winrar));
        Assert.Equal(winrar + " /S", KnownSilentUninstall.For(winrar + " /S"));
    }

    [Fact]
    public void Chrome_GanaForceUninstall()
    {
        const string chrome =
            "\"C:\\Users\\ana\\AppData\\Local\\Google\\Chrome\\Application\\152.0.7977.82\\Installer\\setup.exe\" --uninstall";

        Assert.Equal(chrome + " --force-uninstall", KnownSilentUninstall.For(chrome));
    }
}
