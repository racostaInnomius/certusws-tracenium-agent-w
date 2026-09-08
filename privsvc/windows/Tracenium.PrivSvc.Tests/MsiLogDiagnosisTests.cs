// privsvc/windows/Tracenium.PrivSvc.Tests/MsiLogDiagnosisTests.cs
//
// El extractor que convierte un log de Windows Installer en una linea.
//
// ⚠️ LOS FRAGMENTOS DE ABAJO SON DE UN LOG REAL, no inventados: el que un
// operador capturo con /l*v el 08-sep-2026 en RAV-LAB-HI mientras
// desplegaba Chrome, y que costo una tarde entera de diagnostico sin el.
// Un fixture inventado probaria que el parser entiende el formato que YO
// imagino; lo que tiene que entender es el que msiexec escribe.
//
// Se prueba `Diagnose` (la parte pura) y no `Extract`, para no depender de
// escribir ficheros ni de la codificacion UTF-16 en el test — esa mitad la
// cubre la lectura real en campo.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class MsiLogDiagnosisTests
{
    // Cola literal del log de RAV-LAB-HI. El desenlace de una sesion de MSI
    // esta siempre en las ultimas lineas.
    private const string RealTail =
        "MSI (s) (8C:F0) [22:48:43:494]: Note: 1: 1729 \n" +
        "MSI (s) (8C:F0) [22:48:43:494]: Note: 1: 2205 2:  3: Error \n" +
        "MSI (s) (8C:F0) [22:48:43:494]: Note: 1: 2228 2:  3: Error 4: SELECT `Message` FROM `Error` WHERE `Error` = 1729 \n" +
        "MSI (s) (8C:F0) [22:48:43:494]: Product: Google Chrome -- Configuration failed.\n" +
        "\n" +
        "MSI (s) (8C:F0) [22:48:43:494]: Windows Installer reconfigured the product. Product Name: Google Chrome. Product Version: 152.0.7977.83. Product Language: 1033. Manufacturer: Google LLC. Reconfiguration success or error status: 1603.\n" +
        "\n" +
        "MSI (s) (8C:F0) [22:48:43:505]: MainEngineThread is returning 1603\n";

    [Fact]
    public void Reconoce_la_reconfiguracion_que_costo_la_tarde()
    {
        var d = MsiLogDiagnosis.Diagnose(RealTail);

        Assert.NotNull(d);
        // Lo que importa no es que devuelva "algo": es que diga que el
        // producto YA ESTABA. Un "1603: fatal error" seria tecnicamente
        // cierto y practicamente inutil — es justo el mensaje que no
        // permitia distinguir "fallo" de "ya instalado, no reintentes".
        Assert.Contains("already installed", d!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void El_codigo_interno_gana_al_status_final()
    {
        // 1729 dice POR QUE; 1603 solo dice que si. Si el parser se quedara
        // con el status, perderiamos la unica pista accionable.
        var tail =
            "Note: 1: 1729 \n" +
            "Installation success or error status: 1603.\n";
        var d = MsiLogDiagnosis.Diagnose(tail);
        Assert.StartsWith("1729", d);
    }

    [Fact]
    public void Traduce_los_codigos_conocidos()
    {
        Assert.Contains("already in progress",
            MsiLogDiagnosis.Diagnose("Installation success or error status: 1618.\n")!,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("blocked by system policy",
            MsiLogDiagnosis.Diagnose("Installation success or error status: 1625.\n")!,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("restart",
            MsiLogDiagnosis.Diagnose("Installation success or error status: 3010.\n")!,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Se_queda_con_el_ultimo_desenlace_no_con_el_primero()
    {
        // Una sesion con reintentos internos escribe varios status. El que
        // vale es el ultimo; leer hacia delante se quedaria con el primero y
        // reportaria un fallo intermedio como si fuera el final.
        var tail =
            "Installation success or error status: 1618.\n" +
            "Installation success or error status: 0.\n";
        var d = MsiLogDiagnosis.Diagnose(tail);
        Assert.StartsWith("0", d);
    }

    [Fact]
    public void Un_codigo_desconocido_sale_igual_sin_inventar_significado()
    {
        var d = MsiLogDiagnosis.Diagnose("Installation success or error status: 9999.\n");
        Assert.NotNull(d);
        Assert.Contains("9999", d!);
    }

    [Fact]
    public void Un_log_sin_desenlace_devuelve_null_en_vez_de_adivinar()
    {
        // Media sesion de inventario de tablas y ninguna conclusion. Decir
        // null deja el reason como estaba; inventar una causa seria peor que
        // no tener ninguna.
        var tail =
            "MSI (s) (8C:F0): Note: 1: 2205 2:  3: Control \n" +
            "MSI (s) (8C:F0): Note: 1: 2205 2:  3: ActionText \n";
        Assert.Null(MsiLogDiagnosis.Diagnose(tail));
    }

    [Fact]
    public void No_revienta_con_entrada_vacia()
    {
        Assert.Null(MsiLogDiagnosis.Diagnose(""));
        Assert.Null(MsiLogDiagnosis.Diagnose("\n\n\n"));
    }

    [Fact]
    public void El_detalle_va_acotado()
    {
        // Un log verboso vuelca propiedades con nombre de maquina, usuario y
        // rutas de perfil. Lo que sale de aqui viaja al control plane, asi
        // que la cota no es estetica: es lo que impide convertir un
        // diagnostico en telemetria con PII.
        var largo = new string('x', 600);
        var d = MsiLogDiagnosis.Diagnose($"Product: {largo} -- Installation failed.\n");
        Assert.NotNull(d);
        Assert.True(d!.Length <= 200, $"detalle sin acotar: {d.Length} chars");
    }
}
