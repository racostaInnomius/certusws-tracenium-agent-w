// privsvc/windows/Tracenium.PrivSvc.Tests/GpResultParsingTests.cs
//
// El extractor de GPO aplicadas. El caso que originó estas pruebas se midió en
// producción, no se imaginó: de 20 nombres distintos que llegaban al inventario
// del tenant 111 como "GPO aplicada", sólo 6 lo eran. Los otros venían de la
// sección SIGUIENTE del reporte — los grupos de seguridad — porque el bucle no
// paraba donde debía.

using System.Collections.Generic;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class GpResultParsingTests
{
    /// Un reporte de un equipo que SÍ tiene directivas filtradas. Es la forma
    /// que el codigo anterior manejaba bien.
    private static List<string> ConSeccionFiltrada() => new()
    {
        "COMPUTER SETTINGS",
        "------------------",
        "    CN=DESKTOP-1,OU=Equipos,DC=ejemplo,DC=local",
        "",
        "    Applied Group Policy Objects",
        "    -----------------------------",
        "        Default Domain Policy",
        "        ADC-SecurityFix",
        "",
        "    The following GPOs were not applied because they were filtered out",
        "    -------------------------------------------------------------------",
        "        Local Group Policy",
        "            Filtering:  Not Applied (Empty)",
        "",
        "    The computer is a part of the following security groups",
        "    -------------------------------------------------------",
        "        BUILTIN\\Administrators",
        "        Everyone",
    };

    /// ⚠️ Y uno SIN esa seccion: es el caso que rompia. Eran 3 equipos del
    /// tenant 111 — justo los que no tenian ninguna directiva filtrada.
    private static List<string> SinSeccionFiltrada() => new()
    {
        "COMPUTER SETTINGS",
        "------------------",
        "",
        "    Applied Group Policy Objects",
        "    -----------------------------",
        "        Default Domain Policy",
        "        ADC-WSUS-Service",
        "",
        "    The computer is a part of the following security groups",
        "    -------------------------------------------------------",
        "        BUILTIN\\Administrators",
        "        NT AUTHORITY\\NETWORK",
        "        Everyone",
        "        DESKTOP-M8GJ0V5$",
        "        System Mandatory Level",
    };

    [Fact]
    public void Extrae_solo_las_directivas_cuando_hay_seccion_filtrada()
    {
        var r = GpResultParsing.ExtractAppliedGpoNames(ConSeccionFiltrada());
        Assert.Equal(new[] { "Default Domain Policy", "ADC-SecurityFix" }, r);
    }

    [Fact]
    public void Sin_seccion_filtrada_NO_se_traga_los_grupos_de_seguridad()
    {
        // Este es el bug. Antes devolvia tambien BUILTIN\Administrators,
        // Everyone, la cuenta de maquina y hasta el propio encabezado.
        var r = GpResultParsing.ExtractAppliedGpoNames(SinSeccionFiltrada());
        Assert.Equal(new[] { "Default Domain Policy", "ADC-WSUS-Service" }, r);
    }

    [Fact]
    public void No_devuelve_el_encabezado_de_la_seccion_siguiente()
    {
        // Que el encabezado acabara en la lista es la prueba mas clara de que
        // el bucle no paraba donde debia.
        var r = GpResultParsing.ExtractAppliedGpoNames(SinSeccionFiltrada());
        Assert.DoesNotContain(r, x => x.Contains("security groups"));
    }

    [Fact]
    public void La_parada_es_estructural_y_funciona_en_otro_idioma()
    {
        // ⚠️ El reporte SI se localiza. Una parada por frase en ingles habria
        // funcionado en el laboratorio y fallado en el primer dominio en
        // espanol; el subrayado de guiones es el mismo en todos.
        var r = GpResultParsing.ExtractAppliedGpoNames(new List<string>
        {
            "    Applied Group Policy Objects",
            "    -----------------------------",
            "        Directiva de contrasenas",
            "",
            "    El equipo pertenece a los grupos de seguridad siguientes",
            "    --------------------------------------------------------",
            "        INTEGRADO\\Administradores",
            "        Todos",
        });
        Assert.Equal(new[] { "Directiva de contrasenas" }, r);
    }

    [Fact]
    public void Ignora_los_N_A_y_los_repetidos()
    {
        var r = GpResultParsing.ExtractAppliedGpoNames(new List<string>
        {
            "    Applied Group Policy Objects",
            "    -----------------------------",
            "        N/A",
            "        Default Domain Policy",
            "        default domain policy",
            "",
            "    Otra seccion",
            "    ------------",
        });
        Assert.Equal(new[] { "Default Domain Policy" }, r);
    }

    [Fact]
    public void Sin_la_seccion_de_aplicadas_no_inventa_nada()
    {
        var r = GpResultParsing.ExtractAppliedGpoNames(new List<string>
        {
            "INFO: The user does not have RSOP data.",
        });
        Assert.Empty(r);
    }

    [Fact]
    public void Aguanta_entradas_degeneradas()
    {
        Assert.Empty(GpResultParsing.ExtractAppliedGpoNames(null));
        Assert.Empty(GpResultParsing.ExtractAppliedGpoNames(new List<string>()));
        Assert.Empty(GpResultParsing.ExtractAppliedGpoNames(new List<string> { null!, "", "   " }));
    }

    [Fact]
    public void La_lista_termina_en_el_final_del_reporte_sin_mas_secciones()
    {
        // Sin ninguna seccion despues, se leen todas las directivas y ya.
        var r = GpResultParsing.ExtractAppliedGpoNames(new List<string>
        {
            "    Applied Group Policy Objects",
            "    -----------------------------",
            "        Default Domain Policy",
            "        ADS-WSUS",
        });
        Assert.Equal(new[] { "Default Domain Policy", "ADS-WSUS" }, r);
    }
}
