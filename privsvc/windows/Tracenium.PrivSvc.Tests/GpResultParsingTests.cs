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
// ---------------------------------------------------------------------------
// El lector de `gpresult /X` (XML de RSOP)
//
// ⚠️ Los fixtures reproducen la ESTRUCTURA de dos informes reales de campo
// (04-sep, tenant 111) con los nombres cambiados. La estructura es el objeto
// bajo prueba —los dos espacios de nombres, la GPO no resuelta que llega como
// GUID, la directiva local con los contadores en cero, y los <GPO> anidados
// dentro de <ExtensionData>— y se conserva al detalle. Lo que NO se conserva
// es el contenido: un informe de RSOP lleva el usuario que inició sesión, sus
// SIDs, sus grupos y la ruta de la OU de un cliente real, y eso no entra en
// un repositorio.
// ---------------------------------------------------------------------------
public class RsopXmlTests
{
    private const string EQUIPO_CON_TRES = """
        <?xml version="1.0" encoding="utf-16"?>
        <Rsop xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
          <ReadTime>2026-09-05T15:18:45Z</ReadTime>
          <ComputerResults>
            <Name>EJEMPLO\EQUIPO-1$</Name>
            <GPO>
              <Name>Local Group Policy</Name>
              <VersionDirectory>0</VersionDirectory>
              <VersionSysvol>0</VersionSysvol>
              <Enabled>true</Enabled>
              <IsValid>true</IsValid>
              <FilterAllowed>true</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
            <GPO>
              <Name>ADS-WSUS</Name>
              <VersionDirectory>4</VersionDirectory>
              <VersionSysvol>4</VersionSysvol>
              <Enabled>true</Enabled>
              <IsValid>true</IsValid>
              <FilterAllowed>true</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
            <GPO>
              <Name>ADC-SecurityFix</Name>
              <VersionDirectory>14</VersionDirectory>
              <VersionSysvol>14</VersionSysvol>
              <Enabled>true</Enabled>
              <IsValid>true</IsValid>
              <FilterAllowed>true</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
            <GPO>
              <Name>Default Domain Policy</Name>
              <VersionDirectory>25</VersionDirectory>
              <VersionSysvol>25</VersionSysvol>
              <Enabled>true</Enabled>
              <IsValid>true</IsValid>
              <FilterAllowed>true</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
            <ExtensionData>
              <Extension>
                <RegistryRsopSetting>
                  <GPO>
                    <Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{AAAAAAAA-0000-0000-0000-000000000001}</Identifier>
                  </GPO>
                </RegistryRsopSetting>
                <Account>
                  <GPO>
                    <Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{AAAAAAAA-0000-0000-0000-000000000002}</Identifier>
                  </GPO>
                </Account>
              </Extension>
            </ExtensionData>
          </ComputerResults>
        </Rsop>
        """;

    // El informe de usuario: sólo <UserResults>, la GPO sin resolver como GUID
    // y la directiva local vacía. Es el fichero de campo del equipo que el
    // portal mostraba sin ninguna directiva.
    private const string USUARIO_EN_ESPANOL = """
        <?xml version="1.0" encoding="utf-16"?>
        <Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
          <UserResults>
            <Name>EJEMPLO\usuario</Name>
            <GPO>
              <Name>{31B2F340-016D-11D2-945F-00C04FB984F9}</Name>
              <VersionDirectory>0</VersionDirectory>
              <VersionSysvol>0</VersionSysvol>
              <IsValid>false</IsValid>
              <FilterAllowed>false</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
            <GPO>
              <Name>Directiva de grupo local</Name>
              <VersionDirectory>0</VersionDirectory>
              <VersionSysvol>0</VersionSysvol>
              <Enabled>true</Enabled>
              <IsValid>true</IsValid>
              <FilterAllowed>true</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
            <GPO>
              <Name>Mapeo de unidades</Name>
              <VersionDirectory>7</VersionDirectory>
              <VersionSysvol>7</VersionSysvol>
              <Enabled>true</Enabled>
              <IsValid>true</IsValid>
              <FilterAllowed>true</FilterAllowed>
              <AccessDenied>false</AccessDenied>
            </GPO>
          </UserResults>
        </Rsop>
        """;

    [Fact]
    public void Lee_las_directivas_de_equipo_de_un_informe_real()
    {
        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(EQUIPO_CON_TRES, GpResultParsing.RsopScope.Computer);

        // Las mismas tres que `gpresult /R` lista como aplicadas en ese equipo.
        Assert.Equal(new[] { "ADS-WSUS", "ADC-SecurityFix", "Default Domain Policy" }, r);
    }

    [Fact]
    public void No_recoge_los_GPO_enterrados_en_ExtensionData()
    {
        // En el informe real había 4 GPO de verdad y 30 elementos <GPO> dentro
        // de <ExtensionData>: referencias de cada ajuste a quien lo puso. Un
        // barrido `//GPO` los tomaría por directivas aplicadas.
        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(EQUIPO_CON_TRES, GpResultParsing.RsopScope.Computer)!;

        Assert.DoesNotContain(r, n => n.StartsWith("{AAAAAAAA", StringComparison.Ordinal));
        Assert.Equal(3, r.Count);
    }

    [Fact]
    public void Una_GPO_enlazada_pero_vacia_no_esta_aplicada()
    {
        // "Local Group Policy" pasa los tres booleanos y aun así gpresult la
        // manda a la lista de filtradas: "No aplicado (vacío)". Lo que la
        // delata son los dos contadores de versión en cero.
        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(EQUIPO_CON_TRES, GpResultParsing.RsopScope.Computer)!;

        Assert.DoesNotContain("Local Group Policy", r);
    }

    [Fact]
    public void El_idioma_del_informe_da_igual()
    {
        // ⚠️ La razón de todo esto. El lector de texto buscaba el encabezado
        // "Applied Group Policy Objects" y en un Windows en español no existe:
        // devolvía lista vacía, y un equipo con tres directivas aplicadas
        // llevaba meses contándose como equipo sin ninguna. En el XML los
        // nombres de elemento no se traducen.
        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(USUARIO_EN_ESPANOL, GpResultParsing.RsopScope.User);

        Assert.Equal(new[] { "Mapeo de unidades" }, r);
    }

    [Fact]
    public void Una_GPO_filtrada_no_cuenta_aunque_traiga_nombre()
    {
        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(USUARIO_EN_ESPANOL, GpResultParsing.RsopScope.User)!;

        Assert.DoesNotContain(r, n => n.StartsWith("{31B2F340", StringComparison.Ordinal));
    }

    [Fact]
    public void La_seccion_que_no_esta_es_null_y_no_lista_vacia()
    {
        // ⚠️ El corazón del asunto. Un informe de equipo no trae sección de
        // usuario, y "no sé" no puede salir por la misma puerta que "ninguna".
        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(EQUIPO_CON_TRES, GpResultParsing.RsopScope.User);

        Assert.Null(r);
    }

    [Fact]
    public void Una_seccion_presente_y_sin_directivas_si_es_lista_vacia()
    {
        var xml = """
            <Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
              <ComputerResults><Name>EJEMPLO\EQUIPO-2$</Name></ComputerResults>
            </Rsop>
            """;

        var r = GpResultParsing.ExtractAppliedGposFromRsopXml(xml, GpResultParsing.RsopScope.Computer);

        Assert.NotNull(r);
        Assert.Empty(r!);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no soy xml")]
    [InlineData("<Rsop xmlns=\"http://www.microsoft.com/GroupPolicy/Rsop\"><ComputerResults>")]
    public void Lo_ilegible_es_null(string? xml)
    {
        // gpresult matado por el presupuesto de tiempo deja un fichero a
        // medias. Eso no es un equipo sin directivas.
        Assert.Null(GpResultParsing.ExtractAppliedGposFromRsopXml(xml, GpResultParsing.RsopScope.Computer));
    }
}
