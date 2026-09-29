// privsvc/windows/Tracenium.PrivSvc.Tests/MsuExitCodesTests.cs
//
// Qué significa el código con el que sale DISM al instalar un .msu.
//
// El caso que trae esto: KB5122882 dejó `msi-erp` (T111) sin RDP dos veces en
// una semana por un defecto documentado de RDS. Lo corrige KB5129237, que es
// FUERA DE BANDA: no se distribuye por WSUS, así que PMP no lo ve, y la única
// vía a los diez servidores que siguen en 20348.5622 es SDP.
//
// ⚠️ Lo que se prueba aquí no es aritmética de constantes: es que un paquete
// instalado no se marque como fallido y —sobre todo— que uno del que NO sabemos
// nada no se marque como instalado.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class MsuExitCodesTests
{
    [Fact]
    public void Cero_es_instalado_y_terminado()
    {
        Assert.Equal(MsuOutcome.Success, MsuExitCodes.Classify(0));
        Assert.True(MsuExitCodes.IsInstalled(0));
    }

    // Los dos códigos de ÉXITO de Windows que más veces se han confundido con un
    // fallo: la instalación funcionó y sólo pide un reinicio.
    [Theory]
    [InlineData(3010)] // ERROR_SUCCESS_REBOOT_REQUIRED
    [InlineData(3011)] // ERROR_SUCCESS_RESTART_REQUIRED (DISM)
    [InlineData(2359301)] // WU_S_REBOOT_REQUIRED, por el camino de wusa
    public void Reinicio_pendiente_sigue_siendo_instalado(int code)
    {
        Assert.Equal(MsuOutcome.RebootRequired, MsuExitCodes.Classify(code));
        Assert.True(MsuExitCodes.IsInstalled(code));
    }

    [Fact]
    public void Reinicio_ya_iniciado_se_distingue_del_pendiente()
    {
        // La diferencia importa río arriba: con 1641 la máquina se está apagando,
        // así que cualquier sondeo posterior compite con el apagado.
        Assert.Equal(MsuOutcome.RebootInitiated, MsuExitCodes.Classify(1641));
        Assert.True(MsuExitCodes.IsInstalled(1641));
        Assert.NotEqual(MsuExitCodes.Classify(3010), MsuExitCodes.Classify(1641));
    }

    // 2359302 (0x00240006, WU_S_ALREADY_INSTALLED) dice exactamente «ya estaba»,
    // sin ambigüedad. Antes no estaba mapeado en ninguno de los dos repos, así
    // que caía en el saco de los inesperados: `failed` permanente y sin
    // reintento, sobre un equipo que tenía el parche puesto.
    [Fact]
    public void Ya_instalado_es_un_exito_no_un_fallo()
    {
        Assert.Equal(MsuOutcome.AlreadyInstalled, MsuExitCodes.Classify(2359302));
        Assert.True(MsuExitCodes.IsInstalled(2359302));
        Assert.NotEqual(MsuOutcome.Failed, MsuExitCodes.Classify(2359302));
    }

    // ⚠️ LA DECISIÓN IMPORTANTE DE ESTE MÓDULO. 0x800F081E (CBS_E_NOT_APPLICABLE)
    // mete en el mismo número «ya está instalado» y «este paquete no es para este
    // sistema». Uno es éxito, el otro fallo permanente, y DISM no los separa.
    // Así que NO se adivina, y en particular no se adivina hacia el lado cómodo:
    // dar por instalado algo que quizá no lo está cerraría el job como hecho
    // sobre un servidor que sigue expuesto.
    [Theory]
    [InlineData(unchecked((int)0x800F081E))] // CBS_E_NOT_APPLICABLE
    [InlineData(unchecked((int)0x80240017))] // WU_E_NOT_APPLICABLE
    public void No_aplica_no_afirma_que_se_instalo(int code)
    {
        Assert.Equal(MsuOutcome.NotApplicable, MsuExitCodes.Classify(code));
        Assert.False(MsuExitCodes.IsInstalled(code));
        // Y tampoco se declara un fallo: es una duda, y se resuelve con evidencia.
        Assert.NotEqual(MsuOutcome.Failed, MsuExitCodes.Classify(code));
        Assert.NotEqual(MsuOutcome.AlreadyInstalled, MsuExitCodes.Classify(code));
    }

    [Fact]
    public void El_motivo_de_no_aplica_explica_la_ambiguedad()
    {
        // Sin esto, el operador lee «not applicable» y concluye lo que le
        // convenga. El texto tiene que decir que el número no distingue, y qué
        // dato sí lo hace.
        var d = MsuExitCodes.Describe(unchecked((int)0x800F081E));
        Assert.Contains("already present", d);
        Assert.Contains("does not apply", d);
        Assert.Contains("UBR", d);
    }

    // El HRESULT crudo sale con signo (-2146498530) y toda la documentación de
    // Microsoft está en hexadecimal: sin traducirlo no se puede ni buscar.
    [Fact]
    public void El_motivo_lleva_el_hexadecimal_buscable()
    {
        Assert.Contains("0x800F081E", MsuExitCodes.Describe(unchecked((int)0x800F081E)));
        Assert.Contains("0x00240006", MsuExitCodes.Describe(2359302));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(87)] // ERROR_INVALID_PARAMETER
    [InlineData(1603)]
    [InlineData(unchecked((int)0x800F0805))] // CBS_E_INVALID_PACKAGE
    public void Lo_que_no_reconocemos_es_un_fallo(int code)
    {
        Assert.Equal(MsuOutcome.Failed, MsuExitCodes.Classify(code));
        Assert.False(MsuExitCodes.IsInstalled(code));
        Assert.Contains("failed", MsuExitCodes.Describe(code));
    }

    // ⚠️ El defecto por defecto tiene que ser «fallo», no «éxito»: un código que
    // nadie ha clasificado no puede cerrar un job como hecho.
    [Fact]
    public void Un_codigo_nunca_visto_no_pasa_por_exito()
    {
        Assert.False(MsuExitCodes.IsInstalled(999999));
        Assert.False(MsuExitCodes.IsInstalled(-1));
    }
}
