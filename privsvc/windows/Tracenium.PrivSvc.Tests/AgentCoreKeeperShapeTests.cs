// privsvc/windows/Tracenium.PrivSvc.Tests/AgentCoreKeeperShapeTests.cs
//
// Cuándo el PrivSvc vuelve a arrancar TraceniumAgentCore.
//
// 🔴 T111, 28/29-sep, Event Log de un portátil en Modern Standby:
//   22:43:30  7031  Tracenium Agent Core terminated unexpectedly … Restart in 60000 ms
//   00:34:39  7009  timeout (30000 ms) waiting for Tracenium Agent Core to connect
//   00:34:39  7000  The Tracenium Agent Core service failed to start
// Y nada más: el SCM no reintenta un arranque fallido. Dos días parado.

using System;
using Tracenium.PrivSvc.Windows;
using Xunit;

public class AgentCoreKeeperShapeTests
{
    private static readonly DateTime T0 = new(2026, 9, 29, 5, 34, 39, DateTimeKind.Utc);

    private static KeeperObservation Stopped(
        AgentCoreStartMode mode = AgentCoreStartMode.Automatic,
        bool installer = false,
        bool shuttingDown = false) =>
        new(AgentCoreStatus.Stopped, mode, installer, shuttingDown);

    private static readonly KeeperObservation Running =
        new(AgentCoreStatus.Running, AgentCoreStartMode.Automatic, false, false);

    [Fact]
    public void El_caso_de_T111_parado_tras_un_arranque_fallido_se_vuelve_a_arrancar()
    {
        var s = new AgentCoreKeeperState();

        // Primera vez que se le ve parado: se deja al SCM su oportunidad.
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, T0).Action);
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, T0.AddMinutes(2)).Action);

        // Pasada la gracia, sigue parado: nadie más lo va a arrancar.
        var d = AgentCoreKeeperShape.Decide(Stopped(), s, T0.AddMinutes(3));
        Assert.Equal(KeeperAction.Start, d.Action);
        Assert.Contains("stopped for 3 min", d.Reason);
    }

    [Fact]
    public void La_gracia_supera_el_mayor_reintento_del_SCM()
    {
        // ServiceRecovery: restart/60000/restart/60000/restart/120000.
        Assert.True(AgentCoreKeeperShape.StoppedGrace > TimeSpan.FromSeconds(120));
    }

    [Fact]
    public void En_marcha_o_en_transicion_no_se_toca()
    {
        var s = new AgentCoreKeeperState();
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Running, s, T0).Action);
        var pending = new KeeperObservation(AgentCoreStatus.Pending, AgentCoreStartMode.Automatic, false, false);
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(pending, s, T0.AddHours(1)).Action);
        var gone = new KeeperObservation(AgentCoreStatus.NotInstalled, AgentCoreStartMode.Unknown, false, false);
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(gone, s, T0.AddHours(2)).Action);
    }

    [Theory]
    [InlineData(AgentCoreStartMode.Disabled)]
    [InlineData(AgentCoreStartMode.Manual)]
    [InlineData(AgentCoreStartMode.Unknown)]
    public void Deshabilitado_o_en_manual_es_una_decision_de_alguien(AgentCoreStartMode mode)
    {
        var s = new AgentCoreKeeperState();
        for (var m = 0; m <= 60; m += 1)
        {
            Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(mode), s, T0.AddMinutes(m)).Action);
        }
    }

    [Fact]
    public void Con_Windows_Installer_en_marcha_se_espera_y_la_gracia_cuenta_desde_que_acaba()
    {
        var s = new AgentCoreKeeperState();
        // Nuestro MSI para AgentCore durante 10 minutos.
        for (var m = 0; m <= 10; m++)
        {
            Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(installer: true), s, T0.AddMinutes(m)).Action);
        }
        // Termina el MSI y el servicio sigue parado: gracia completa contada
        // desde la última vez que se vio el instalador (minuto 10), no desde
        // que se paró.
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, T0.AddMinutes(11)).Action);
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, T0.AddMinutes(12)).Action);
        Assert.Equal(KeeperAction.Start, AgentCoreKeeperShape.Decide(Stopped(), s, T0.AddMinutes(13)).Action);
    }

    [Fact]
    public void Con_Windows_apagandose_no_se_arranca()
    {
        var s = new AgentCoreKeeperState { StoppedSinceUtc = T0 };
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(shuttingDown: true), s, T0.AddHours(1)).Action);
    }

    [Fact]
    public void Si_el_arranque_falla_espera_cada_vez_mas_y_no_entra_en_bucle()
    {
        var s = new AgentCoreKeeperState();
        AgentCoreKeeperShape.Decide(Stopped(), s, T0);
        var now = T0.AddMinutes(3);
        Assert.Equal(KeeperAction.Start, AgentCoreKeeperShape.Decide(Stopped(), s, now).Action);

        // Falla (otra vez 7009/7000, el equipo sigue frenado).
        AgentCoreKeeperShape.RecordStart(s, ok: false, now);
        Assert.Equal(1, s.FailedStarts);
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, now.AddMinutes(1)).Action);
        Assert.Equal(KeeperAction.Start, AgentCoreKeeperShape.Decide(Stopped(), s, now.AddMinutes(2)).Action);

        AgentCoreKeeperShape.RecordStart(s, ok: false, now.AddMinutes(2));
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, now.AddMinutes(5)).Action);
        Assert.Equal(KeeperAction.Start, AgentCoreKeeperShape.Decide(Stopped(), s, now.AddMinutes(6)).Action);
    }

    [Fact]
    public void El_backoff_es_2_4_8_16_y_luego_30_min_como_tope()
    {
        Assert.Equal(TimeSpan.Zero, AgentCoreKeeperShape.Backoff(0));
        Assert.Equal(TimeSpan.FromMinutes(2), AgentCoreKeeperShape.Backoff(1));
        Assert.Equal(TimeSpan.FromMinutes(4), AgentCoreKeeperShape.Backoff(2));
        Assert.Equal(TimeSpan.FromMinutes(8), AgentCoreKeeperShape.Backoff(3));
        Assert.Equal(TimeSpan.FromMinutes(16), AgentCoreKeeperShape.Backoff(4));
        Assert.Equal(TimeSpan.FromMinutes(30), AgentCoreKeeperShape.Backoff(5));
        Assert.Equal(TimeSpan.FromMinutes(30), AgentCoreKeeperShape.Backoff(50));
    }

    [Fact]
    public void Cuando_vuelve_a_estar_en_marcha_se_olvida_el_historial()
    {
        var s = new AgentCoreKeeperState { FailedStarts = 4, NextAttemptUtc = T0.AddMinutes(30), StoppedSinceUtc = T0 };
        AgentCoreKeeperShape.Decide(Running, s, T0.AddMinutes(1));
        Assert.Equal(0, s.FailedStarts);
        Assert.Null(s.NextAttemptUtc);
        Assert.Null(s.StoppedSinceUtc);

        // Y si se vuelve a parar, gracia completa desde cero.
        Assert.Equal(KeeperAction.None, AgentCoreKeeperShape.Decide(Stopped(), s, T0.AddMinutes(2)).Action);
    }

    [Fact]
    public void Un_arranque_que_sale_bien_limpia_el_estado()
    {
        var s = new AgentCoreKeeperState { FailedStarts = 2, NextAttemptUtc = T0, StoppedSinceUtc = T0 };
        AgentCoreKeeperShape.RecordStart(s, ok: true, T0.AddMinutes(1));
        Assert.Equal(0, s.FailedStarts);
        Assert.Null(s.NextAttemptUtc);
        Assert.Null(s.StoppedSinceUtc);
    }
}
