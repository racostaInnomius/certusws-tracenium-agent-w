// AgentCoreKeeperShape.cs
//
// Cuándo el PrivSvc vuelve a arrancar TraceniumAgentCore. La decisión es pura
// —lo que se observa entra como datos— para poder probarla fuera de Windows;
// mirar el SCM y arrancar el servicio vive en AgentCoreKeeper.cs.
//
// 🔴 Por qué existe (T111, 28/29-sep, Event Log de un portátil en Modern Standby):
//   22:43:30  7031  Tracenium Agent Core terminated unexpectedly … Restart the
//                   service in 60000 milliseconds.
//   00:34:39  7009  timeout (30000 ms) waiting for Tracenium Agent Core to connect
//   00:34:39  7000  The Tracenium Agent Core service failed to start
// El reinicio del SCM llegó 1 h 51 min tarde (el equipo dormía) y, con el
// sistema frenado, WinSW no avisó de que había arrancado dentro de los 30 s. Y
// ahí se acaba todo: las failure actions del SCM sólo actúan cuando un servicio
// EN MARCHA muere, no cuando falla al arrancar. El agente se quedó parado hasta
// el siguiente arranque de Windows — dos días en ese equipo, 42 h en otro.
//
// El PrivSvc es un servicio aparte que sigue vivo, y ya repara la política de
// reinicio de AgentCore al arrancar (ServiceRecovery). Este es el paso que
// faltaba: si AgentCore está parado y debería no estarlo, arrancarlo.
//
// Lo que NO hace, a propósito:
//   - nada si el servicio está deshabilitado o en manual: eso lo decidió alguien;
//   - nada mientras hay una instalación de Windows Installer en curso: nuestro
//     MSI para AgentCore para reemplazar ficheros y lo arranca al final;
//   - nada con Windows apagándose;
//   - nada durante los primeros minutos parado: el propio SCM reintenta a los
//     60–120 s, y no hay que pisarle;
//   - no insiste en bucle: si el arranque falla, espera cada vez más.

using System;

namespace Tracenium.PrivSvc.Windows;

public enum AgentCoreStatus
{
    NotInstalled,
    Running,
    Stopped,
    /// <summary>StartPending, StopPending y compañía: el SCM está en ello.</summary>
    Pending,
    Other
}

public enum AgentCoreStartMode
{
    Automatic,
    Manual,
    Disabled,
    Unknown
}

public sealed record KeeperObservation(
    AgentCoreStatus Status,
    AgentCoreStartMode StartMode,
    bool InstallerRunning,
    bool ShuttingDown);

public enum KeeperAction
{
    None,
    Start
}

public sealed record KeeperDecision(KeeperAction Action, string Reason);

/// <summary>Lo que el vigilante recuerda entre comprobaciones.</summary>
public sealed class AgentCoreKeeperState
{
    /// <summary>Desde cuándo se le ve parado (null si no lo está).</summary>
    public DateTime? StoppedSinceUtc { get; set; }

    /// <summary>Arranques fallidos seguidos.</summary>
    public int FailedStarts { get; set; }

    /// <summary>No se vuelve a intentar antes de esto.</summary>
    public DateTime? NextAttemptUtc { get; set; }
}

public static class AgentCoreKeeperShape
{
    /// <summary>
    /// Cuánto tiene que llevar parado antes de que el PrivSvc actúe. Por
    /// encima del mayor retraso de reinicio del SCM (120 s, ver
    /// ServiceRecovery) para no competir con él cuando sí funciona.
    /// </summary>
    public static readonly TimeSpan StoppedGrace = TimeSpan.FromMinutes(3);

    private static readonly TimeSpan BackoffBase = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan BackoffMax = TimeSpan.FromMinutes(30);

    /// <summary>Espera tras el n-ésimo arranque fallido seguido: 2, 4, 8, 16, 30, 30… min.</summary>
    public static TimeSpan Backoff(int failedStarts)
    {
        if (failedStarts <= 0) return TimeSpan.Zero;
        var exp = Math.Min(failedStarts - 1, 10);
        var ms = BackoffBase.TotalMilliseconds * Math.Pow(2, exp);
        return TimeSpan.FromMilliseconds(Math.Min(ms, BackoffMax.TotalMilliseconds));
    }

    public static KeeperDecision Decide(KeeperObservation o, AgentCoreKeeperState s, DateTime nowUtc)
    {
        if (o.Status != AgentCoreStatus.Stopped)
        {
            s.StoppedSinceUtc = null;
            if (o.Status == AgentCoreStatus.Running)
            {
                // Arrancó (lo arrancamos nosotros, el SCM o alguien): se olvida
                // el historial de fallos.
                s.FailedStarts = 0;
                s.NextAttemptUtc = null;
            }
            return new KeeperDecision(KeeperAction.None, o.Status switch
            {
                AgentCoreStatus.NotInstalled => "not installed",
                AgentCoreStatus.Running => "running",
                AgentCoreStatus.Pending => "SCM transition in progress",
                _ => "not stopped"
            });
        }

        if (o.StartMode != AgentCoreStartMode.Automatic)
        {
            // Deshabilitado o en manual: lo decidió alguien. Que se quede así.
            s.StoppedSinceUtc = null;
            return new KeeperDecision(KeeperAction.None, $"start mode is {o.StartMode}");
        }

        if (o.ShuttingDown)
        {
            return new KeeperDecision(KeeperAction.None, "Windows is shutting down");
        }

        if (o.InstallerRunning)
        {
            // El MSI lo para y lo arranca al final. La gracia vuelve a contar
            // desde que termine, para no arrancarlo entre medias.
            s.StoppedSinceUtc = nowUtc;
            return new KeeperDecision(KeeperAction.None, "Windows Installer is running");
        }

        s.StoppedSinceUtc ??= nowUtc;
        var stoppedFor = nowUtc - s.StoppedSinceUtc.Value;
        if (stoppedFor < StoppedGrace)
        {
            return new KeeperDecision(KeeperAction.None, "within grace (the SCM retries first)");
        }

        if (s.NextAttemptUtc is { } next && nowUtc < next)
        {
            return new KeeperDecision(KeeperAction.None, "backing off after a failed start");
        }

        return new KeeperDecision(KeeperAction.Start, $"stopped for {(int)stoppedFor.TotalMinutes} min");
    }

    /// <summary>Apunta el resultado de un arranque que se acaba de intentar.</summary>
    public static void RecordStart(AgentCoreKeeperState s, bool ok, DateTime nowUtc)
    {
        if (ok)
        {
            s.FailedStarts = 0;
            s.NextAttemptUtc = null;
            s.StoppedSinceUtc = null;
            return;
        }
        s.FailedStarts += 1;
        s.NextAttemptUtc = nowUtc + Backoff(s.FailedStarts);
    }
}
