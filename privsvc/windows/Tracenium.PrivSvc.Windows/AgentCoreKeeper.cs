// AgentCoreKeeper.cs
//
// Vuelve a arrancar TraceniumAgentCore cuando se queda parado y nadie más lo va
// a hacer. Qué cuenta como "nadie más" y cuándo NO actuar está en
// AgentCoreKeeperShape.cs, que es puro y tiene tests; aquí sólo se observa el
// SCM y se llama a Start().
//
// 🔴 T111, 28/29-sep: 7031 (el agente sale con el equipo en Modern Standby),
// 7009 + 7000 (el reinicio del SCM llega tarde y falla al arrancar), y ningún
// reintento más. El agente quedó parado dos días.

using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Tracenium.PrivSvc.Windows.Ipc;

namespace Tracenium.PrivSvc.Windows;

public static class AgentCoreKeeper
{
    private const string TargetService = "TraceniumAgentCore";

    /// <summary>Cada cuánto se mira. La gracia (3 min) la pone la decisión, no el intervalo.</summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Lo que se espera a que el arranque se vea en Running. Más que los 30 s
    /// que da el SCM: si el equipo está frenado el SCM puede tardar en
    /// decidir, y queremos el resultado real, no el de nuestro reloj.
    /// </summary>
    private static readonly TimeSpan StartWait = TimeSpan.FromSeconds(90);

    public static async Task RunAsync(ILogger logger, CancellationToken ct)
    {
        var state = new AgentCoreKeeperState();
        IpcLog.Write("[keeper] watching TraceniumAgentCore");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                var decision = AgentCoreKeeperShape.Decide(Observe(), state, DateTime.UtcNow);
                if (decision.Action != KeeperAction.Start) continue;

                var attempt = state.FailedStarts + 1;
                IpcLog.Write($"[keeper] {TargetService} is stopped ({decision.Reason}); starting it, attempt {attempt}");
                logger.LogWarning("[keeper] {Service} stopped ({Reason}); starting it, attempt {Attempt}",
                    TargetService, decision.Reason, attempt);

                var ok = TryStart(out var error);
                AgentCoreKeeperShape.RecordStart(state, ok, DateTime.UtcNow);

                if (ok)
                {
                    IpcLog.Write($"[keeper] {TargetService} started");
                }
                else
                {
                    var wait = AgentCoreKeeperShape.Backoff(state.FailedStarts);
                    IpcLog.Write($"[keeper] {TargetService} failed to start: {error}; next try in {(int)wait.TotalMinutes} min");
                    logger.LogError("[keeper] {Service} failed to start: {Error}", TargetService, error);
                }
            }
            catch (Exception ex)
            {
                // El vigilante no puede tumbar al PrivSvc.
                IpcLog.Write($"[keeper] check failed: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private static KeeperObservation Observe()
    {
        AgentCoreStatus status;
        AgentCoreStartMode mode;
        try
        {
            using var sc = new ServiceController(TargetService);
            status = sc.Status switch
            {
                ServiceControllerStatus.Running => AgentCoreStatus.Running,
                ServiceControllerStatus.Stopped => AgentCoreStatus.Stopped,
                ServiceControllerStatus.StartPending
                    or ServiceControllerStatus.StopPending
                    or ServiceControllerStatus.ContinuePending
                    or ServiceControllerStatus.PausePending => AgentCoreStatus.Pending,
                _ => AgentCoreStatus.Other
            };
            mode = sc.StartType switch
            {
                ServiceStartMode.Automatic => AgentCoreStartMode.Automatic,
                ServiceStartMode.Manual => AgentCoreStartMode.Manual,
                ServiceStartMode.Disabled => AgentCoreStartMode.Disabled,
                _ => AgentCoreStartMode.Unknown
            };
        }
        catch (InvalidOperationException)
        {
            // El servicio no existe (desinstalado, o a medio instalar).
            return new KeeperObservation(AgentCoreStatus.NotInstalled, AgentCoreStartMode.Unknown, false, false);
        }

        return new KeeperObservation(status, mode, IsWindowsInstallerRunning(), IsShuttingDown());
    }

    private static bool TryStart(out string error)
    {
        error = "";
        try
        {
            using var sc = new ServiceController(TargetService);
            sc.Refresh();
            if (sc.Status != ServiceControllerStatus.Stopped)
            {
                // Lo arrancó alguien entre la observación y aquí: vale igual.
                return true;
            }
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, StartWait);
            return true;
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            error = $"not Running after {(int)StartWait.TotalSeconds}s";
            return false;
        }
        catch (Exception ex)
        {
            // InvalidOperationException con un Win32Exception dentro: 1053, 1069…
            error = ex.InnerException is { } inner
                ? $"{ex.GetType().Name}: {inner.Message}"
                : $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Windows Installer está ejecutando una instalación (cualquiera): mientras
    /// exista el mutex global `_MSIExecute`. Nuestro MSI para AgentCore durante
    /// la suya y lo arranca al final, así que no hay que tocarlo.
    /// </summary>
    private static bool IsWindowsInstallerRunning()
    {
        try
        {
            if (Mutex.TryOpenExisting(@"Global\_MSIExecute", out var m))
            {
                m.Dispose();
                return true;
            }
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            // Existe aunque no nos dejen abrirlo.
            return true;
        }
        catch
        {
            return false;
        }
    }

    private const int SM_SHUTTINGDOWN = 0x2000;

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private static bool IsShuttingDown()
    {
        try { return GetSystemMetrics(SM_SHUTTINGDOWN) != 0; }
        catch { return false; }
    }
}
