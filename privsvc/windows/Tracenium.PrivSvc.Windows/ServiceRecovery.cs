// ServiceRecovery.cs
//
// Re-applies the SCM failure actions for TraceniumAgentCore every time the
// PrivSvc starts.
//
// Why this is not the installer's job alone:
//
// The MSI has carried a `ConfigureAgentCoreRecovery` custom action since
// 1.1.20 (`sc.exe failure ...`, Return="ignore"). In August 2026 a host running
// 1.1.35 answered `sc qfailure TraceniumAgentCore` with RESET_PERIOD 0 and no
// actions at all — so the custom action had not taken effect, and because it
// ignores its exit code nothing ever said so. AgentCore then died and stayed
// dead for days: the SCM had no instruction to restart it.
//
// Note the WinSW `<onfailure>` entries in TraceniumAgentCore.xml do NOT help
// here — WinSW only pushes those to the SCM during `winsw install`, and this
// product installs the service through WiX <ServiceInstall> instead. `sc.exe
// failure` is the only path that actually configures recovery.
//
// The PrivSvc is the right place for the repair: it runs as LocalSystem, it is
// a declared dependency of AgentCore (so it starts first), and it survives
// AgentCore's death. Doing it here also fixes hosts that are ALREADY deployed
// with the broken config, without waiting for an MSI upgrade to reach them.
//
// Idempotent by construction: `sc.exe failure` overwrites, so applying it on
// every start is safe and needs no parsing of the current configuration.

using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Tracenium.PrivSvc.Windows.Ipc;

namespace Tracenium.PrivSvc.Windows;

public static class ServiceRecovery
{
    private const string TargetService = "TraceniumAgentCore";

    /// <summary>
    /// Restart on the 1st, 2nd and 3rd failure (60s, 60s, 120s), with the
    /// failure counter resetting after a day. Mirrors the values in the MSI's
    /// ConfigureAgentCoreRecovery custom action — the two must agree, or an
    /// upgrade and a service restart would disagree about the policy.
    /// </summary>
    private const string ResetPeriodSeconds = "86400";
    private const string Actions = "restart/60000/restart/60000/restart/120000";

    public static void EnsureConfigured(ILogger logger)
    {
        try
        {
            var before = Query();

            Run("failure", TargetService, "reset=", ResetPeriodSeconds, "actions=", Actions);

            // Also act when the service stops without reporting an error code.
            // AgentCore's wrapper has died with 1067 (ERROR_PROCESS_ABORTED),
            // which already counts as a failure, but a wrapper that manages to
            // exit cleanly on its way down would otherwise get no restart.
            Run("failureflag", TargetService, "1");

            var after = Query();
            var hadNone = before.IndexOf("RESTART", StringComparison.OrdinalIgnoreCase) < 0;

            if (hadNone)
            {
                // Worth shouting about: this host was one crash away from
                // staying down silently.
                IpcLog.Write($"[recovery] {TargetService} had NO failure actions configured — applied them now");
                logger.LogWarning("[recovery] {Service} had no SCM failure actions; applied restart policy", TargetService);
            }
            else
            {
                IpcLog.Write($"[recovery] {TargetService} failure actions re-applied");
            }

            if (after.IndexOf("RESTART", StringComparison.OrdinalIgnoreCase) < 0)
            {
                // sc.exe returned but the configuration did not stick. Do not
                // fail the service over it — just make it visible, because the
                // silent version of this is exactly what caused the outage.
                IpcLog.Write($"[recovery] WARNING: {TargetService} still reports no failure actions after configuring");
                logger.LogError("[recovery] {Service} still has no failure actions after sc.exe", TargetService);
            }
        }
        catch (Exception ex)
        {
            // Recovery configuration must never keep the PrivSvc from starting.
            IpcLog.Write($"[recovery] configuration failed: {ex.GetType().Name}: {ex.Message}");
            try { logger.LogError(ex, "[recovery] failed to configure {Service}", TargetService); } catch { }
        }
    }

    private static string Query()
    {
        try { return Run("qfailure", TargetService); }
        catch { return string.Empty; }
    }

    private static string Run(params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            // Absolute path: the deferred-install context that runs the MSI's
            // equivalent action cannot be trusted to have System32 on PATH, and
            // neither should we.
            FileName = Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\sc.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi);
        if (p == null) return string.Empty;

        var stdout = p.StandardOutput.ReadToEnd();
        p.WaitForExit(15_000);
        return stdout;
    }
}
