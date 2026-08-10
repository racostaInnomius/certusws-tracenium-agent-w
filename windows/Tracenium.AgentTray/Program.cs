using System.Diagnostics;
using System.Windows.Forms;

namespace Tracenium.AgentTray;

internal static class Program
{
    // Set on the child when we relaunch ourselves after a fatal error.
    // Presence of this variable means "you are already a restart" and
    // suppresses a second one, so a deterministic crash can't turn into
    // a relaunch loop that pegs the CPU.
    private const string RestartGuardVar = "TRACENIUM_TRAY_RESTARTED";

    [STAThread]
    private static void Main()
    {
        // ── Never show the modal .NET crash dialog to an end user ──────
        //
        // This is a background tray app. Before this, ANY unhandled
        // exception surfaced the WinForms "Excepción no controlada en la
        // aplicación / Continuar / Salir" dialog — a modal window sitting
        // on top of whatever the user was doing, which they cannot
        // dismiss permanently (Continuar just re-arms it). Two endpoints
        // hit exactly that (2026-07-28) with:
        //
        //   System.IO.FileNotFoundException: System.Collections.NonGeneric
        //     at System.Windows.Forms.Application.get_OpenForms
        //     at System.Windows.Forms.Form.OnLoad
        //
        // Why that assembly, in a SELF-CONTAINED app that bundles it (we
        // verified it ships — 238 assemblies in the publish): a
        // single-file app reads its managed assemblies LAZILY out of the
        // bundle inside its own .exe. An MSI upgrade replaces that .exe
        // while the old process is still running, so every assembly not
        // yet loaded becomes unreachable. `System.Collections.NonGeneric`
        // (FormCollection : ReadOnlyCollectionBase) is loaded the FIRST
        // time a Form is shown — hence the crash appearing "out of
        // nowhere" some time after an upgrade, on the first status window
        // or device-info flyout.
        //
        // Handling it here fixes the user-visible symptom for good,
        // independently of the trigger: log it, then relaunch (which
        // picks up the NEW binary — the correct outcome after an
        // upgrade) instead of blocking the desktop with a dialog.
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => HandleFatal(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => HandleFatal(e.ExceptionObject as Exception);

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApplicationContext());
    }

    private static void HandleFatal(Exception? ex)
    {
        Log(ex);
        TryRestart();
        // Exit without ever rendering UI. Exit code 1 marks it abnormal
        // for anyone reading process telemetry.
        Environment.Exit(1);
    }

    private static void Log(Exception? ex)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Tracenium", "Agent", "logs");
            Directory.CreateDirectory(dir);
            var line =
                $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z] tray fatal: " +
                $"{ex?.GetType().Name}: {ex?.Message}{Environment.NewLine}{ex?.StackTrace}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(dir, "tray-crash.log"), line);
        }
        catch
        {
            // Logging must never be the reason we fail to exit cleanly.
        }
    }

    private static void TryRestart()
    {
        // Already a restart → stop here, otherwise a permanent failure
        // would spawn processes forever.
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(RestartGuardVar)))
        {
            return;
        }

        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            {
                return;
            }

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false
            };
            psi.Environment[RestartGuardVar] = "1";
            Process.Start(psi);
        }
        catch
        {
            // If the relaunch fails the Run key still starts a fresh tray
            // at next logon — better than a dialog either way.
        }
    }
}
