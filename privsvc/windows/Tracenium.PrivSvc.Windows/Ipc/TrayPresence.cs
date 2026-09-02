using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Asegura que el icono de bandeja está corriendo en la sesión de consola.
///
/// ── El problema que resuelve ─────────────────────────────────────────
///
///   El MSI TIENE que cerrar la bandeja para actualizarla: su .exe es
///   single-file self-contained y reemplazarlo bajo un proceso vivo lo deja
///   sin poder cargar sus propios assemblies (ver el bloque CloseApplication
///   en Product.wxs, y el incidente que lo motivó).
///
///   Pero nadie la vuelve a abrir. La Run key solo dispara en el siguiente
///   inicio de sesión, así que tras CADA auto-actualización el usuario se
///   queda sin bandeja hasta que reinicia o vuelve a entrar. En campo eso son
///   días.
///
/// ── Por qué ahora importa mucho más que antes ────────────────────────
///
///   La bandeja dejó de ser decorativa. Desde ADR-0012 es donde vive el
///   INDICADOR de "te están viendo la pantalla" y donde se enseña el DIÁLOGO
///   de consentimiento. Sin bandeja corriendo:
///
///     - el indicador no aparece — alguien mira sin que se note;
///     - la petición de consentimiento no la lee nadie, vence, y el agente la
///       trata como negativa: todas las sesiones rechazadas, en silencio.
///
///   O sea: la función de privacidad que acabamos de construir se apaga sola
///   después de cada actualización.
///
/// ── Por qué SÍ es viable, contra lo que decía el WiX ─────────────────
///
///   El comentario del instalador dice que relanzarla desde el MSI no es
///   viable porque el auto-update corre como SYSTEM y un GUI lanzado desde ahí
///   quedaría huérfano en la sesión 0. Eso es cierto para un spawn normal — y
///   es exactamente el problema que SessionScreenCapture ya resuelve para el
///   helper de captura: WTSQueryUserToken + CreateProcessAsUser con
///   lpDesktop="winsta0\\default". La maquinaria existe; solo no se había
///   aplicado aquí.
///
/// ── Token NORMAL, no el elevado ──────────────────────────────────────
///
///   SessionScreenCapture pide el token ENLAZADO para poder inyectar entrada
///   en ventanas elevadas. Aquí NO: un icono de bandeja no necesita
///   privilegios, y lanzarlo elevado sería regalar integridad alta a un
///   proceso que solo lee un JSON y dibuja una ventana.
/// </summary>
internal static class TrayPresence
{
    private const string TrayExeName = "Tracenium.AgentTray.exe";

    /// <summary>
    /// Arranca la bandeja si no está corriendo en la sesión de consola.
    ///
    /// Devuelve qué hizo, para que el llamador lo registre: "already_running"
    /// es el caso normal y no debería llenar el log.
    /// </summary>
    public static PrivSvcResponse Ensure(PrivSvcRequest req)
    {
        try
        {
            var session = SessionScreenCapture.NativeMethods.WTSGetActiveConsoleSessionId();
            if (session == 0xFFFFFFFF)
            {
                // Nadie en consola: no hay bandeja que arrancar y no es un
                // error. Un servidor sin sesión interactiva vive así siempre.
                return PrivSvcResponse.Success(req.Id, new { ok = true, action = "no_console_session" });
            }

            if (IsRunningInSession(session))
            {
                return PrivSvcResponse.Success(req.Id, new { ok = true, action = "already_running" });
            }

            var exe = ResolveTrayExe();
            if (exe is null)
            {
                return PrivSvcResponse.Success(req.Id, new
                {
                    ok = false,
                    action = "exe_not_found",
                    hint = "Tracenium.AgentTray.exe no está donde se esperaba"
                });
            }

            Launch(exe, session);
            IpcLog.Write($"tray relaunched into session {session}: {exe}");
            return PrivSvcResponse.Success(req.Id, new { ok = true, action = "launched" });
        }
        catch (Exception ex)
        {
            // Nunca tumbar por esto: la bandeja es importante y no es crítica
            // para que el agente siga funcionando.
            IpcLog.Write($"tray ensure failed: {ex.Message}");
            return PrivSvcResponse.Success(req.Id, new
            {
                ok = false,
                action = "error",
                hint = ex.Message
            });
        }
    }

    /// <summary>
    /// ¿Hay una bandeja viva EN ESA SESIÓN?
    ///
    /// Comprobar solo el nombre no basta en un equipo con varias sesiones
    /// (RDP, cambio rápido de usuario): la bandeja de otro usuario no le sirve
    /// de nada a quien está en consola.
    /// </summary>
    private static bool IsRunningInSession(uint session)
    {
        var name = Path.GetFileNameWithoutExtension(TrayExeName);
        foreach (var p in Process.GetProcessesByName(name))
        {
            try
            {
                if ((uint)p.SessionId == session) return true;
            }
            catch
            {
                // El proceso murió entre el enumerate y el acceso.
            }
            finally
            {
                p.Dispose();
            }
        }
        return false;
    }

    /// <summary>
    /// Ruta del .exe de la bandeja.
    ///
    /// PrivSvc vive en ...\Tracenium\PrivSvc\ y la bandeja en
    /// ...\Tracenium\AgentTray\. Se busca relativo al propio binario y NO por
    /// una ruta absoluta escrita a mano: el instalador puede ir a Program
    /// Files (x86) en un equipo de 32 bits, y una constante allí fallaría solo
    /// en esos.
    /// </summary>
    private static string? ResolveTrayExe()
    {
        var baseDir = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(baseDir, TrayExeName),
            Path.Combine(baseDir, "..", "AgentTray", TrayExeName),
            Path.Combine(baseDir, "..", TrayExeName)
        };
        foreach (var c in candidates)
        {
            var full = Path.GetFullPath(c);
            if (File.Exists(full)) return full;
        }
        return null;
    }

    private static void Launch(string exe, uint session)
    {
        if (!SessionScreenCapture.NativeMethods.WTSQueryUserToken(session, out var userToken))
        {
            throw new InvalidOperationException(
                $"WTSQueryUserToken failed (Win32 {Marshal.GetLastWin32Error()}).");
        }

        var primaryToken = IntPtr.Zero;
        var envBlock = IntPtr.Zero;
        try
        {
            // ⚠️ El token TAL CUAL, sin pedir el enlazado. Ver la nota de
            // cabecera: la bandeja no necesita elevación y dársela sería
            // ampliar su superficie a cambio de nada.
            if (!SessionScreenCapture.NativeMethods.DuplicateTokenEx(userToken,
                    SessionScreenCapture.NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SessionScreenCapture.NativeMethods.SecurityImpersonation,
                    SessionScreenCapture.NativeMethods.TokenPrimary, out primaryToken))
            {
                throw new InvalidOperationException(
                    $"DuplicateTokenEx failed (Win32 {Marshal.GetLastWin32Error()}).");
            }

            SessionScreenCapture.NativeMethods.CreateEnvironmentBlock(out envBlock, primaryToken, false);

            var si = new SessionScreenCapture.NativeMethods.STARTUPINFO();
            si.cb = Marshal.SizeOf<SessionScreenCapture.NativeMethods.STARTUPINFO>();
            // Sin esto el proceso arranca en un escritorio que no existe para
            // el usuario y el icono nunca aparece — el "huérfano en la sesión
            // 0" que el WiX describía.
            si.lpDesktop = "winsta0\\default";

            var created = SessionScreenCapture.NativeMethods.CreateProcessAsUser(
                primaryToken,
                exe,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                SessionScreenCapture.NativeMethods.CREATE_UNICODE_ENVIRONMENT,
                envBlock,
                Path.GetDirectoryName(exe),
                ref si,
                out var pi);

            if (!created)
            {
                throw new InvalidOperationException(
                    $"CreateProcessAsUser failed (Win32 {Marshal.GetLastWin32Error()}).");
            }

            // No se espera al proceso: la bandeja vive mientras dure la sesión
            // del usuario. Solo se sueltan los handles.
            if (pi.hProcess != IntPtr.Zero) SessionScreenCapture.NativeMethods.CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero) SessionScreenCapture.NativeMethods.CloseHandle(pi.hThread);
        }
        finally
        {
            if (envBlock != IntPtr.Zero) SessionScreenCapture.NativeMethods.DestroyEnvironmentBlock(envBlock);
            if (primaryToken != IntPtr.Zero) SessionScreenCapture.NativeMethods.CloseHandle(primaryToken);
            SessionScreenCapture.NativeMethods.CloseHandle(userToken);
        }
    }
}
