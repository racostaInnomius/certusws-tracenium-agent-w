// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/UserScopedUninstall.cs
//
// Desinstalar lo que un usuario instaló en SU perfil (ADR-0019, paso 3).
//
// ── El problema ──────────────────────────────────────────────────────────
//
// RingCentral, Zoom, OneDrive, Teams… se instalan POR USUARIO: su entrada de
// desinstalación vive en HKEY_USERS\<SID>\...\Uninstall y sus ficheros en
// %LOCALAPPDATA% de esa persona. 132 filas del inventario de T111 (el 5 %). El
// PrivSvc corre como LocalSystem, y hasta aquí la desinstalación sólo miraba
// HKLM: esas apps eran intocables.
//
// ── Por qué con el token DEL USUARIO, y nunca como SYSTEM ────────────────
//
// Dos razones, y la segunda es la que no se puede negociar:
//
//   1. Como SYSTEM, `%LOCALAPPDATA%`, `HKCU` y el perfil son los de SYSTEM.
//      Un desinstalador de usuario lanzado así no encuentra lo suyo: falla, o
//      deja la app a medias.
//   2. ⚠️ `QuietUninstallString` vive en el HKCU de ese usuario, y ESE USUARIO
//      PUEDE ESCRIBIRLO. Ejecutarlo como SYSTEM sería darle a cualquier usuario
//      sin privilegios una forma de hacer que el agente ejecute lo que él
//      quiera con los permisos máximos del equipo. Con su propio token, lo peor
//      que puede conseguir es ejecutar algo como él mismo — que ya podía.
//
// Por eso NO HAY PLAN B: sin sesión del usuario no hay token, y la respuesta es
// `user_not_logged_on`, no «lo intento como SYSTEM».
//
// ── Límites, dichos ──────────────────────────────────────────────────────
//
//   · Sólo se ven los perfiles CARGADOS (usuarios con sesión): HKEY_USERS no
//     monta el hive de quien no ha iniciado sesión. Es el mismo límite que el
//     inventario, que es de donde salió la fila.
//   · El token es el FILTRADO (sin elevación UAC). Un desinstalador de usuario
//     no la necesita, y pedir la elevación sería ampliar la superficie a cambio
//     de nada — mismo criterio que la bandeja (TrayPresence).

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

internal static class UserScopedUninstall
{
    private const string UninstallSubPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";

    /// <summary>
    /// Cuánto se espera a que la entrada desaparezca tras un «éxito».
    ///
    /// ⚠️ Los desinstaladores NSIS (el «Uninstall X.exe /S» de casi toda app
    /// Electron: RingCentral, Plaud…) se copian a %TEMP%, se relanzan desde allí
    /// y el proceso original sale con 0 AL INSTANTE, mientras la copia sigue
    /// borrando. Sin esta espera el post-detect del agente llega antes que el
    /// borrado y califica «still present» algo que un minuto después ya no está.
    /// </summary>
    private static readonly TimeSpan SettleWindow = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Las entradas de desinstalación que casan con el patrón, en cada perfil
    /// de usuario cargado. Un perfil ilegible no tumba a los demás.
    /// </summary>
    public static List<UserUninstallShape.UserEntry> FindEntries(string displayNameLike)
    {
        var regex = UninstallIdentity.LikeToRegex(displayNameLike);
        var list = new List<UserUninstallShape.UserEntry>();
        try
        {
            // Misma vista y misma ruta que el inventario (SoftwareInventory.
            // ReadLoadedUserProfiles): si buscáramos en otro sitio, la fila que
            // el operador vio no sería la que se desinstala.
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            foreach (var sid in users.GetSubKeyNames())
            {
                if (!UserRegistryProbeShape.IsUserProfileHive(sid)) continue;
                try
                {
                    using var uninstall = users.OpenSubKey(sid + @"\" + UninstallSubPath);
                    if (uninstall == null) continue;
                    foreach (var name in uninstall.GetSubKeyNames())
                    {
                        using var entry = uninstall.OpenSubKey(name);
                        if (entry == null) continue;
                        var displayName = entry.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(displayName) || !regex.IsMatch(displayName)) continue;
                        list.Add(new UserUninstallShape.UserEntry(
                            sid,
                            name,
                            displayName,
                            entry.GetValue("UninstallString") as string,
                            entry.GetValue("QuietUninstallString") as string,
                            entry.GetValue("WindowsInstaller") is int wi && wi == 1,
                            entry.GetValue("DisplayVersion") as string));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PrivSvc][UserUninstall] user hive {sid} unreadable: {ex.GetType().Name}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][UserUninstall] HKEY_USERS unreadable: {ex.GetType().Name}");
        }
        return list;
    }

    /// <summary>
    /// Desinstala la app en cada perfil donde esté, con el token de cada
    /// usuario, y devuelve UN veredicto (ver UserUninstallShape.Aggregate).
    ///
    /// El plazo es para TODOS los perfiles juntos, no por perfil: el agente
    /// espera a la privsvc con un tiempo fijo, y dos perfiles a plazo completo
    /// cada uno lo desbordarían.
    /// </summary>
    public static async Task<UserUninstallShape.Outcome> RunAsync(string displayNameLike, int timeoutSeconds)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        var entries = FindEntries(displayNameLike);
        var sessions = entries.Count > 0 ? InteractiveSessionsBySid() : new Dictionary<string, uint>();
        var results = new List<UserUninstallShape.ProfileResult>();

        foreach (var e in entries)
        {
            var label = AccountLabel(e.Sid);
            var choice = UserUninstallShape.ChooseCommand(e);
            // Sin silencioso conocido, queda mirar el BINARIO: la cola larga de
            // desinstaladores por usuario es NSIS, que acepta `/S`. Ver
            // UninstallerProbe — se lee el fichero, no se adivina por el nombre.
            var commandLine = choice.CommandLine ?? UninstallerProbe.SilentCommandFor(e.UninstallString);
            if (commandLine == null)
            {
                results.Add(new(label, UserUninstallShape.ProfileStatus.NoSilentUninstall, null));
                continue;
            }
            if (!sessions.TryGetValue(e.Sid, out var session))
            {
                results.Add(new(label, UserUninstallShape.ProfileStatus.NotLoggedOn, null));
                continue;
            }

            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException($"uninstall timed out after {timeoutSeconds}s");

            var exit = await Task.Run(() => RunAsUser(session, commandLine, remaining));
            var status = UserUninstallShape.ClassifyExit(exit);
            if (status == UserUninstallShape.ProfileStatus.Removed)
            {
                var settle = remaining - SettleWindow > TimeSpan.Zero ? SettleWindow : remaining;
                await WaitForEntryGone(e.Sid, e.KeyName, settle);
            }
            results.Add(new(label, status, exit));
        }

        return UserUninstallShape.Aggregate(results);
    }

    /// <summary>
    /// SID → sesión con token de usuario. Activas primero; una desconectada
    /// (usuario con sesión abierta pero sin conectar, típico de RDP) también
    /// vale: el token existe y el perfil está cargado.
    /// </summary>
    private static Dictionary<string, uint> InteractiveSessionsBySid()
    {
        var map = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!Native.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            Console.WriteLine($"[PrivSvc][UserUninstall] WTSEnumerateSessions failed (Win32 {Marshal.GetLastWin32Error()})");
            return map;
        }
        try
        {
            var size = Marshal.SizeOf<Native.WTS_SESSION_INFO>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<Native.WTS_SESSION_INFO>(buffer + i * size);
                var isActive = info.State == Native.WTSActive;
                if (!isActive && info.State != Native.WTSDisconnected) continue;
                if (!SessionScreenCapture.NativeMethods.WTSQueryUserToken((uint)info.SessionId, out var token)) continue;
                try
                {
                    using var identity = new WindowsIdentity(token);
                    var sid = identity.User?.Value;
                    if (sid == null) continue;
                    if (!map.ContainsKey(sid) || (isActive && !active.Contains(sid)))
                    {
                        map[sid] = (uint)info.SessionId;
                        if (isActive) active.Add(sid);
                    }
                }
                finally
                {
                    SessionScreenCapture.NativeMethods.CloseHandle(token);
                }
            }
        }
        finally
        {
            Native.WTSFreeMemory(buffer);
        }
        return map;
    }

    /// <summary>
    /// Lanza la línea de comandos en la sesión del usuario, con su token y su
    /// entorno, sin ventana, y espera su código de salida.
    /// </summary>
    private static int RunAsUser(uint session, string commandLine, TimeSpan timeout)
    {
        if (!SessionScreenCapture.NativeMethods.WTSQueryUserToken(session, out var userToken))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WTSQueryUserToken failed");
        }

        var primaryToken = IntPtr.Zero;
        var envBlock = IntPtr.Zero;
        var pi = default(SessionScreenCapture.NativeMethods.PROCESS_INFORMATION);
        try
        {
            if (!SessionScreenCapture.NativeMethods.DuplicateTokenEx(userToken,
                    SessionScreenCapture.NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SessionScreenCapture.NativeMethods.SecurityImpersonation,
                    SessionScreenCapture.NativeMethods.TokenPrimary, out primaryToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");
            }

            // ⚠️ El entorno DEL USUARIO: sin esto %LOCALAPPDATA% y %APPDATA%
            // resuelven a los de SYSTEM, que es exactamente el fallo que este
            // fichero existe para evitar.
            if (!SessionScreenCapture.NativeMethods.CreateEnvironmentBlock(out envBlock, primaryToken, false))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock failed");
            }

            var si = new SessionScreenCapture.NativeMethods.STARTUPINFO
            {
                cb = Marshal.SizeOf<SessionScreenCapture.NativeMethods.STARTUPINFO>(),
                lpDesktop = @"winsta0\default",
                // Es un desinstalador SILENCIOSO (ChooseCommand no deja pasar otro),
                // pero si uno aun así pinta algo, que no aparezca en la cara del
                // usuario.
                dwFlags = Native.STARTF_USESHOWWINDOW,
                wShowWindow = Native.SW_HIDE,
            };

            var created = SessionScreenCapture.NativeMethods.CreateProcessAsUser(
                primaryToken,
                null,
                new StringBuilder(commandLine),
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                SessionScreenCapture.NativeMethods.CREATE_UNICODE_ENVIRONMENT | SessionScreenCapture.NativeMethods.CREATE_NO_WINDOW,
                envBlock,
                null,
                ref si,
                out pi);
            if (!created)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser failed");
            }

            var waitMs = (uint)Math.Min(timeout.TotalMilliseconds, uint.MaxValue - 1);
            if (Native.WaitForSingleObject(pi.hProcess, waitMs) != Native.WAIT_OBJECT_0)
            {
                Native.TerminateProcess(pi.hProcess, 1);
                throw new TimeoutException($"uninstaller did not finish within {(int)timeout.TotalSeconds}s");
            }
            if (!Native.GetExitCodeProcess(pi.hProcess, out var exitCode))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
            }
            return unchecked((int)exitCode);
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) SessionScreenCapture.NativeMethods.CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) SessionScreenCapture.NativeMethods.CloseHandle(pi.hProcess);
            if (envBlock != IntPtr.Zero) SessionScreenCapture.NativeMethods.DestroyEnvironmentBlock(envBlock);
            if (primaryToken != IntPtr.Zero) SessionScreenCapture.NativeMethods.CloseHandle(primaryToken);
            SessionScreenCapture.NativeMethods.CloseHandle(userToken);
        }
    }

    /// <summary>Espera (sondeando) a que la entrada de ESE perfil desaparezca. Ver SettleWindow.</summary>
    private static async Task WaitForEntryGone(string sid, string keyName, TimeSpan window)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < window)
        {
            try
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
                using var entry = users.OpenSubKey($@"{sid}\{UninstallSubPath}\{keyName}");
                if (entry == null) return;
            }
            catch
            {
                return; // hive descargada (el usuario cerró sesión): nada que esperar
            }
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }

    /// <summary>DOMINIO\usuario para el resumen; el SID si no se puede traducir.</summary>
    private static string AccountLabel(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            return sid;
        }
    }

    internal static class Native
    {
        public const int WTSActive = 0;
        public const int WTSDisconnected = 4;
        public const int STARTF_USESHOWWINDOW = 0x00000001;
        public const short SW_HIDE = 0;
        public const uint WAIT_OBJECT_0 = 0x00000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public int State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true, EntryPoint = "WTSEnumerateSessionsW")]
        public static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version,
            out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    }
}
