// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SessionScreenCapture.cs
//
// ADR-0006 — lanza tracenium-screencap.exe DENTRO de la sesión interactiva
// del usuario y habla con él por stdin/stdout.
//
// EL PROBLEMA QUE RESUELVE: el PrivSvc corre como LocalSystem, o sea en la
// Sesión 0, que desde Vista no tiene escritorio interactivo. DXGI Desktop
// Duplication captura el escritorio de la sesión donde vive quien llama, así
// que desde aquí siempre responde "no hay escritorio" haya o no usuario
// conectado. Medido en W11-JPR-Lab01: el MISMO código captura desde la
// sesión 1 y falla desde la 0.
//
// macOS y Linux ya hacían este salto (`launchctl asuser`, `runuser -u` con
// DISPLAY). Windows era la única plataforma sin él.
//
// LA SECUENCIA:
//   WTSGetActiveConsoleSessionId()  → qué sesión tiene la consola
//   WTSQueryUserToken()             → token del usuario de esa sesión
//                                     (requiere SE_TCB_NAME: LocalSystem lo tiene)
//   DuplicateTokenEx()              → token primario, que es lo que exige
//                                     CreateProcessAsUser
//   CreateEnvironmentBlock()        → entorno del usuario, no el de SYSTEM
//   CreateProcessAsUser(lpDesktop = "winsta0\\default")
//
// El proceso es de VIDA LARGA (ver Program.cs del helper): arrancar uno por
// fotograma a 5-10 fps se comería la latencia entera y perdería el estado de
// DXGI entre fotogramas, convirtiendo cada frame en un keyframe.
//
// ⚠️ Esto es P/Invoke a mano, que en este repo ya nos ha costado tres bugs
// que compilan, corren y fallan en silencio: el layout de
// DXGI_OUTDUPL_FRAME_INFO, el "True" de JsonElement, y el CharSet ausente de
// DXGI_OUTPUT_DESC. Los structs de abajo llevan CharSet.Unicode explícito y
// el orden de campos verificado contra la documentación de Win32. Cualquier
// cambio aquí merece la misma desconfianza.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

internal static class SessionScreenCapture
{
    // Cuánto esperamos una respuesta del helper. Generoso frente al coste real
    // de una captura (decenas de ms) pero muy por debajo del presupuesto IPC
    // del cliente, que es el invariante que ya nos ha mordido cinco veces:
    // job > cliente IPC > handler. Si el helper se cuelga, preferimos matarlo
    // y rearrancar a que el carril serial del pipe se atasque detrás.
    private const int ResponseTimeoutMs = 8000;

    private static readonly object Gate = new();
    private static Process? _helper;
    private static StreamWriter? _stdin;
    private static StreamReader? _stdout;
    private static uint _helperSession = uint.MaxValue;

    /// <summary>
    /// Captura un fotograma desde la sesión del usuario. Devuelve la misma
    /// forma de respuesta que ScreenCaptureDxgi.Capture, para que el llamante
    /// no distinga de dónde vino.
    /// </summary>
    public static PrivSvcResponse Capture(string reqId, int quality, bool forceFull)
    {
        lock (Gate)
        {
            try
            {
                var session = NativeMethods.WTSGetActiveConsoleSessionId();
                // 0xFFFFFFFF = no hay sesión de consola conectada. Es el único
                // caso en el que el mensaje histórico ("no user is logged in")
                // era CIERTO; durante meses se mostró también cuando sí lo había.
                if (session == 0xFFFFFFFF)
                {
                    return PrivSvcResponse.Fail(reqId, "no_interactive_desktop",
                        "No user is signed in to this device right now. " +
                        "For a headless server, use a Shell session instead.");
                }

                // Si el usuario cerró sesión y entró otro, el helper viejo
                // apunta a un escritorio que ya no existe.
                if (_helper is { HasExited: false } && _helperSession != session)
                {
                    StopHelperLocked();
                }
                if (_helper is null || _helper.HasExited)
                {
                    StartHelperLocked(session);
                }

                var request = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["quality"] = quality,
                    ["full"] = forceFull
                });

                _stdin!.Write(request);
                _stdin.Write('\n');
                _stdin.Flush();

                var readTask = _stdout!.ReadLineAsync();
                if (!readTask.Wait(ResponseTimeoutMs))
                {
                    // No podemos abandonar una lectura a medias sobre un stream
                    // compartido: el siguiente fotograma leería la respuesta de
                    // este. Tiramos el helper y que el siguiente lo rearranque.
                    StopHelperLocked();
                    return PrivSvcResponse.Fail(reqId, "screen_capture_timeout",
                        $"The screen capture helper did not respond within {ResponseTimeoutMs} ms.");
                }

                var line = readTask.Result;
                if (string.IsNullOrWhiteSpace(line))
                {
                    StopHelperLocked();
                    return PrivSvcResponse.Fail(reqId, "screen_capture_helper_gone",
                        "The screen capture helper closed its output stream.");
                }

                return ParseHelperLine(reqId, line!);
            }
            catch (Exception ex)
            {
                StopHelperLocked();
                return PrivSvcResponse.Fail(reqId, "screen_capture_failed", ex.Message);
            }
        }
    }

    /// <summary>Para el helper. Lo llama el cierre de la sesión de screen share.</summary>
    public static void Stop()
    {
        lock (Gate) StopHelperLocked();
    }

    private static PrivSvcResponse ParseHelperLine(string reqId, string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;

        var ok = root.TryGetProperty("ok", out var okEl) &&
                 okEl.ValueKind == JsonValueKind.True;
        if (!ok)
        {
            var code = root.TryGetProperty("code", out var c)
                ? c.GetString() ?? "screen_capture_failed"
                : "screen_capture_failed";
            var msg = root.TryGetProperty("message", out var m)
                ? m.GetString() ?? "capture failed"
                : "capture failed";
            return PrivSvcResponse.Fail(reqId, code, msg);
        }

        int Int(string name, int fallback) =>
            root.TryGetProperty(name, out var el) && el.TryGetInt32(out var v) ? v : fallback;

        var payload = new Dictionary<string, object?>
        {
            ["data"] = root.TryGetProperty("data", out var d) ? d.GetString() ?? "" : "",
            ["width"] = Int("width", 0),
            ["height"] = Int("height", 0),
            ["cursorX"] = Int("cursorX", -1),
            ["cursorY"] = Int("cursorY", -1)
        };
        if (root.TryGetProperty("dirty", out var dirty) &&
            dirty.ValueKind != JsonValueKind.Null)
        {
            payload["dirty"] = JsonSerializer.Deserialize<object>(dirty.GetRawText());
        }

        return PrivSvcResponse.Success(reqId, payload);
    }

    // ── Arranque del helper en la sesión del usuario ──────────────────────

    private static void StartHelperLocked(uint session)
    {
        var exe = ResolveHelperPath();
        if (exe is null)
        {
            throw new FileNotFoundException(
                "tracenium-screencap.exe not found next to the PrivSvc binary.");
        }

        if (!NativeMethods.WTSQueryUserToken(session, out var userToken))
        {
            var err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"WTSQueryUserToken failed for session {session} (Win32 {err}). " +
                "The PrivSvc must run as LocalSystem to hold SE_TCB_NAME.");
        }

        IntPtr primaryToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;
        try
        {
            // CreateProcessAsUser exige un token PRIMARIO; WTSQueryUserToken
            // devuelve uno de impersonación.
            if (!NativeMethods.DuplicateTokenEx(userToken,
                    NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    NativeMethods.SecurityImpersonation,
                    NativeMethods.TokenPrimary, out primaryToken))
            {
                throw new InvalidOperationException(
                    $"DuplicateTokenEx failed (Win32 {Marshal.GetLastWin32Error()}).");
            }

            // Sin esto el helper heredaría el entorno de SYSTEM: TEMP, APPDATA
            // y el resto apuntando a sitios que no son del usuario.
            NativeMethods.CreateEnvironmentBlock(out envBlock, primaryToken, false);

            var (childStdinRead, parentStdinWrite) = CreatePipePair(inheritRead: true);
            var (parentStdoutRead, childStdoutWrite) = CreatePipePair(inheritRead: false);

            var si = new NativeMethods.STARTUPINFO();
            si.cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>();
            // LA línea que da sentido a todo el fichero: el escritorio
            // interactivo de la ventana de estación del usuario.
            si.lpDesktop = @"winsta0\default";
            si.dwFlags = NativeMethods.STARTF_USESTDHANDLES;
            si.hStdInput = childStdinRead;
            si.hStdOutput = childStdoutWrite;
            si.hStdError = childStdoutWrite;

            var cmdline = new StringBuilder($"\"{exe}\" --serve");

            var created = NativeMethods.CreateProcessAsUser(
                primaryToken,
                null,
                cmdline,
                IntPtr.Zero,
                IntPtr.Zero,
                true, // heredar handles: es como viajan los pipes
                NativeMethods.CREATE_UNICODE_ENVIRONMENT | NativeMethods.CREATE_NO_WINDOW,
                envBlock,
                Path.GetDirectoryName(exe),
                ref si,
                out var pi);

            // Los extremos del hijo son suyos a partir de aquí. Si no los
            // cerramos, nuestro lado del pipe nunca ve EOF cuando el helper
            // muere y la lectura se cuelga hasta el timeout.
            NativeMethods.CloseHandle(childStdinRead);
            NativeMethods.CloseHandle(childStdoutWrite);

            if (!created)
            {
                var err = Marshal.GetLastWin32Error();
                NativeMethods.CloseHandle(parentStdinWrite);
                NativeMethods.CloseHandle(parentStdoutRead);
                throw new InvalidOperationException(
                    $"CreateProcessAsUser failed (Win32 {err}).");
            }

            NativeMethods.CloseHandle(pi.hThread);

            _helper = Process.GetProcessById((int)pi.dwProcessId);
            _helperSession = session;
            _stdin = new StreamWriter(
                new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    parentStdinWrite, true), FileAccess.Write),
                new UTF8Encoding(false)) { AutoFlush = false };
            _stdout = new StreamReader(
                new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    parentStdoutRead, true), FileAccess.Read),
                new UTF8Encoding(false));

            NativeMethods.CloseHandle(pi.hProcess);
        }
        finally
        {
            if (primaryToken != IntPtr.Zero) NativeMethods.CloseHandle(primaryToken);
            if (envBlock != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(envBlock);
            NativeMethods.CloseHandle(userToken);
        }
    }

    /// <summary>
    /// Crea un pipe con UN solo extremo heredable. El otro tiene que ser NO
    /// heredable: si el hijo hereda nuestro extremo, el pipe nunca cierra del
    /// todo y las lecturas se quedan esperando para siempre.
    /// </summary>
    private static (IntPtr inheritable, IntPtr ours) CreatePipePair(bool inheritRead)
    {
        var sa = new NativeMethods.SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<NativeMethods.SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = IntPtr.Zero,
            bInheritHandle = true
        };
        if (!NativeMethods.CreatePipe(out var read, out var write, ref sa, 0))
        {
            throw new InvalidOperationException(
                $"CreatePipe failed (Win32 {Marshal.GetLastWin32Error()}).");
        }
        var ours = inheritRead ? write : read;
        NativeMethods.SetHandleInformation(ours, NativeMethods.HANDLE_FLAG_INHERIT, 0);
        return inheritRead ? (read, write) : (write, read);
    }

    private static string? ResolveHelperPath()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, "tracenium-screencap.exe");
        return File.Exists(candidate) ? candidate : null;
    }

    private static void StopHelperLocked()
    {
        // Cerrar stdin es la salida ordenada: el helper sale de su bucle de
        // lectura por su cuenta. Kill() es la red por si se quedó colgado
        // dentro de una llamada a DXGI.
        try { _stdin?.Dispose(); } catch { /* ya cerrado */ }
        try { _stdout?.Dispose(); } catch { /* ya cerrado */ }
        try
        {
            if (_helper is { HasExited: false })
            {
                if (!_helper.WaitForExit(1000)) _helper.Kill(entireProcessTree: true);
            }
        }
        catch { /* murió entre la comprobación y el kill */ }
        try { _helper?.Dispose(); } catch { /* idem */ }

        _stdin = null;
        _stdout = null;
        _helper = null;
        _helperSession = uint.MaxValue;
    }

    // ── P/Invoke ──────────────────────────────────────────────────────────

    private static class NativeMethods
    {
        public const int TOKEN_ALL_ACCESS = 0xF01FF;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const int HANDLE_FLAG_INHERIT = 0x00000001;
        public const int SecurityImpersonation = 2;
        public const int TokenPrimary = 1;

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken, int dwDesiredAccess, IntPtr lpTokenAttributes,
            int impersonationLevel, int tokenType, out IntPtr phNewToken);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(
            out IntPtr hReadPipe, out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        // ⚠️ CharSet.Unicode explícito. Sin él el default es Ansi y lpDesktop
        // —que es LPWSTR— se marshalaría como ANSI: el escritorio no
        // resolvería y CreateProcessAsUser fallaría de forma opaca. Es
        // exactamente el bug que ya nos costó una tarde en DXGI_OUTPUT_DESC.
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken, string? lpApplicationName, StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        // Orden de campos verificado contra STARTUPINFOW. Un campo de más o de
        // menos aquí desplaza hStdOutput y el helper escribe en el vacío.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
    }
}
