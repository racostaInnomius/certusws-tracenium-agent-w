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

using System.Collections.Generic;
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
    /// El helper vivo está sobre `winsta0\winlogon` (pantalla de inicio de
    /// sesión) y no sobre el escritorio de un usuario.
    ///
    /// Hay que recordarlo porque el id de sesión NO cambia cuando alguien
    /// entra por la consola: sigue siendo la 1, pero el escritorio activo pasa
    /// a ser el suyo. Sin esta marca el helper se quedaría dibujando un login
    /// que ya nadie está mirando.
    /// </summary>
    private static bool _helperLogonDesktop;

    /// <summary>
    /// Lo último que dijo el control plane sobre si este equipo es un servidor
    /// clasificado como tal (`features.remoteServerConsole`).
    ///
    /// Se recuerda porque `input.inject` no lo trae: la entrada llega DESPUÉS
    /// de que la captura haya arrancado el helper, y sin esto una pulsación
    /// tiraría la sesión de login que la captura acaba de abrir.
    /// </summary>
    private static bool _serverConsoleAllowed;

    /// Último resultado del sondeo de UAC, con su momento. Ver UacPromptActive.
    /// <summary>
    /// ¿La última captura fue de la pantalla de inicio de sesión de un servidor
    /// SIN NADIE DENTRO?
    ///
    /// ⚠️ No es lo mismo que `_helperLogonDesktop`: ese también está a true
    /// mientras un aviso de UAC ocupa el escritorio seguro de una sesión CON
    /// usuario. La diferencia importa para el navegador, que con esta marca
    /// arranca en control solo — decisión del usuario, 29-sep-2026: «tu acceso
    /// sin un usuario logueado ya implica tomar el control de teclado y
    /// mouse». Con alguien sentado delante eso NO aplica.
    /// </summary>
    private static bool _noUserSignedIn;

    /// <summary>
    /// ¿La última captura fue la pantalla de BLOQUEO de un servidor (hay
    /// usuario, pero su sesión está bloqueada)? Viaja al navegador junto a
    /// `_noUserSignedIn`: el visor arranca en control con cualquiera de las
    /// dos. Dato, no conclusión — son dos situaciones distintas y el visor
    /// puede querer decirlas distinto.
    /// </summary>
    private static bool _consoleLocked;

    /// <summary>
    /// ¿Se ha pasado en ESTA sesión remota por una pantalla de Windows (login
    /// o bloqueo)? Es lo que decide si al terminar se bloquea la consola: si el
    /// operador entró con credenciales del servidor, no se deja la sesión
    /// abierta al irse. Se pone a false en EndSession.
    /// </summary>
    private static bool _sawSignInScreen;

    // Caché del sondeo de bloqueo: se consulta en cada fotograma (5-8 por
    // segundo) y la consulta WTS no hace falta tan a menudo. Mismo criterio
    // que el de UAC.
    private static DateTime _lastLockCheckUtc = DateTime.MinValue;
    private static uint _lastLockSession = uint.MaxValue;
    private static bool _lastLocked;

    private const int WTSSessionInfoEx = 25;

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr hServer, uint sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);

    private static DateTime _lastUacCheckUtc = DateTime.MinValue;
    private static bool _uacActive;
    private static StreamReader? _stderr;

    /// <summary>
    /// Captura un fotograma desde la sesión del usuario. Devuelve la misma
    /// forma de respuesta que ScreenCaptureDxgi.Capture, para que el llamante
    /// no distinga de dónde vino.
    /// </summary>
    public static PrivSvcResponse Capture(string reqId, int quality, bool forceFull,
                                          bool serverConsole = false)
    {
        _serverConsoleAllowed = serverConsole;
        var req = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["kind"] = "capture",
            ["quality"] = quality,
            ["full"] = forceFull
        });
        var (line, error) = Exchange(reqId, req);
        if (error is not null) return error;

        var response = ParseHelperLine(reqId, line!);
        // El helper no sabe en qué sesión le pusieron; lo sabe quien lo lanzó.
        if (response.Ok && response.Result is Dictionary<string, object?> result)
        {
            result["noUserSignedIn"] = _noUserSignedIn;
            result["consoleLocked"] = _consoleLocked;
        }
        return response;
    }

    /// <summary>
    /// Inyecta teclado/ratón en la sesión del usuario.
    ///
    /// SendInput encola en el escritorio al que está adjunto el HILO QUE LLAMA.
    /// Un hilo de la Sesión 0 no está adjunto a winsta0\default, así que la
    /// entrada se iba al vacío: el operador veía "Controlling" encendido y el
    /// escritorio remoto quieto. Es el mismo problema de sesión que la captura,
    /// y tenía escrita la misma premisa falsa en su cabecera ("still works from
    /// Session 0 in most modern Windows builds"). Pasa por el helper, que sí
    /// vive en la sesión del usuario.
    /// </summary>
    public static PrivSvcResponse Inject(PrivSvcRequest req)
    {
        var payload = new Dictionary<string, object?> { ["kind"] = "input" };
        foreach (var kv in req.Params ?? new Dictionary<string, object>())
        {
            payload[kv.Key] = kv.Value;
        }

        var (line, error) = Exchange(req.Id, JsonSerializer.Serialize(payload));
        if (error is not null) return error;

        using var doc = JsonDocument.Parse(line!);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True)
        {
            return PrivSvcResponse.Success(req.Id, new Dictionary<string, object?> { ["injected"] = true });
        }
        return PrivSvcResponse.Fail(req.Id,
            root.TryGetProperty("code", out var c) ? c.GetString() ?? "input_inject_error" : "input_inject_error",
            root.TryGetProperty("message", out var m) ? m.GetString() ?? "input injection failed" : "input injection failed");
    }

    /// <summary>
    /// Manda una línea de petición al helper y devuelve su línea de respuesta.
    /// Arranca el helper si hace falta. Serializado por `Gate`: el pipe es un
    /// carril único y dos peticiones a la vez leerían la respuesta de la otra.
    /// </summary>
    /// <summary>
    /// Devuelve el token ELEVADO del mismo usuario, si lo hay.
    ///
    /// Solo tiene sentido cuando el token de entrada es el filtrado de un
    /// administrador bajo UAC (TokenElevationTypeLimited). Un usuario estándar
    /// —o un equipo con UAC apagado— no tiene token enlazado, y ahí devolver
    /// false es la respuesta correcta, no un fallo.
    ///
    /// No lanza nunca. Perder la elevación cuesta no poder controlar ventanas
    /// elevadas; lanzar costaría la sesión entera, que es peor.
    /// </summary>
    private static bool TryGetLinkedToken(IntPtr userToken, out IntPtr linked)
    {
        linked = IntPtr.Zero;
        var buf = IntPtr.Zero;
        try
        {
            // 1) ¿Es un token filtrado por UAC?
            buf = Marshal.AllocHGlobal(sizeof(int));
            if (!NativeMethods.GetTokenInformation(
                    userToken, NativeMethods.TokenElevationType,
                    buf, sizeof(int), out _))
            {
                return false;
            }
            var elevationType = Marshal.ReadInt32(buf);
            if (elevationType != NativeMethods.TokenElevationTypeLimited)
            {
                // Ya elevado, o sin token dividido. En ninguno de los dos casos
                // hay nada que pedir.
                return false;
            }
            Marshal.FreeHGlobal(buf);

            // 2) El token enlazado. Viene como HANDLE, así que el búfer es del
            //    tamaño de un puntero — no de un int. En x64 pedir 4 bytes aquí
            //    fallaría con ERROR_INSUFFICIENT_BUFFER y la elevación se
            //    perdería en silencio.
            buf = Marshal.AllocHGlobal(IntPtr.Size);
            if (!NativeMethods.GetTokenInformation(
                    userToken, NativeMethods.TokenLinkedToken,
                    buf, IntPtr.Size, out _))
            {
                return false;
            }
            linked = Marshal.ReadIntPtr(buf);
            return linked != IntPtr.Zero;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static (string? line, PrivSvcResponse? error) Exchange(string reqId, string requestJson)
    {
        lock (Gate)
        {
            try
            {
                var picked = PickInteractiveSession();
                uint session;
                var logonDesktop = false;

                if (picked is not null)
                {
                    session = picked.Value;
                    _noUserSignedIn = false;

                    // ⭐ Consola BLOQUEADA en un servidor: se trata igual que
                    // «sin nadie dentro» — decisión del usuario, 29-sep-2026.
                    // Muy común en servidores: alguien entró, se fue y la
                    // sesión se bloqueó sola. Sin esto el helper se quedaba en
                    // el escritorio del usuario, la pantalla de bloqueo vive en
                    // Winlogon, y el operador veía negro y tecleaba a ciegas.
                    //
                    // Las MISMAS dos condiciones que la pantalla de inicio de
                    // sesión: clasificado como servidor por el portal y SKU de
                    // servidor según Windows. En el portátil de nadie.
                    _consoleLocked = ServerConsoleLocked(session);
                    if (_consoleLocked)
                    {
                        logonDesktop = true;
                        _sawSignInScreen = true;
                    }
                    else
                    {
                        // ⭐ UAC vive en el escritorio SEGURO. Mientras el aviso
                        // esté abierto el helper tiene que estar allí, o el
                        // operador ve negro justo cuando la máquina pide permiso.
                        // Al contestarlo, `consent.exe` desaparece y la comparación
                        // de abajo devuelve el helper al escritorio del usuario.
                        logonDesktop = UacPromptActive(session);
                    }
                }
                else
                {
                    // ⭐ Nadie dentro. En un SERVIDOR eso no es el final: se
                    // enseña su propia pantalla de inicio de sesión para que el
                    // operador entre con credenciales DE ESA MÁQUINA. Windows
                    // es la puerta — la que sustituye al consentimiento en un
                    // equipo donde no hay a quién preguntar.
                    //
                    // DOS condiciones, y hacen falta las dos:
                    //
                    //  · el control plane dice que este equipo es un servidor
                    //    CLASIFICADO como tal (lista positiva; un equipo sin
                    //    clasificar no la trae). Es la decisión de gobierno.
                    //  · y el propio Windows dice que es una SKU de servidor.
                    //    Es la salvaguarda técnica: un error clasificando no
                    //    puede encender esto en el portátil de nadie.
                    // ⚠️ El mensaje dice QUÉ CONDICIÓN falló, con el dato.
                    //
                    // La primera versión devolvía un texto único para las dos,
                    // y costó una ronda entera de despliegue no poder
                    // distinguirlas: con el equipo clasificado como servidor,
                    // la política confirmada con sufijo `-sv0` y el agente en
                    // 1.1.84, seguía diciendo «no hay nadie» sin decir por qué.
                    // Es el mismo error que ya cometimos con el consentimiento
                    // y con el 1008: afirmar una conclusión en vez de reportar
                    // el dato. Un mensaje que no se puede accionar cuesta un
                    // despliegue por intento.
                    if (!_serverConsoleAllowed)
                    {
                        return (null, PrivSvcResponse.Fail(reqId, "no_interactive_desktop",
                            "Nobody is signed in to this device, and the control plane has not " +
                            "marked it as a server, so there is no sign-in screen to show. " +
                            "Check that its effective policy carries features.remoteServerConsole " +
                            "(its version then ends in '-sv' plus a hash). Meanwhile a Shell " +
                            "session works."));
                    }
                    var sku = WindowsProductType();
                    if (!IsServerProductType(sku))
                    {
                        return (null, PrivSvcResponse.Fail(reqId, "no_interactive_desktop",
                            "Nobody is signed in to this device. It is classified as a server, " +
                            $"but Windows reports ProductType='{sku ?? "(unreadable)"}' — only " +
                            "'ServerNT' or 'LanmanNT' get the sign-in screen, so a wrong " +
                            "classification cannot switch this on for somebody's laptop. " +
                            "A Shell session works."));
                    }

                    var console = NativeMethods.WTSGetActiveConsoleSessionId();
                    if (console == 0xFFFFFFFF || console == 0)
                    {
                        return (null, PrivSvcResponse.Fail(reqId, "no_interactive_desktop",
                            "This server has no console session attached right now, so there is " +
                            "no sign-in screen to show. Use a Shell session instead."));
                    }
                    session = console;
                    logonDesktop = true;
                    _noUserSignedIn = true;
                    _consoleLocked = false;
                    _sawSignInScreen = true;
                }

                // Si el usuario cerró sesión y entró otro, el helper viejo
                // apunta a un escritorio que ya no existe.
                //
                // ⚠️ Y también al REVÉS, que es el caso nuevo: alguien acaba de
                // autenticarse en la consola. El id de sesión no cambia —sigue
                // siendo la 1— pero el escritorio activo pasa a ser el suyo, así
                // que un helper que siga en `winlogon` dibujaría un login que ya
                // nadie mira. Por eso se compara también el escritorio.
                if (_helper is { HasExited: false } &&
                    (_helperSession != session || _helperLogonDesktop != logonDesktop))
                {
                    StopHelperLocked();
                }
                if (_helper is null || _helper.HasExited)
                {
                    StartHelperLocked(session, logonDesktop);
                }

                _stdin!.Write(requestJson);
                _stdin.Write('\n');
                _stdin.Flush();

                var readTask = _stdout!.ReadLineAsync();
                if (!readTask.Wait(ResponseTimeoutMs))
                {
                    // No podemos abandonar una lectura a medias sobre un stream
                    // compartido: la siguiente petición leería la respuesta de
                    // esta. Tiramos el helper y que la siguiente lo rearranque.
                    StopHelperLocked();
                    return (null, PrivSvcResponse.Fail(reqId, "screen_capture_timeout",
                        $"The session helper did not respond within {ResponseTimeoutMs} ms."));
                }

                var line = readTask.Result;
                // Cinturón además de tirantes: stderr ya va por su propio pipe,
                // pero si algo vuelve a escribir texto suelto en stdout preferimos
                // un error nuestro y legible al del parser de JSON.
                if (line is not null && line.Length > 0 && line[0] != '{')
                {
                    IpcLog.Write($"[screencap helper] salida no-JSON en stdout: {line}");
                    StopHelperLocked();
                    return (null, PrivSvcResponse.Fail(reqId, "screen_capture_failed",
                        "The session helper wrote unexpected output. See the PrivSvc log."));
                }
                if (string.IsNullOrWhiteSpace(line))
                {
                    StopHelperLocked();
                    return (null, PrivSvcResponse.Fail(reqId, "screen_capture_helper_gone",
                        "The session helper closed its output stream."));
                }

                return (line, null);
            }
            catch (NoInteractiveUserException ex)
            {
                // Mismo código que el guardia de `0xFFFFFFFF`: para quien mira
                // el portal las dos cosas son «aquí no hay nadie», y darles
                // códigos distintos sólo reparte la misma causa en dos sitios.
                StopHelperLocked();
                return (null, PrivSvcResponse.Fail(reqId, "no_interactive_desktop", ex.Message));
            }
            catch (Exception ex)
            {
                StopHelperLocked();
                return (null, PrivSvcResponse.Fail(reqId, "screen_capture_failed", ex.Message));
            }
        }
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

        // full/x/y/rw/rh son el contrato de los rects sucios y tienen que
        // llegar enteros hasta el navegador. Con full:false, `data` es SOLO la
        // región cambiada y (x,y) dice dónde pegarla; sin esos campos el
        // canvas pinta un recorte creyendo que es la pantalla completa. Este
        // bloque también los perdía —buscaba una propiedad "dirty" que no
        // existe— y el resultado era el mismo que en el helper: ventanas
        // duplicadas y desplazadas al tomar el control.
        var full = !root.TryGetProperty("full", out var fEl) ||
                   fEl.ValueKind != JsonValueKind.False;

        var payload = new Dictionary<string, object?>
        {
            ["data"] = root.TryGetProperty("data", out var d) ? d.GetString() ?? "" : "",
            ["width"] = Int("width", 0),
            ["height"] = Int("height", 0),
            ["full"] = full,
            ["x"] = Int("x", 0),
            ["y"] = Int("y", 0),
            ["rw"] = Int("rw", Int("width", 0)),
            ["rh"] = Int("rh", Int("height", 0)),
            ["cursorX"] = Int("cursorX", -1),
            ["cursorY"] = Int("cursorY", -1)
        };

        return PrivSvcResponse.Success(reqId, payload);
    }

    /// <summary>
    /// La sesión de consola existe pero no tiene usuario dentro.
    ///
    /// Se distingue de un fallo de verdad para que el operador lea «no hay
    /// nadie conectado» y no un error de configuración: son acciones
    /// completamente distintas.
    /// </summary>
    internal sealed class NoInteractiveUserException : Exception
    {
        public NoInteractiveUserException(string message) : base(message) { }
    }

    /// <summary>
    /// ¿Hay un aviso de UAC en pantalla ahora mismo, en esta sesión?
    ///
    /// ── El problema ─────────────────────────────────────────────────
    ///
    /// UAC no dibuja sobre el escritorio del usuario: cambia al escritorio
    /// SEGURO (`winsta0\winlogon`). El helper está adjunto a
    /// `winsta0\default`, así que en cuanto sale el aviso DXGI pierde el
    /// acceso y la reserva de GDI copia un escritorio que ya no se está
    /// componiendo. El operador ve un fotograma negro o congelado justo cuando
    /// la máquina le está pidiendo permiso para algo, y no puede ni leerlo ni
    /// contestarlo.
    ///
    /// ── Por qué se busca `consent.exe` y no el escritorio ────────────
    ///
    /// Lo natural sería preguntar cuál es el escritorio de entrada. No se
    /// puede desde aquí: este servicio vive en la sesión 0, cuya estación de
    /// ventanas no es la del usuario. Y desde el helper tampoco, porque corre
    /// como el usuario y el escritorio seguro sólo lo abre SYSTEM — el propio
    /// fallo sería la señal, pero es la MISMA señal que da la pantalla de
    /// bloqueo.
    ///
    /// Y esa diferencia importa mucho: la pantalla de bloqueo también vive en
    /// el escritorio seguro. Saltar allí en cuanto se pierde el acceso
    /// convertiría esto en «mirar a alguien teclear su contraseña al
    /// desbloquear», que es exactamente lo que el consentimiento existe para
    /// impedir. `consent.exe` sólo existe mientras hay un aviso de UAC
    /// abierto: es la señal ESPECÍFICA, no la genérica.
    ///
    /// ⚠️ Con sondeo acotado a 500 ms. Esto se consulta en el camino de cada
    /// fotograma —hasta treinta por segundo— y enumerar procesos en cada uno
    /// sería un coste permanente por una condición que dura segundos. Medio
    /// segundo de negro antes de saltar es un precio que se paga.
    /// </summary>
    private static bool UacPromptActive(uint session)
    {
        var now = DateTime.UtcNow;
        if ((now - _lastUacCheckUtc).TotalMilliseconds < 500) return _uacActive;
        _lastUacCheckUtc = now;

        var found = false;
        try
        {
            foreach (var proc in Process.GetProcessesByName("consent"))
            {
                try
                {
                    if ((uint)proc.SessionId == session) found = true;
                }
                catch
                {
                    // El proceso murió entre la enumeración y la consulta: es
                    // justo lo que hace un aviso que se acaba de contestar.
                }
                finally
                {
                    proc.Dispose();
                }
                if (found) break;
            }
        }
        catch
        {
            // Sin poder enumerar no se salta al escritorio seguro. Fallar hacia
            // "no hay UAC" deja un fotograma negro; fallar al revés pondría al
            // operador en el escritorio seguro sin motivo.
            found = false;
        }
        _uacActive = found;
        return found;
    }

    /// <summary>
    /// ¿Windows dice que esto es un servidor?
    ///
    /// Salvaguarda TÉCNICA, aparte de la decisión de gobierno. Enseñar la
    /// pantalla de inicio de sesión exige que el control plane haya
    /// clasificado el equipo como servidor, pero una clasificación es un dato
    /// editable: si alguien se equivoca —o la cambia a mano— eso no puede
    /// acabar encendiendo el escritorio seguro en el portátil de una persona.
    /// Aquí lo dice el propio sistema operativo, que nadie edita desde el
    /// portal.
    ///
    /// `ProductType` del registro: `WinNT` = estación de trabajo,
    /// `ServerNT` / `LanmanNT` = servidor. Se lee del registro y no por WMI
    /// porque esto corre en el camino de cada fotograma fallido y una consulta
    /// WMI cuesta órdenes de magnitud más.
    ///
    /// Ante la duda —clave ilegible— se responde NO: no encender una función
    /// privilegiada por no haber podido leer una cadena.
    /// </summary>
    /// El dato crudo, para poder decirlo en el mensaje. `null` = ilegible.
    internal static string? WindowsProductType()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\ProductOptions");
            return key?.GetValue("ProductType") as string;
        }
        catch
        {
            return null;
        }
    }

    /// El juicio, separado del dato: así el mensaje puede enseñar lo que leyó
    /// en vez de dejar al operador adivinando qué vio el equipo.
    internal static bool IsServerProductType(string? value)
    {
        return string.Equals(value, "ServerNT", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "LanmanNT", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWindowsServerSku() => IsServerProductType(WindowsProductType());

    /// <summary>
    /// Qué sesión se captura.
    ///
    /// 🔴 Antes era siempre `WTSGetActiveConsoleSessionId()`, y en un servidor
    /// eso es casi siempre la sesión equivocada.
    ///
    /// Windows Server es multiusuario por definición: quien administra entra
    /// por RDP, y RDP crea una sesión NUEVA. La consola se queda en la pantalla
    /// de inicio de sesión, vacía. Así que con un administrador trabajando
    /// dentro del servidor, mirábamos la consola, no encontrábamos usuario y
    /// devolvíamos Win32 1008 — «no hay nadie» cuando sí había alguien.
    /// Medido en TNS-OPER-SNOC04 (T1, 26-sep-2026).
    ///
    /// Orden de preferencia, y el porqué de cada paso:
    ///
    ///   1. La consola, SI tiene usuario. Es la pantalla física del equipo: en
    ///      un portátil o un sobremesa es la única que existe, y en un servidor
    ///      con alguien delante es la que esa persona está usando.
    ///   2. Si no, una sesión ACTIVA con usuario — el caso RDP. Por id
    ///      ascendente para que dos peticiones seguidas vean lo mismo: elegir
    ///      «la más reciente» haría saltar al operador de escritorio a mitad de
    ///      una intervención cada vez que alguien se conecta.
    ///
    /// ⚠️ NO se cae a sesiones DESCONECTADAS. Existen y tienen token, pero su
    /// escritorio no se está componiendo: se capturaría un fotograma congelado
    /// o negro, que es peor que decir que no hay nadie — el operador lo
    /// diagnosticaría como «la captura está rota».
    ///
    /// ⚠️ La sesión 0 es la de servicios y no tiene escritorio de usuario.
    /// Nunca se elige.
    /// </summary>
    private static uint? PickInteractiveSession()
    {
        var console = NativeMethods.WTSGetActiveConsoleSessionId();
        if (console != 0xFFFFFFFF && console != 0 && HasUserToken(console))
        {
            return console;
        }

        if (!UserScopedUninstall.Native.WTSEnumerateSessions(IntPtr.Zero, 0, 1,
                                                             out var buffer, out var count))
        {
            IpcLog.Write("[screencap] WTSEnumerateSessions falló (Win32 " +
                         Marshal.GetLastWin32Error() + "); sin candidatos alternativos");
            return null;
        }
        try
        {
            var size = Marshal.SizeOf<UserScopedUninstall.Native.WTS_SESSION_INFO>();
            var actives = new List<uint>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<UserScopedUninstall.Native.WTS_SESSION_INFO>(
                    buffer + i * size);
                if (info.SessionId <= 0) continue;                       // 0 = servicios
                if (info.State != UserScopedUninstall.Native.WTSActive) continue;
                actives.Add((uint)info.SessionId);
            }
            actives.Sort();
            foreach (var s in actives)
            {
                if (HasUserToken(s))
                {
                    IpcLog.Write($"[screencap] la consola no tiene usuario; se captura la sesión {s}");
                    return s;
                }
            }
        }
        finally
        {
            UserScopedUninstall.Native.WTSFreeMemory(buffer);
        }
        return null;
    }

    /// <summary>
    /// ¿Es `session` la consola BLOQUEADA de un servidor clasificado?
    ///
    /// Las MISMAS condiciones que la pantalla de inicio de sesión, en el mismo
    /// orden de coste: la clasificación del portal (gratis), que sea la sesión
    /// de consola, la SKU de servidor según Windows, y por último el sondeo WTS.
    ///
    /// ⚠️ Sólo la sesión de CONSOLA. Una sesión RDP bloqueada es de alguien
    /// conectado desde otro sitio; «consola bloqueada» es lo que se decidió, y
    /// es lo que después se bloquea al salir. La consola aquí sólo se COMPARA
    /// con la sesión ya elegida — nunca la sustituye: eso reabriría el 1008.
    /// </summary>
    private static bool ServerConsoleLocked(uint session) =>
        _serverConsoleAllowed
        && session == NativeMethods.WTSGetActiveConsoleSessionId()
        && IsWindowsServerSku()
        && SessionLocked(session);

    /// <summary>
    /// ¿Está bloqueada esta sesión? WTSINFOEX nivel 1, `SessionFlags`.
    /// Cacheado 500 ms salvo `fresh`. Cualquier fallo cuenta como NO
    /// bloqueada: ante la duda no se toma la pantalla de bloqueo de nadie.
    /// La disposición de la estructura está fijada por una prueba — ver
    /// SignInScreenShape.
    /// </summary>
    private static bool SessionLocked(uint session, bool fresh = false)
    {
        var now = DateTime.UtcNow;
        if (!fresh && session == _lastLockSession &&
            (now - _lastLockCheckUtc).TotalMilliseconds < 500)
        {
            return _lastLocked;
        }

        var locked = false;
        var buf = IntPtr.Zero;
        try
        {
            if (WTSQuerySessionInformationW(IntPtr.Zero, session, WTSSessionInfoEx,
                                            out buf, out _) && buf != IntPtr.Zero)
            {
                var info = Marshal.PtrToStructure<WtsInfoEx>(buf);
                if (info.Level == 1) locked = SignInScreenShape.IsLocked(info.Data.SessionFlags);
            }
        }
        catch
        {
            locked = false;
        }
        finally
        {
            if (buf != IntPtr.Zero) UserScopedUninstall.Native.WTSFreeMemory(buf);
        }

        _lastLockSession = session;
        _lastLockCheckUtc = now;
        _lastLocked = locked;
        return locked;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSDisconnectSession(IntPtr hServer, uint sessionId, bool wait);

    /// <summary>
    /// Fin de la sesión de screen share: para el helper y, si el operador
    /// entró por una pantalla de Windows, bloquea la consola.
    ///
    /// 🔴 Antes no lo llamaba NADIE: `Stop()` no tenía ni una llamada y el
    /// helper tampoco caducaba, así que seguía vivo indefinidamente al
    /// terminar la sesión — en el caso del login, un proceso SYSTEM pegado al
    /// escritorio seguro. Ahora lo llama el agente al cerrar la última sesión
    /// de pantalla del equipo (`screen.end`).
    ///
    /// «Bloquear» es `WTSDisconnectSession` sobre la consola —lo que hace
    /// `tsdiscon`—: la sesión sigue viva con sus procesos, la consola vuelve a
    /// «Presiona Ctrl+Alt+Supr», y entrar con ese usuario la retoma. Se hace
    /// desde el servicio y no con LockWorkStation desde el helper porque ése
    /// exige estar en el escritorio del usuario, y al terminar el helper puede
    /// seguir en Winlogon.
    /// </summary>
    public static PrivSvcResponse EndSession(string reqId)
    {
        lock (Gate)
        {
            var locked = false;
            string? note = null;
            try
            {
                if (_sawSignInScreen)
                {
                    var console = NativeMethods.WTSGetActiveConsoleSessionId();
                    var hasUser = console != 0xFFFFFFFF && console != 0 && HasUserToken(console);
                    var isLocked = hasUser && SessionLocked(console, fresh: true);
                    if (SignInScreenShape.ShouldLockOnEnd(true, hasUser, isLocked))
                    {
                        locked = WTSDisconnectSession(IntPtr.Zero, console, false);
                        if (!locked) note = $"WTSDisconnectSession failed ({Marshal.GetLastWin32Error()})";
                        IpcLog.Write(locked
                            ? $"[screencap] fin de sesión: se entró por la pantalla de Windows; consola {console} bloqueada"
                            : $"[screencap] fin de sesión: NO se pudo bloquear la consola {console}: {note}");
                    }
                }
            }
            catch (Exception ex)
            {
                note = ex.Message;
            }
            finally
            {
                StopHelperLocked();
                _sawSignInScreen = false;
                _noUserSignedIn = false;
                _consoleLocked = false;
                _lastLockSession = uint.MaxValue;
            }

            return PrivSvcResponse.Success(reqId, new Dictionary<string, object?>
            {
                ["stopped"] = true,
                ["consoleLocked"] = locked,
                ["note"] = note
            });
        }
    }

    /// <summary>¿Hay un usuario con token en esta sesión? Sin efectos.</summary>
    private static bool HasUserToken(uint session)
    {
        if (!NativeMethods.WTSQueryUserToken(session, out var token)) return false;
        NativeMethods.CloseHandle(token);
        return true;
    }

    // ── Arranque del helper en la sesión del usuario ──────────────────────

    private static void StartHelperLocked(uint session, bool logonDesktop = false)
    {
        var exe = ResolveHelperPath();
        if (exe is null)
        {
            throw new FileNotFoundException(
                "tracenium-screencap.exe not found next to the PrivSvc binary.");
        }

        IntPtr userToken;
        if (logonDesktop)
        {
            // No hay usuario al que pedirle token: se usa el del PROPIO
            // servicio (LocalSystem) y más abajo se le mueve la sesión. Es
            // cómo se llega al escritorio de inicio de sesión, que no
            // pertenece a nadie.
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                    NativeMethods.TOKEN_ALL_ACCESS, out userToken))
            {
                throw new InvalidOperationException(
                    $"OpenProcessToken failed (Win32 {Marshal.GetLastWin32Error()}).");
            }
        }
        else if (!NativeMethods.WTSQueryUserToken(session, out userToken))
        {
            var err = Marshal.GetLastWin32Error();

            // 🔴 El mensaje culpaba a la cuenta del servicio para CUALQUIER
            // error, y en el caso más común eso es falso.
            //
            // Visto en TNS-OPER-SNOC04 (Windows Server 2022, 26-sep-2026): el
            // operador leyó «The PrivSvc must run as LocalSystem to hold
            // SE_TCB_NAME» y se fue a mirar la cuenta del servicio, que estaba
            // perfecta. El código era 1008.
            //
            //   1008 ERROR_NO_TOKEN         → la sesión EXISTE pero no hay
            //                                 nadie dentro. Es la pantalla de
            //                                 inicio de sesión: no hay usuario
            //                                 a quien pedirle el token, y por
            //                                 tanto no hay escritorio suyo que
            //                                 capturar. No es un fallo de
            //                                 configuración.
            //   1314 ERROR_PRIVILEGE_NOT_HELD → ESE sí es el caso del mensaje
            //                                 original: sin SE_TCB_NAME.
            //
            // El guardia de arriba sólo cubre `0xFFFFFFFF` («no hay sesión de
            // consola»). Aquí hay sesión —la 1— y está vacía, que es el estado
            // normal de un servidor sin monitor. Es la tercera vez que un
            // mensaje nuestro afirma una causa en vez de leer el código y manda
            // a buscar el fallo donde no está.
            const int ERROR_NO_TOKEN = 1008;
            const int ERROR_PRIVILEGE_NOT_HELD = 1314;

            if (err == ERROR_NO_TOKEN)
            {
                throw new NoInteractiveUserException(
                    $"Nobody is signed in on this device (console session {session} has no user). " +
                    "Screen sharing shows a signed-in user's desktop, so there is nothing to show " +
                    "yet. Sign in — locally or over RDP — and try again, or use a Shell session, " +
                    "which does not need a desktop.");
            }
            if (err == ERROR_PRIVILEGE_NOT_HELD)
            {
                throw new InvalidOperationException(
                    $"WTSQueryUserToken was denied for session {session} (Win32 {err}). " +
                    "The PrivSvc must run as LocalSystem to hold SE_TCB_NAME.");
            }
            throw new InvalidOperationException(
                $"WTSQueryUserToken failed for session {session} (Win32 {err}).");
        }

        IntPtr primaryToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;
        try
        {
            // CreateProcessAsUser exige un token PRIMARIO; WTSQueryUserToken
            // devuelve uno de impersonación.
            // ⚠️ El token que hay que duplicar NO es siempre el que devuelve
            // WTSQueryUserToken.
            //
            // Para un administrador con UAC, ese token es el FILTRADO: integridad
            // MEDIA. Y UIPI —User Interface Privilege Isolation— impide que un
            // proceso de integridad media mande entrada sintética a una ventana
            // ELEVADA. Resultado en campo: con la consola de servicios o un cmd
            // "como administrador" en primer plano, el operador dejaba de poder
            // mover el cursor; al cerrar esa ventana, el control volvía solo.
            // SendInput devolvía 0 y nadie lo miraba, así que no había ni una
            // línea de log que lo explicara.
            //
            // Se pide el token ENLAZADO (el elevado del mismo usuario) cuando
            // existe. No es un privilegio nuevo para el producto: PrivSvc ya
            // corre como LocalSystem, estrictamente por encima.
            //
            // Si el usuario NO es admin —o UAC está apagado— no hay token
            // enlazado y se sigue con el filtrado. Es correcto: en ese equipo
            // tampoco hay ventanas elevadas que controlar. Cualquier fallo aquí
            // cae al camino de siempre; quedarse sin sesión por no poder elevar
            // sería peor que no poder controlar una ventana de servicios.
            // Sin usuario no hay token enlazado que buscar: el del servicio ya
            // es LocalSystem, que está estrictamente por encima de cualquier
            // elevación.
            // ⚠️ Declarado fuera: con `&&` en cortocircuito, `linkedToken`
            // quedaría sin asignar cuando el escritorio es el de login y el
            // compilador —con razón— lo rechaza.
            IntPtr linkedToken = IntPtr.Zero;
            var sourceToken = !logonDesktop && TryGetLinkedToken(userToken, out linkedToken)
                ? linkedToken
                : userToken;

            try
            {
                if (!NativeMethods.DuplicateTokenEx(sourceToken,
                        NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                        NativeMethods.SecurityImpersonation,
                        NativeMethods.TokenPrimary, out primaryToken))
                {
                    throw new InvalidOperationException(
                        $"DuplicateTokenEx failed (Win32 {Marshal.GetLastWin32Error()}).");
                }

                if (logonDesktop)
                {
                    // ⚠️ El token del servicio vive en la sesión 0, que no tiene
                    // escritorio. Sin moverlo, el proceso arrancaría allí y no
                    // vería la pantalla de inicio de sesión. Esto es lo que
                    // exige SE_TCB_NAME, y por eso el PrivSvc corre como
                    // LocalSystem — aquí el mensaje sobre SE_TCB_NAME sí es el
                    // correcto.
                    var target = session;
                    if (!NativeMethods.SetTokenInformation(primaryToken,
                            NativeMethods.TokenSessionId, ref target, sizeof(uint)))
                    {
                        throw new InvalidOperationException(
                            "SetTokenInformation(TokenSessionId) failed " +
                            $"(Win32 {Marshal.GetLastWin32Error()}). The PrivSvc must run as " +
                            "LocalSystem to hold SE_TCB_NAME.");
                    }
                }
            }
            finally
            {
                if (linkedToken != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(linkedToken);
                }
            }

            // Sin esto el helper heredaría el entorno de SYSTEM: TEMP, APPDATA
            // y el resto apuntando a sitios que no son del usuario.
            NativeMethods.CreateEnvironmentBlock(out envBlock, primaryToken, false);

            // Acceso por NOMBRE, no por posición. Esto era una desestructuración
            // posicional y el par de stdout estaba cruzado: `parentStdoutRead`
            // acababa siendo el extremo de ESCRITURA, y abrir un FileStream de
            // lectura sobre él da "Access to the path is denied" envuelto en un
            // AggregateException — un mensaje que no menciona pipes por ningún
            // lado. La tupla invierte su significado según el booleano, así que
            // el orden correcto no es evidente al leer la llamada.
            var stdinPipe = CreatePipePair(inheritRead: true);   // el hijo LEE
            var stdoutPipe = CreatePipePair(inheritRead: false); // el hijo ESCRIBE
            // stderr necesita SU PROPIO pipe. Compartirlo con stdout mezclaba
            // los diagnósticos del helper con las líneas JSON, y el parser se
            // atragantaba: "'D' is an invalid start of a value" era literalmente
            // el "DXGI falló…" que el helper escribe antes de probar GDI. Un
            // canal de datos y un canal de texto no pueden compartir tubería.
            var stderrPipe = CreatePipePair(inheritRead: false);

            var childStdinRead = stdinPipe.childEnd;
            var parentStdinWrite = stdinPipe.ourEnd;
            var childStdoutWrite = stdoutPipe.childEnd;
            var parentStdoutRead = stdoutPipe.ourEnd;
            var childStderrWrite = stderrPipe.childEnd;
            var parentStderrRead = stderrPipe.ourEnd;

            var si = new NativeMethods.STARTUPINFO();
            si.cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>();
            // LA línea que da sentido a todo el fichero: el escritorio
            // interactivo de la ventana de estación del usuario.
            // ⭐ `winsta0\winlogon` es el escritorio SEGURO: la pantalla de
            // inicio de sesión (y el de UAC). Es el único sitio donde se puede
            // enseñar el login de un servidor sin nadie dentro.
            si.lpDesktop = logonDesktop ? @"winsta0\winlogon" : @"winsta0\default";
            si.dwFlags = NativeMethods.STARTF_USESTDHANDLES;
            si.hStdInput = childStdinRead;
            si.hStdOutput = childStdoutWrite;
            si.hStdError = childStderrWrite;

            var cmdline = new StringBuilder($"\"{exe}\" --serve");
            // En el escritorio de Windows (login, bloqueo, UAC) el helper
            // despierta la pantalla antes de la primera imagen. Ver
            // InputInjection.Nudge.
            if (logonDesktop) cmdline.Append(" --logon");

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
            NativeMethods.CloseHandle(childStderrWrite);

            if (!created)
            {
                var err = Marshal.GetLastWin32Error();
                NativeMethods.CloseHandle(parentStdinWrite);
                NativeMethods.CloseHandle(parentStdoutRead);
                NativeMethods.CloseHandle(parentStderrRead);
                throw new InvalidOperationException(
                    $"CreateProcessAsUser failed (Win32 {err}).");
            }

            NativeMethods.CloseHandle(pi.hThread);

            _helper = Process.GetProcessById((int)pi.dwProcessId);
            _helperSession = session;
            _helperLogonDesktop = logonDesktop;
            _stdin = new StreamWriter(
                new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    parentStdinWrite, true), FileAccess.Write),
                new UTF8Encoding(false)) { AutoFlush = false };
            _stdout = new StreamReader(
                new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    parentStdoutRead, true), FileAccess.Read),
                new UTF8Encoding(false));

            _stderr = new StreamReader(
                new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    parentStderrRead, true), FileAccess.Read),
                new UTF8Encoding(false));

            // Drenar stderr en su propio hilo, SIEMPRE. Un pipe que nadie lee
            // se llena y bloquea al que escribe: el helper se quedaría colgado
            // a mitad de una captura y lo veríamos como un timeout. Y de paso
            // sus diagnósticos acaban en nuestro log, que es donde se explica
            // por qué DXGI no pudo.
            var stderrReader = _stderr;
            new Thread(() =>
            {
                try
                {
                    string? l;
                    while ((l = stderrReader.ReadLine()) != null)
                    {
                        if (l.Length > 0) IpcLog.Write($"[screencap helper] {l}");
                    }
                }
                catch { /* el pipe se cerró: fin normal */ }
            })
            { IsBackground = true }.Start();

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
    private static (IntPtr childEnd, IntPtr ourEnd) CreatePipePair(bool inheritRead)
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
        // inheritRead=true  → el hijo lee: su extremo es `read`, el nuestro `write`
        // inheritRead=false → el hijo escribe: su extremo es `write`, el nuestro `read`
        var childEnd = inheritRead ? read : write;
        var ourEnd = inheritRead ? write : read;
        // Nuestro extremo NO debe heredarse. Si el hijo lo hereda, el pipe nunca
        // llega a cerrarse del todo y la lectura se queda esperando para siempre.
        NativeMethods.SetHandleInformation(ourEnd, NativeMethods.HANDLE_FLAG_INHERIT, 0);
        return (childEnd, ourEnd);
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
        try { _stderr?.Dispose(); } catch { /* ya cerrado */ }
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
        _stderr = null;
        _helper = null;
        _helperSession = uint.MaxValue;
        _helperLogonDesktop = false;
    }

    // ── P/Invoke ──────────────────────────────────────────────────────────

    /// <summary>
    /// internal, no private: TrayPresence.cs necesita el mismo salto a la
    /// sesión de consola. Se deja aquí en vez de moverlo a un fichero propio
    /// para no remover este justo antes de probar en campo el cambio del token
    /// elevado; si aparece un tercer llamador, toca extraerlo.
    /// </summary>
    internal static class NativeMethods
    {
        public const int TOKEN_ALL_ACCESS = 0xF01FF;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const int HANDLE_FLAG_INHERIT = 0x00000001;
        public const int SecurityImpersonation = 2;
        public const int TokenPrimary = 1;

        // TOKEN_INFORMATION_CLASS
        public const int TokenElevationType = 18;
        public const int TokenLinkedToken = 19;

        // TOKEN_ELEVATION_TYPE
        public const int TokenElevationTypeDefault = 1; // sin token dividido
        public const int TokenElevationTypeFull    = 2; // ya elevado
        public const int TokenElevationTypeLimited = 3; // admin filtrado por UAC

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            int TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

        /// TOKEN_INFORMATION_CLASS.TokenSessionId
        public const int TokenSessionId = 12;

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess,
                                                   out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
                                                      ref uint tokenInformation, int tokenInformationLength);

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
