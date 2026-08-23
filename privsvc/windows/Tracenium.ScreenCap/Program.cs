// privsvc/windows/Tracenium.ScreenCap/Program.cs
//
// ADR-0006 — helper de captura de pantalla que corre DENTRO de la sesión
// del usuario.
//
// POR QUÉ EXISTE: el PrivSvc corre como LocalSystem, o sea en la Sesión 0,
// que desde Windows Vista no tiene escritorio interactivo por diseño. DXGI
// Desktop Duplication captura el escritorio de la sesión donde vive el
// proceso que llama, así que desde ahí devuelve "no hay escritorio" haya o
// no un usuario conectado. Confirmado empíricamente en W11-JPR-Lab01: el
// MISMO código captura sin problemas desde la sesión 1 y falla desde la 0.
//
// Es el análogo Windows de lo que macOS y Linux ya hacían: sus privsvc
// también corren fuera de la sesión gráfica y por eso lanzan un helper
// dentro de ella (`launchctl asuser` / `runuser -u` con DISPLAY). Windows
// era la única plataforma sin ese salto.
//
// CONTRATO — idéntico al de los helpers de Mac y Linux, para que el lado
// Node no tenga que distinguir plataformas:
//
//   salida  : EXACTAMENTE una línea JSON por captura, en stdout
//             { "ok": true,  "data": "<jpeg base64>", "width": N,
//               "height": N, "cursorX": N, "cursorY": N }
//             { "ok": false, "code": "<slug>", "message": "<texto>" }
//   stderr  : texto para humanos, nunca parseado
//
// Dos modos:
//
//   --serve                  (el que usa el PrivSvc)
//       Proceso de vida larga. Lee una línea JSON de petición por stdin
//       — { "quality": 1..100, "full": true|false } — y escribe una línea
//       de respuesta por stdout. Termina cuando stdin se cierra.
//
//       Es de vida larga a propósito: screen share pide entre 5 y 10
//       fotogramas por segundo, y arrancar un proceso por fotograma
//       (~50-100 ms cada uno, más el coste del token y el entorno) se
//       come el presupuesto de latencia entero. Además DXGI mantiene
//       estado entre fotogramas — la cadena de duplicación y los rects
//       sucios — que se perdería en cada arranque, convirtiendo cada
//       frame en un keyframe completo.
//
//   --quality <n> [--full]   (una sola captura y salir)
//       Para diagnóstico manual desde una consola del usuario.
//
// stdout es SOLO líneas JSON. Cualquier otra cosa que se imprima ahí
// rompe al que parsea del otro lado; los mensajes van a stderr.

using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;

[DllImport("kernel32.dll")]
static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);
[DllImport("kernel32.dll")]
static extern uint GetCurrentProcessId();

static void Fail(string code, string message)
{
    var payload = JsonSerializer.Serialize(new
    {
        ok = false,
        code,
        message
    });
    Console.Out.Write(payload);
    Console.Out.Write('\n');
    Console.Out.Flush();
    Environment.Exit(1);
}

// ── Argumentos ────────────────────────────────────────────────────────
int quality = 80;
bool forceFull = false;
bool serve = false;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--quality":
            if (i + 1 < args.Length &&
                int.TryParse(args[i + 1], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var q))
            {
                quality = Math.Max(1, Math.Min(100, q));
                i++;
            }
            break;
        case "--full":
            forceFull = true;
            break;
        case "--serve":
            serve = true;
            break;
    }
}

// ── Guardia de sesión ─────────────────────────────────────────────────
// Si alguien lanza el helper desde la Sesión 0 estamos exactamente en el
// escenario que este binario existe para evitar. Mejor decirlo con un
// código propio que devolver el genérico de DXGI, que ya nos mandó a
// buscar adaptadores de vídeo que no tenían nada roto.
ProcessIdToSessionId(GetCurrentProcessId(), out var mySession);
if (mySession == 0)
{
    Fail("screen_capture_helper_in_session0",
        "The screen capture helper is running in Session 0. It must be " +
        "launched inside the interactive user session (see ADR-0006).");
}

// ── Captura ───────────────────────────────────────────────────────────
// DXGI primero; GDI BitBlt como reserva. La sonda de ADR-0006 comprobó que
// ambos funcionan desde la sesión del usuario, así que el fallback no es
// teórico: cubre los adaptadores que de verdad no soportan Desktop
// Duplication, que es lo que DXGI_ERROR_UNSUPPORTED significa.
static string CaptureOnce(int quality, bool forceFull)
{
    PrivSvcResponse? result = null;
    string? code = null;
    string? message = null;

    try
    {
        result = ScreenCaptureDxgi.Capture("helper", quality, forceFull);
        if (result is { Ok: false })
        {
            code = result.Error?.Code;
            message = result.Error?.Message;
            result = null;
        }
    }
    catch (Exception ex)
    {
        code = "screen_capture_failed";
        message = ex.Message;
    }

    if (result is null)
    {
        Console.Error.WriteLine($"DXGI falló ({code}): {message} — probando GDI");
        try
        {
            result = ScreenCapture.Capture("helper", quality);
            if (result is { Ok: false }) result = null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"GDI también falló: {ex.Message}");
            result = null;
        }
    }

    if (result?.Result is null)
    {
        // Los dos caminos fallaron. Reportamos el error de DXGI, que es el
        // informativo: GDI casi siempre falla por lo mismo y con menos detalle.
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["ok"] = false,
            ["code"] = code ?? "screen_capture_failed",
            ["message"] = message ?? "capture failed"
        });
    }

    // El Result de los capturadores es un objeto anónimo. Lo reserializamos
    // por reflexión para no acoplarnos a su forma exacta ni arrastrar campos
    // internos si mañana crece.
    var src = result.Result;
    object? Prop(string name) => src.GetType().GetProperty(name)?.GetValue(src);

    var payload = new Dictionary<string, object?>
    {
        ["ok"] = true,
        ["data"] = Prop("data") ?? "",
        ["width"] = Prop("width") ?? 0,
        ["height"] = Prop("height") ?? 0,
        ["cursorX"] = Prop("cursorX") ?? -1,
        ["cursorY"] = Prop("cursorY") ?? -1
    };
    // Los rects sucios son opcionales: solo viajan si el capturador los emitió.
    var dirty = Prop("dirty");
    if (dirty is not null) payload["dirty"] = dirty;
    return JsonSerializer.Serialize(payload);
}

// ── Inyección de entrada ──────────────────────────────────────────────
// Mismo motivo que la captura: SendInput encola en el escritorio al que está
// adjunto el hilo que llama. Desde la Sesión 0 ese escritorio no es el del
// usuario, así que el clic se iba al vacío — el operador veía el botón
// "Controlling" encendido y nada se movía.
static string InjectOnce(Dictionary<string, object>? p)
{
    try
    {
        var res = InputInjection.Inject(new PrivSvcRequest
        {
            Id = "helper",
            Method = "input.inject",
            Params = p ?? new Dictionary<string, object>()
        });
        if (res is { Ok: true })
        {
            return JsonSerializer.Serialize(new Dictionary<string, object?> { ["ok"] = true });
        }
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["ok"] = false,
            ["code"] = res?.Error?.Code ?? "input_inject_error",
            ["message"] = res?.Error?.Message ?? "input injection failed"
        });
    }
    catch (Exception ex)
    {
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["ok"] = false,
            ["code"] = "input_inject_error",
            ["message"] = ex.Message
        });
    }
}

// Escribimos por el stream crudo: Console.WriteLine mete CRLF en Windows y
// añadiría un \r al final de cada línea JSON que el lector del otro lado
// tendría que recordar recortar. Una línea, un \n, sin sorpresas.
var stdout = Console.OpenStandardOutput();
void WriteLine(string json)
{
    var b = Encoding.UTF8.GetBytes(json + "\n");
    stdout.Write(b, 0, b.Length);
    stdout.Flush();
}

if (!serve)
{
    var once = CaptureOnce(quality, forceFull);
    WriteLine(once);
    return once.Contains("\"ok\":true") ? 0 : 1;
}

// ── Modo servidor ─────────────────────────────────────────────────────
// Una petición por línea, una respuesta por línea. Si stdin se cierra —
// porque el PrivSvc terminó o la sesión se cayó — salimos: no queremos un
// helper huérfano capturando la pantalla de nadie.
// Vigilante de inactividad. Mientras vive, este proceso retiene el handle de
// duplicación de DXGI, y Windows solo concede uno por pantalla: un helper
// ocioso le devolvería DXGI_ERROR_NOT_CURRENTLY_AVAILABLE (0x887A0022) a
// cualquier otra herramienta de captura del equipo — el mismo error que
// pasamos días persiguiendo. Si el PrivSvc deja de pedir fotogramas y no
// cierra stdin (se colgó, lo mataron), salimos por nuestra cuenta.
var lastRequest = DateTime.UtcNow;
var idleWatchdog = new Thread(() =>
{
    while (true)
    {
        Thread.Sleep(5000);
        if (DateTime.UtcNow - lastRequest > TimeSpan.FromSeconds(60))
        {
            Console.Error.WriteLine("60 s sin peticiones — el helper se retira");
            Environment.Exit(0);
        }
    }
}) { IsBackground = true };
idleWatchdog.Start();

string? line;
while ((line = Console.In.ReadLine()) != null)
{
    lastRequest = DateTime.UtcNow;
    var reqQuality = 80;
    var reqFull = false;
    // `kind` distingue captura de entrada. Ausente = captura, para que un
    // PrivSvc viejo hablando con un helper nuevo siga funcionando: los dos
    // viajan en el mismo MSI, pero durante una actualización a medias no
    // conviene depender de eso.
    var kind = "capture";
    Dictionary<string, object>? inputParams = null;
    try
    {
        if (!string.IsNullOrWhiteSpace(line))
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.TryGetProperty("kind", out var kEl) &&
                kEl.ValueKind == JsonValueKind.String)
            {
                kind = kEl.GetString() ?? "capture";
            }
            if (kind == "input")
            {
                // Reconstruimos el diccionario que espera InputInjection. Sus
                // getters ya saben leer JsonElement, así que no hay conversión
                // que se pueda desalinear con el original.
                inputParams = new Dictionary<string, object>();
                foreach (var prop in root.EnumerateObject())
                {
                    if (prop.NameEquals("kind")) continue;
                    inputParams[prop.Name] = prop.Value.Clone();
                }
            }
            if (root.TryGetProperty("quality", out var qEl) &&
                qEl.TryGetInt32(out var qv))
            {
                reqQuality = Math.Max(1, Math.Min(100, qv));
            }
            if (root.TryGetProperty("full", out var fEl))
            {
                // Aceptamos booleano JSON y string: el lado que compone la
                // petición ha cambiado de forma antes, y un "True" con mayúscula
                // ya nos costó que los keyframes no se pidieran nunca.
                reqFull = fEl.ValueKind == JsonValueKind.True ||
                    (fEl.ValueKind == JsonValueKind.String &&
                     string.Equals(fEl.GetString(), "true",
                         StringComparison.OrdinalIgnoreCase));
            }
        }
    }
    catch (Exception ex)
    {
        WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["ok"] = false,
            ["code"] = "bad_request",
            ["message"] = ex.Message
        }));
        continue;
    }

    if (kind == "input")
    {
        WriteLine(InjectOnce(inputParams));
        continue;
    }

    WriteLine(CaptureOnce(reqQuality, reqFull));
}

return 0;
