// experiments/win-session-probe/Program.cs
//
// Prerequisito bloqueante de ADR-0006.
//
// PREGUNTA QUE RESPONDE: ¿screen share falla en Windows porque PrivSvc corre
// en la Sesión 0, o porque el adaptador de vídeo no soporta la captura?
//
// Compila el CÓDIGO REAL del agente (ScreenCaptureDxgi.cs y ScreenCapture.cs,
// incluidos por referencia, no copiados) dentro de un ejecutable normal. Al
// lanzarlo el usuario conectado corre en SU sesión, no en la 0. Si aquí
// captura y como servicio no, la única variable es la sesión y ADR-0006 es
// correcto. Si falla igual y con el mismo HRESULT, el ADR está equivocado y
// el sospechoso vuelve a ser el adaptador.
//
// Ejecutar EN LA VM, en una consola normal del usuario conectado (NO como
// servicio, NO con PsExec -s):
//     .\tracenium-session-probe.exe

using System.Runtime.InteropServices;
using Tracenium.PrivSvc.Windows.Ipc;

[DllImport("kernel32.dll")]
static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);
[DllImport("kernel32.dll")]
static extern uint GetCurrentProcessId();
[DllImport("kernel32.dll")]
static extern uint WTSGetActiveConsoleSessionId();
[DllImport("user32.dll")]
static extern int GetSystemMetrics(int nIndex);
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
static extern bool EnumDisplaySettings(string? dev, int mode, ref DEVMODE dm);

// Guarda el JPEG a disco para poder MIRARLO. Un tamaño en bytes no distingue
// "capturó bien" de "capturó un rectángulo negro"; la imagen sí.
static string? Dump(string name, dynamic r)
{
    try
    {
        var path = Path.Combine(Environment.CurrentDirectory, name);
        File.WriteAllBytes(path, Convert.FromBase64String((string)r!.data));
        return path;
    }
    catch (Exception ex) { return "‼ no se pudo guardar: " + ex.Message; }
}

Console.WriteLine("=== Tracenium — sonda de sesión / captura de pantalla ===");
Console.WriteLine($"arquitectura : {RuntimeInformation.ProcessArchitecture}");

uint mySession = 0;
ProcessIdToSessionId(GetCurrentProcessId(), out mySession);
uint consoleSession = WTSGetActiveConsoleSessionId();

Console.WriteLine($"sesión de este proceso : {mySession}");
Console.WriteLine($"sesión de consola activa: {consoleSession}");
if (mySession == 0)
{
    Console.WriteLine();
    Console.WriteLine("!! Este proceso está en la SESIÓN 0. La prueba no vale:");
    Console.WriteLine("   lánzalo desde una consola normal del usuario conectado.");
    return 2;
}
// ── Tamaño REAL del escritorio ────────────────────────────────────────
// EnumDisplaySettings devuelve el modo físico del dispositivo y NO se ve
// afectado por si el proceso es DPI-aware, a diferencia de GetSystemMetrics.
// Es el árbitro para saber si el 1920x1080 que reporta DXGI es de verdad o
// es el valor codificado a mano que usa cuando GetDesc falla.
var dm = new DEVMODE { dmSize = (ushort)Marshal.SizeOf<DEVMODE>() };
var haveMode = EnumDisplaySettings(null, -1 /* ENUM_CURRENT_SETTINGS */, ref dm);
Console.WriteLine(haveMode
    ? $"escritorio real (EnumDisplaySettings): {dm.dmPelsWidth}x{dm.dmPelsHeight}"
    : "escritorio real: EnumDisplaySettings falló");
Console.WriteLine($"GetSystemMetrics pantalla : {GetSystemMetrics(0)}x{GetSystemMetrics(1)}"
    + $"   virtual: {GetSystemMetrics(78)}x{GetSystemMetrics(79)}");

Console.WriteLine(mySession == consoleSession
    ? "→ corriendo DENTRO de la sesión interactiva (lo que queremos probar)"
    : "→ ojo: sesión distinta de la consola activa (¿RDP?); el resultado sigue siendo informativo");
Console.WriteLine();

// ── 1. DXGI Desktop Duplication — lo que usa el agente hoy ────────────
Console.WriteLine("[1] DXGI Desktop Duplication (ruta actual del agente)");
var dxgi = ScreenCaptureDxgi.Capture("probe-dxgi", 60);
var dxgiOk = dxgi.Ok;
if (dxgiOk)
{
    var d = dxgi.Result as dynamic;
    Console.WriteLine($"    OK — {d!.width}x{d!.height}, {((string)d!.data).Length} chars base64");
    Console.WriteLine($"    imagen → {Dump("probe-dxgi.jpg", d)}");
    if (haveMode && ((int)d!.width != dm.dmPelsWidth || (int)d!.height != dm.dmPelsHeight))
    {
        Console.WriteLine($"    ‼ NO coincide con el escritorio real ({dm.dmPelsWidth}x{dm.dmPelsHeight}).");
        if ((int)d!.width == 1920 && (int)d!.height == 1080)
            Console.WriteLine("      Y es exactamente 1920x1080 = el valor por defecto codificado a mano");
        Console.WriteLine("      => GetDesc está fallando en silencio y la textura de staging");
        Console.WriteLine("         se crea con el tamaño equivocado (CopyResource no copia).");
    }
}
else
{
    Console.WriteLine($"    FALLO code={dxgi.Error?.Code}");
    Console.WriteLine($"          msg={dxgi.Error?.Message}");
}
Console.WriteLine();

// ── 2. GDI BitBlt — el fallback que ADR-0006 quiere rescatar ──────────
Console.WriteLine("[2] GDI BitBlt (ScreenCapture.cs, hoy sin usar)");
var gdi = ScreenCapture.Capture("probe-gdi", 60);
var gdiOk = gdi.Ok;
if (gdiOk)
{
    var g = gdi.Result as dynamic;
    Console.WriteLine($"    OK — {g!.width}x{g!.height}, {((string)g!.data).Length} chars base64");
    Console.WriteLine($"    imagen → {Dump("probe-gdi.jpg", g)}");
}
else
{
    Console.WriteLine($"    FALLO code={gdi.Error?.Code}");
    Console.WriteLine($"          msg={gdi.Error?.Message}");
}

// ── Veredicto ─────────────────────────────────────────────────────────
Console.WriteLine();
Console.WriteLine("=== VEREDICTO ===");
if (dxgiOk || gdiOk)
{
    Console.WriteLine("La captura FUNCIONA desde la sesión del usuario.");
    Console.WriteLine("Como servicio (Sesión 0) falla. => ADR-0006 CONFIRMADO:");
    Console.WriteLine("la causa es la sesión, no el adaptador de vídeo.");
    if (!dxgiOk && gdiOk)
        Console.WriteLine("Además: DXGI no va en este equipo pero GDI sí — el fallback es necesario.");
    Console.WriteLine();
    Console.WriteLine("ABRE probe-dxgi.jpg y probe-gdi.jpg. Si el de DXGI sale negro o");
    Console.WriteLine("cortado, hay un 2º bug (dimensiones) además del de la Sesión 0.");
    return 0;
}
Console.WriteLine("Ninguna de las dos rutas captura NI SIQUIERA desde la sesión del usuario.");
Console.WriteLine("=> ADR-0006 NO aplica. El problema está en el adaptador de vídeo");
Console.WriteLine("   o en el entorno gráfico, no en la Sesión 0.");
return 1;


[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct DEVMODE
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
    public ushort dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra;
    public uint dmFields;
    public int dmPositionX, dmPositionY;
    public uint dmDisplayOrientation, dmDisplayFixedOutput;
    public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
    public ushort dmLogPixels;
    public uint dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency;
    public uint dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2;
    public uint dmPanningWidth, dmPanningHeight;
}
