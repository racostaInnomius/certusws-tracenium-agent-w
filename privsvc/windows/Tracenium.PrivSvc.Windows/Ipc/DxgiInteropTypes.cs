// DxgiInteropTypes.cs
//
// Los structs de DXGI que cruzan la frontera nativa, en un fichero aparte.
//
// ── Por que estan aqui y no dentro de ScreenCaptureDxgi ──────────────
//
// Por lo mismo que `RegistryProbeShape.cs`, `SeceditShape.cs` y compania:
// para poder PROBARLOS. Estaban declarados `private` dentro de
// `ScreenCaptureDxgi`, y ese fichero usa System.Drawing.Imaging, asi que
// el proyecto de pruebas —`net8.0` a secas, para que la suite corra en la
// maquina de cualquiera y no solo en un Windows que nadie tiene delante—
// no puede compilarlo.
//
// Aqui dentro no hay NADA de Windows: System.Runtime.InteropServices y
// tipos primitivos. El fichero se compila tal cual en el proyecto de
// pruebas, que mide su disposicion en memoria con `Marshal.SizeOf`.
//
// ── Por que eso importa ──────────────────────────────────────────────
//
// Un tamano equivocado en `DXGI_OUTDUPL_FRAME_INFO` no da error de
// compilacion ni excepcion: DXGI escribe en la pila del llamante mas alla
// del struct y el proceso se cae mas tarde, en otro sitio, sin relacion
// aparente. Y el `CharSet` ausente de `DXGI_OUTPUT_DESC` ya nos costo una
// tarde: `GetDesc` devolvia S_OK con un escritorio de 0x0.
//
// Son `internal` y no `public`: siguen siendo un detalle de la frontera
// con dxgi.dll, solo que uno que se puede medir.

using System.Runtime.InteropServices;

namespace Tracenium.PrivSvc.Windows.Ipc;

[StructLayout(LayoutKind.Sequential)]
internal struct POINT
{
    public int X;
    public int Y;
}

[StructLayout(LayoutKind.Sequential)]
internal struct RECT
{
    public int Left, Top, Right, Bottom;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DXGI_OUTDUPL_POINTER_POSITION
{
    public POINT Position;   // 8
    public int Visible;      // 4 (BOOL)
}

// This used to be an opaque `Size = 48` blob: we only needed it as an
// `out` parameter to satisfy the AcquireNextFrame ABI and never read it.
// Dirty-rect capture changes that — `TotalMetadataBufferSize` is how we
// learn whether DXGI has change metadata for this frame, and how big a
// buffer GetFrameDirtyRects needs.
//
// The layout must match the native one EXACTLY; a wrong size means DXGI
// scribbles into adjacent stack memory and we crash unpredictably. With
// natural x64 alignment the fields below land at 0, 8, 16, 20, 24, 28,
// 40, 44 — 48 bytes total, identical to the blob it replaces.
[StructLayout(LayoutKind.Sequential)]
internal struct DXGI_OUTDUPL_FRAME_INFO
{
    public long LastPresentTime;            // LARGE_INTEGER
    public long LastMouseUpdateTime;        // LARGE_INTEGER
    public uint AccumulatedFrames;
    public int RectsCoalesced;              // BOOL
    public int ProtectedContentMaskedOut;   // BOOL
    public DXGI_OUTDUPL_POINTER_POSITION PointerPosition;
    public uint TotalMetadataBufferSize;
    public uint PointerShapeBufferSize;
}

// ⚠️ CharSet.Unicode NO es opcional. El campo nativo es WCHAR DeviceName[32],
// o sea 64 bytes. Sin CharSet el default es Ansi y ByValTStr marshala 32,
// dejando todo lo que va detrás corrido 32 bytes: DesktopCoordinates cae
// sobre la segunda mitad de DeviceName, que va rellena de ceros. GetDesc
// devuelve S_OK y aun así el escritorio mide 0x0.
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct DXGI_OUTPUT_DESC
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string DeviceName;
    public RECT DesktopCoordinates;
    public int AttachedToDesktop;
    public uint Rotation;
    public IntPtr Monitor;
}
