// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/ScreenCapture.cs
//
// RCP M3.S1 — GDI+ screen capture helper.
//
// Captures the primary display using GDI+ BitBlt and encodes the result
// as a JPEG with a caller-specified quality level. Returns the image as
// a base64 string alongside the pixel dimensions.
//
// Session 0 note: Windows services run in Session 0, which by default
// has no interactive desktop. We use GetDC(GetDesktopWindow()) which
// still reaches the visible desktop from a LocalSystem service as long
// as the HWINSTA is "WinSta0" and the thread desktop is "Default". In
// practice this works on Windows 10 / 11 for the primary display.
//
// Uses GDI+ via System.Drawing (net8.0-windows + System.Drawing.Common
// NuGet). All unmanaged handles are released in finally blocks.

using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace Tracenium.PrivSvc.Windows.Ipc;

internal static class ScreenCapture
{
    // ── Win32 imports ──────────────────────────────────────────────────────────

    [DllImport("user32.dll")]
    private static extern IntPtr GetDesktopWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateCompatibleDC(IntPtr hDC);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateCompatibleBitmap(IntPtr hDC, int nWidth, int nHeight);

    [DllImport("gdi32.dll")]
    private static extern IntPtr SelectObject(IntPtr hDC, IntPtr hObject);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BitBlt(
        IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight,
        IntPtr hdcSrc, int nXSrc, int nYSrc, int dwRop);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteDC(IntPtr hDC);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    // M3.S3 — cursor position for overlay rendering.
    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    private const int SM_CXSCREEN = 0;  // primary monitor width
    private const int SM_CYSCREEN = 1;  // primary monitor height
    private const int SRCCOPY = 0x00CC0020;
    // ⚠️ Sin CAPTUREBLT, BitBlt desde el DC del escritorio NO incluye las
    // ventanas en capas, y la pantalla de bloqueo / inicio de sesión lo es.
    //
    // 🔴 TNS-OPER-SNOC04 (29-sep-2026): con el escritorio quieto el keyframe
    // forzado cae a este GDI (Tracenium.ScreenCap, `forceFull` + no_frame), y
    // salía un AZUL LISO — el fondo del escritorio Winlogon, sin la foto, el
    // reloj ni «Presiona Ctrl+Alt+Supr». El operador lo tomó por roto. Hasta
    // que pulsó «Take control»: el movimiento del ratón hizo cambiar la
    // pantalla, DXGI —que sí captura lo compuesto— entregó un fotograma de
    // verdad, y apareció la pantalla de bloqueo.
    //
    // Cuesta algo de rendimiento (obliga a componer las capas), pero este
    // camino sólo se toma como reserva o para un keyframe de un escritorio que
    // no cambia, y ahí lo que importa es que la imagen sea la real.
    private const int CAPTUREBLT = 0x40000000;

    // Lazy-initialised JPEG encoder info.
    private static ImageCodecInfo? _jpegCodec;
    private static ImageCodecInfo JpegCodec =>
        _jpegCodec ??= GetJpegEncoder();

    // ── Public API ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Captures the primary display and returns a base64-encoded JPEG.
    /// </summary>
    /// <param name="reqId">IPC request ID for the response envelope.</param>
    /// <param name="quality">JPEG quality 1–100 (default 80).</param>
    public static PrivSvcResponse Capture(string reqId, int quality = 80)
    {
        quality = Math.Max(1, Math.Min(100, quality));

        int width  = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);

        if (width <= 0 || height <= 0)
            return PrivSvcResponse.Fail(reqId, "screen_capture_no_display",
                $"GetSystemMetrics returned {width}×{height}");

        IntPtr hDesktop = GetDesktopWindow();
        IntPtr hDC      = GetDC(hDesktop);
        if (hDC == IntPtr.Zero)
            return PrivSvcResponse.Fail(reqId, "screen_capture_getdc_failed",
                "GetDC returned NULL — service may lack desktop access");

        IntPtr hMemDC  = IntPtr.Zero;
        IntPtr hBitmap = IntPtr.Zero;
        IntPtr hOld    = IntPtr.Zero;

        try
        {
            hMemDC  = CreateCompatibleDC(hDC);
            hBitmap = CreateCompatibleBitmap(hDC, width, height);
            hOld    = SelectObject(hMemDC, hBitmap);

            if (!BitBlt(hMemDC, 0, 0, width, height, hDC, 0, 0, SRCCOPY | CAPTUREBLT))
                return PrivSvcResponse.Fail(reqId, "screen_capture_bitblt_failed",
                    "BitBlt failed");

            // Deselect the bitmap before wrapping with Image.FromHbitmap.
            SelectObject(hMemDC, hOld);
            hOld = IntPtr.Zero;

            using var bmp = Image.FromHbitmap(hBitmap);
            using var ms  = new System.IO.MemoryStream();

            var encParams = new EncoderParameters(1);
            encParams.Param[0] = new EncoderParameter(Encoder.Quality, (long)quality);
            bmp.Save(ms, JpegCodec, encParams);

            // M3.S3 — capture cursor position for browser overlay.
            // Failure is non-fatal; we simply omit the cursor in that case.
            int cursorX = -1, cursorY = -1;
            if (GetCursorPos(out POINT cp))
            {
                cursorX = cp.X;
                cursorY = cp.Y;
            }

            var base64 = Convert.ToBase64String(ms.ToArray());
            return PrivSvcResponse.Success(reqId, new
            {
                ok      = true,
                data    = base64,
                width,
                height,
                cursorX,
                cursorY
            });
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(reqId, "screen_capture_error", ex.Message);
        }
        finally
        {
            if (hOld != IntPtr.Zero)  SelectObject(hMemDC, hOld);
            if (hMemDC  != IntPtr.Zero) DeleteDC(hMemDC);
            if (hBitmap != IntPtr.Zero) DeleteObject(hBitmap);
            ReleaseDC(hDesktop, hDC);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static ImageCodecInfo GetJpegEncoder()
    {
        foreach (var codec in ImageCodecInfo.GetImageEncoders())
            if (codec.FormatID == ImageFormat.Jpeg.Guid) return codec;
        throw new InvalidOperationException("JPEG ImageCodecInfo not found");
    }
}
