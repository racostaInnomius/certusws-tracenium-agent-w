// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/ScreenCaptureDxgi.cs
//
// RCP M3.S1 — Screen capture via DXGI Desktop Duplication API.
//
// Why this exists (i.e. why we don't use GDI BitBlt like ScreenCapture.cs):
//
//   PrivSvc runs as a Windows service in Session 0 with LocalSystem.
//   GDI BitBlt from Session 0's "desktop" returns black/empty because the
//   Session 0 desktop is the *system* desktop, not the interactive one
//   the user sees (Session 0 Isolation, post-Win-Vista). This caused the
//   long-standing "BitBlt failed" error on every rcp.screen capture
//   request — recorded across many sessions in the err.log file.
//
//   DXGI Desktop Duplication (added in Windows 8) replaces BitBlt with
//   a kernel-mode-accelerated path that can read the actual *active*
//   interactive desktop from any session, including from a service in
//   Session 0. As long as a user is logged into Session 1+ AND has an
//   active desktop, this works regardless of who calls it.
//
// What it can NOT do:
//
//   - Capture when there is NO active interactive session (server
//     without anyone logged in, lock-screen-only state). In those cases
//     this returns `no_interactive_desktop` so the operator UI can
//     surface a useful message instead of "BitBlt failed". Solving the
//     server case requires a Virtual Display Driver (see ROADMAP) and
//     is intentionally OUT OF SCOPE for this sprint.
//   - Capture secondary monitors. We acquire output index 0 (primary)
//     only. Multi-monitor support is a future task.
//   - Capture protected/DRM content (Netflix, etc). DXGI honors the
//     content protection bit on the desktop image; protected regions
//     come back black. This matches every commercial remote-control
//     vendor's behavior — there is no fix.
//
// ARM64 compatibility:
//
//   This file uses ONLY P/Invoke to system DLLs that ship in both
//   x64 and ARM64 Windows installations (`d3d11.dll`, `dxgi.dll`,
//   `gdi32.dll`, `user32.dll`). No third-party NuGet binaries. The
//   same compiled assembly runs on either architecture; the underlying
//   DXGI implementation in the OS is the native one for that CPU.
//
// Lifecycle:
//
//   The DXGI device, context, and OutputDuplication are created lazily
//   on the first Capture() call and CACHED in static fields. They
//   survive across many rapid captures (typical for a screen-share
//   session at 10-30fps). On certain failures — DXGI_ERROR_ACCESS_LOST
//   when the user switches desktops, or after a sleep/resume cycle —
//   we tear down and recreate the chain transparently. The caller
//   never sees the recreate.
//
// Concurrency:
//
//   DXGI Desktop Duplication only permits ONE active duplication per
//   output per session at a time. We serialize Capture() calls under a
//   single static lock to ensure we don't trip over our own state on
//   concurrent rcp.screen sessions targeting the same machine. The lock
//   is held for the duration of a single AcquireNextFrame + copy +
//   ReleaseFrame cycle, which is typically <20 ms.

using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace Tracenium.PrivSvc.Windows.Ipc;

internal static class ScreenCaptureDxgi
{
    // ── HRESULT helpers ────────────────────────────────────────────────────────

    private const int S_OK = 0;
    private const int DXGI_ERROR_ACCESS_LOST            = unchecked((int)0x887A0026);
    private const int DXGI_ERROR_WAIT_TIMEOUT           = unchecked((int)0x887A0027);
    private const int DXGI_ERROR_NOT_CURRENTLY_AVAILABLE = unchecked((int)0x887A0022);
    private const int DXGI_ERROR_UNSUPPORTED            = unchecked((int)0x887A0004);
    private const int DXGI_ERROR_INVALID_CALL           = unchecked((int)0x887A0001);
    private const int DXGI_ERROR_ACCESS_DENIED          = unchecked((int)0x887A002B);
    private const int E_ACCESSDENIED                    = unchecked((int)0x80070005);
    private const int E_OUTOFMEMORY                     = unchecked((int)0x8007000E);
    private const int E_FAIL                            = unchecked((int)0x80004005);

    // ── D3D / DXGI enums ───────────────────────────────────────────────────────

    private enum D3D_DRIVER_TYPE : uint
    {
        Hardware = 1,
        Reference = 2,
        Null = 3,
        Software = 4,
        Warp = 5,
    }

    private enum D3D_FEATURE_LEVEL : uint
    {
        Level_11_0 = 0xb000,
        Level_10_1 = 0xa100,
        Level_10_0 = 0xa000,
        Level_9_3  = 0x9300,
    }

    [Flags]
    private enum D3D11_CREATE_DEVICE_FLAG : uint
    {
        None             = 0,
        BgraSupport      = 0x20,
    }

    private const uint D3D11_SDK_VERSION = 7;

    private enum DXGI_FORMAT : uint
    {
        B8G8R8A8_UNORM = 87,
    }

    [Flags]
    private enum D3D11_BIND_FLAG : uint
    {
        None            = 0,
        RenderTarget    = 0x20,
        ShaderResource  = 0x8,
    }

    private enum D3D11_USAGE : uint
    {
        Default   = 0,
        Immutable = 1,
        Dynamic   = 2,
        Staging   = 3,
    }

    [Flags]
    private enum D3D11_CPU_ACCESS_FLAG : uint
    {
        Write = 0x10000,
        Read  = 0x20000,
    }

    private enum D3D11_MAP : uint
    {
        Read = 1,
        Write = 2,
        ReadWrite = 3,
        WriteDiscard = 4,
        WriteNoOverwrite = 5,
    }

    // ── Native structs ─────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct DXGI_SAMPLE_DESC
    {
        public uint Count;
        public uint Quality;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct D3D11_TEXTURE2D_DESC
    {
        public uint Width;
        public uint Height;
        public uint MipLevels;
        public uint ArraySize;
        public DXGI_FORMAT Format;
        public DXGI_SAMPLE_DESC SampleDesc;
        public D3D11_USAGE Usage;
        public D3D11_BIND_FLAG BindFlags;
        public D3D11_CPU_ACCESS_FLAG CPUAccessFlags;
        public uint MiscFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct D3D11_MAPPED_SUBRESOURCE
    {
        public IntPtr pData;
        public uint RowPitch;
        public uint DepthPitch;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DXGI_OUTDUPL_POINTER_POSITION
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
    private struct DXGI_OUTDUPL_FRAME_INFO
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

    [StructLayout(LayoutKind.Sequential)]
    private struct DXGI_OUTPUT_DESC
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string DeviceName;
        public RECT DesktopCoordinates;
        public int AttachedToDesktop;
        public uint Rotation;
        public IntPtr Monitor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    // ── COM Interface GUIDs ────────────────────────────────────────────────────

    private static readonly Guid IID_IDXGIFactory1     = new("770aae78-f26f-4dba-a829-253c83d1b387");
    private static readonly Guid IID_IDXGIDevice       = new("54ec77fa-1377-44e6-8c32-88fd5f44c84c");
    private static readonly Guid IID_IDXGIOutput1      = new("00cddea8-939b-4b83-a340-a685226666cc");
    private static readonly Guid IID_ID3D11Texture2D   = new("6f15aaf2-d208-4e89-9ab4-489535d34f9c");
    private static readonly Guid IID_IDXGIResource     = new("035f3ab4-482e-4e50-b41f-8a7f8bd8960b");

    // ── P/Invoke ───────────────────────────────────────────────────────────────

    [DllImport("d3d11.dll")]
    private static extern int D3D11CreateDevice(
        IntPtr pAdapter,
        D3D_DRIVER_TYPE DriverType,
        IntPtr Software,
        D3D11_CREATE_DEVICE_FLAG Flags,
        IntPtr pFeatureLevels,
        uint FeatureLevels,
        uint SDKVersion,
        out IntPtr ppDevice,
        out D3D_FEATURE_LEVEL pFeatureLevel,
        out IntPtr ppImmediateContext);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    // ── Static state cached across captures ────────────────────────────────────
    //
    // We hold IUnknown pointers via Marshal.GetIUnknownForObject helpers.
    // For simplicity and to avoid bringing in SharpGen/Vortice, we cache
    // by VTABLE offsets directly. The interface lifetimes mirror the
    // duplication chain itself: tearing down requires releasing in reverse.

    // Above this share of the screen, cropping stops paying for itself: the
    // JPEG of the bounding box costs about what the whole screen costs and we
    // would add a blit for nothing. Tuned conservatively — the point of dirty
    // rects is the typing/cursor case, which is a tiny fraction of a screen.
    private const int DIRTY_MAX_AREA_PERCENT = 55;

    private static readonly object _lock = new();
    private static IntPtr _d3dDevice;
    private static IntPtr _d3dContext;
    private static IntPtr _outputDuplication;
    private static uint _width;
    private static uint _height;
    private static bool _initialized;
    // Set whenever the duplication chain is (re)created. The first
    // AcquireNextFrame after DuplicateOutput has nothing to diff against, so
    // its dirty rects can't be trusted — and the browser has no prior pixels
    // for this chain either. Forces one full frame, then clears.
    private static bool _needKeyframe = true;

    // ── Lazy JPEG encoder reused from ScreenCapture.cs path ────────────────────

    private static ImageCodecInfo? _jpegCodec;
    private static ImageCodecInfo JpegCodec =>
        _jpegCodec ??= GetJpegEncoder();

    private static ImageCodecInfo GetJpegEncoder()
    {
        foreach (var codec in ImageCodecInfo.GetImageEncoders())
            if (codec.FormatID == ImageFormat.Jpeg.Guid) return codec;
        throw new InvalidOperationException("JPEG ImageCodecInfo not found");
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Captures the primary display via DXGI Desktop Duplication and returns
    /// a base64-encoded JPEG. Matches the signature of ScreenCapture.Capture
    /// so the IPC handler can be swapped without other code changes.
    /// </summary>
    /// <param name="forceFull">
    /// Ask for a complete frame even when DXGI reports a small dirty region.
    /// The agent sets this on its keyframe cadence: the screen DataChannel is
    /// unreliable (ordered:false, maxRetransmits:0), so a dropped partial
    /// update would otherwise leave a stale rectangle on the operator's canvas
    /// forever. See screen-session.ts.
    /// </param>
    public static PrivSvcResponse Capture(string reqId, int quality = 80,
        bool forceFull = false)
    {
        quality = Math.Max(1, Math.Min(100, quality));

        lock (_lock)
        {
            int hr;

            // ── Initialize lazily, with one automatic retry on ACCESS_LOST. ──
            for (int attempt = 0; attempt < 2; attempt++)
            {
                if (!_initialized)
                {
                    hr = TryInitialize();
                    if (hr != S_OK)
                    {
                        // Common failure: no interactive desktop available. Map
                        // it to a stable error code the UI can branch on.
                        Cleanup();
                        if (hr == DXGI_ERROR_NOT_CURRENTLY_AVAILABLE ||
                            hr == DXGI_ERROR_UNSUPPORTED ||
                            hr == DXGI_ERROR_ACCESS_DENIED ||
                            hr == E_ACCESSDENIED)
                        {
                            return PrivSvcResponse.Fail(reqId,
                                "no_interactive_desktop",
                                "No active interactive desktop. " +
                                "Screen sharing requires a user to be logged " +
                                "into the device. For headless servers, use " +
                                "rcp.shell instead.");
                        }
                        return PrivSvcResponse.Fail(reqId,
                            "screen_capture_init_failed",
                            $"DXGI init failed: 0x{hr:X8}");
                    }
                }

                // A freshly (re)initialised chain always yields a keyframe.
                hr = TryCaptureFrame(reqId, quality, forceFull || _needKeyframe, out var response);
                if (hr == S_OK && response != null) { _needKeyframe = false; return response; }

                if (hr == DXGI_ERROR_ACCESS_LOST && attempt == 0)
                {
                    // Recoverable: user switched desktops (Ctrl-Alt-Del, UAC
                    // prompt, fast user switch, secure desktop). Tear down,
                    // re-init, retry once.
                    Cleanup();
                    continue;
                }

                if (hr == DXGI_ERROR_WAIT_TIMEOUT)
                {
                    // No new frame within the timeout window. The previous
                    // frame is still on the screen, no need to re-encode.
                    // Caller will retry on its own polling schedule.
                    return PrivSvcResponse.Fail(reqId, "screen_capture_no_frame",
                        "No new frame within timeout (idle desktop)");
                }

                return PrivSvcResponse.Fail(reqId, "screen_capture_acquire_failed",
                    $"AcquireNextFrame failed: 0x{hr:X8}");
            }

            // Unreachable but the compiler can't prove it without an explicit
            // return.
            return PrivSvcResponse.Fail(reqId, "screen_capture_unreachable",
                "Capture loop exited without result");
        }
    }

    // ── Internals ──────────────────────────────────────────────────────────────

    private static int TryInitialize()
    {
        var hr = D3D11CreateDevice(
            IntPtr.Zero,
            D3D_DRIVER_TYPE.Hardware,
            IntPtr.Zero,
            D3D11_CREATE_DEVICE_FLAG.BgraSupport,
            IntPtr.Zero,
            0,
            D3D11_SDK_VERSION,
            out _d3dDevice,
            out _,
            out _d3dContext);
        if (hr != S_OK)
        {
            // Try WARP as a software fallback. Useful in headless / GPU-less
            // VM scenarios; quality and FPS are lower but it works.
            hr = D3D11CreateDevice(
                IntPtr.Zero,
                D3D_DRIVER_TYPE.Warp,
                IntPtr.Zero,
                D3D11_CREATE_DEVICE_FLAG.BgraSupport,
                IntPtr.Zero,
                0,
                D3D11_SDK_VERSION,
                out _d3dDevice,
                out _,
                out _d3dContext);
            if (hr != S_OK) return hr;
        }

        // From device → DXGIDevice → adapter → output[0] → output1 → duplication.
        hr = QueryInterface(_d3dDevice, IID_IDXGIDevice, out var dxgiDevice);
        if (hr != S_OK) return hr;
        try
        {
            hr = GetParent(dxgiDevice, IID_IDXGIFactory1, out var adapter);
            // GetParent on IDXGIDevice returns the IDXGIAdapter, not the
            // factory; the IID is incidental for ABI navigation. We just
            // need any GUID the QueryInterface will accept on the adapter.
            if (hr != S_OK)
            {
                // Try IID_IDXGIAdapter1 instead — older drivers sometimes
                // reject other IIDs at this hop.
                var iidIDXGIAdapter1 = new Guid("29038f61-3839-4626-91fd-086879011a05");
                hr = GetParent(dxgiDevice, iidIDXGIAdapter1, out adapter);
                if (hr != S_OK) return hr;
            }
            try
            {
                hr = EnumOutputs(adapter, 0, out var output);
                if (hr != S_OK) return hr;
                try
                {
                    hr = QueryInterface(output, IID_IDXGIOutput1, out var output1);
                    if (hr != S_OK) return hr;
                    try
                    {
                        // Cache the desktop size from the output description.
                        hr = GetDesc(output, out var desc);
                        if (hr == S_OK)
                        {
                            _width  = (uint)(desc.DesktopCoordinates.Right  - desc.DesktopCoordinates.Left);
                            _height = (uint)(desc.DesktopCoordinates.Bottom - desc.DesktopCoordinates.Top);
                        }

                        hr = DuplicateOutput(output1, _d3dDevice, out _outputDuplication);
                        if (hr != S_OK) return hr;

                        _initialized = true;
                        return S_OK;
                    }
                    finally { Release(output1); }
                }
                finally { Release(output); }
            }
            finally { Release(adapter); }
        }
        finally { Release(dxgiDevice); }
    }

    private static int TryCaptureFrame(string reqId, int quality, bool forceFull,
        out PrivSvcResponse? response)
    {
        response = null;

        // Acquire next frame with 500ms timeout.
        var hr = AcquireNextFrame(_outputDuplication, 500,
            out var frameInfo, out var desktopResource);
        if (hr != S_OK) return hr;

        try
        {
            // The desktop is delivered as an IDXGIResource. We QI it to
            // ID3D11Texture2D so we can copy it onto a staging texture we
            // can lock for CPU read.
            hr = QueryInterface(desktopResource, IID_ID3D11Texture2D,
                out var desktopTex);
            if (hr != S_OK) return hr;

            IntPtr stagingTex = IntPtr.Zero;
            try
            {
                var w = _width;  if (w == 0) w = 1920;  // safe defaults
                var h = _height; if (h == 0) h = 1080;

                var stagingDesc = new D3D11_TEXTURE2D_DESC
                {
                    Width            = w,
                    Height           = h,
                    MipLevels        = 1,
                    ArraySize        = 1,
                    Format           = DXGI_FORMAT.B8G8R8A8_UNORM,
                    SampleDesc       = new DXGI_SAMPLE_DESC { Count = 1, Quality = 0 },
                    Usage            = D3D11_USAGE.Staging,
                    BindFlags        = D3D11_BIND_FLAG.None,
                    CPUAccessFlags   = D3D11_CPU_ACCESS_FLAG.Read,
                    MiscFlags        = 0,
                };

                hr = CreateTexture2D(_d3dDevice, ref stagingDesc, IntPtr.Zero,
                    out stagingTex);
                if (hr != S_OK) return hr;

                CopyResource(_d3dContext, stagingTex, desktopTex);

                hr = Map(_d3dContext, stagingTex, 0, D3D11_MAP.Read, 0,
                    out var mapped);
                if (hr != S_OK) return hr;

                try
                {
                    using var bmp = new Bitmap(
                        (int)w, (int)h, (int)mapped.RowPitch,
                        PixelFormat.Format32bppArgb, mapped.pData);

                    // ── Dirty-rect decision ───────────────────────────────
                    // Encode only what changed when that's a real saving.
                    // Full frame when: the caller asked for one (the agent's
                    // periodic keyframe — the unreliable DataChannel means a
                    // dropped delta would leave a permanent artifact), we
                    // can't trust the metadata, or the changed region is big
                    // enough that cropping buys nothing.
                    var region = new Rectangle(0, 0, (int)w, (int)h);
                    var isFull = true;
                    if (!forceFull &&
                        TryGetDirtyBounds(_outputDuplication, frameInfo, w, h, out var dirty))
                    {
                        var dw = dirty.Right - dirty.Left;
                        var dh = dirty.Bottom - dirty.Top;
                        long dirtyArea = (long)dw * dh;
                        long screenArea = (long)w * h;
                        // Below this share of the screen a crop is worth it.
                        // Above it, the JPEG of the box costs about what the
                        // whole screen costs and we'd pay an extra blit for
                        // nothing.
                        if (dirtyArea > 0 && dirtyArea * 100 < screenArea * DIRTY_MAX_AREA_PERCENT)
                        {
                            region = new Rectangle(dirty.Left, dirty.Top, dw, dh);
                            isFull = false;
                        }
                    }

                    using var ms = new System.IO.MemoryStream();
                    var encParams = new EncoderParameters(1);
                    encParams.Param[0] = new EncoderParameter(
                        Encoder.Quality, (long)quality);

                    if (isFull)
                    {
                        bmp.Save(ms, JpegCodec, encParams);
                    }
                    else
                    {
                        // Clone lifts the sub-rectangle out of the mapped
                        // staging texture into managed memory, so the JPEG
                        // encoder only ever sees the changed pixels.
                        using var crop = bmp.Clone(region, PixelFormat.Format32bppArgb);
                        crop.Save(ms, JpegCodec, encParams);
                    }

                    int cursorX = -1, cursorY = -1;
                    if (GetCursorPos(out POINT cp))
                    {
                        cursorX = cp.X;
                        cursorY = cp.Y;
                    }

                    var base64 = Convert.ToBase64String(ms.ToArray());
                    response = PrivSvcResponse.Success(reqId, new
                    {
                        ok      = true,
                        data    = base64,
                        // width/height stay the FULL desktop size — the
                        // browser sizes its canvas from these, and an input
                        // click maps through them. The region is separate.
                        width   = (int)w,
                        height  = (int)h,
                        full    = isFull,
                        x       = region.X,
                        y       = region.Y,
                        rw      = region.Width,
                        rh      = region.Height,
                        cursorX,
                        cursorY,
                    });
                }
                finally
                {
                    Unmap(_d3dContext, stagingTex, 0);
                }
            }
            finally
            {
                if (stagingTex != IntPtr.Zero) Release(stagingTex);
                Release(desktopTex);
            }
        }
        finally
        {
            Release(desktopResource);
            ReleaseFrame(_outputDuplication);
        }

        return S_OK;
    }

    private static void Cleanup()
    {
        if (_outputDuplication != IntPtr.Zero) { Release(_outputDuplication); _outputDuplication = IntPtr.Zero; }
        if (_d3dContext        != IntPtr.Zero) { Release(_d3dContext);        _d3dContext        = IntPtr.Zero; }
        if (_d3dDevice         != IntPtr.Zero) { Release(_d3dDevice);         _d3dDevice         = IntPtr.Zero; }
        _initialized = false;
        _needKeyframe = true;
    }

    // ── COM vtable navigation ──────────────────────────────────────────────────
    //
    // For each interface method we call, we read the function pointer from
    // the vtable at a fixed offset (in pointer-sized slots from method
    // index 0 = QueryInterface). This is the lowest-level way to invoke a
    // COM method without any binding library.
    //
    // Method indices are defined by the COM interface declaration; they
    // never change for a frozen interface.

    private static IntPtr GetVtableSlot(IntPtr pUnknown, int slotIndex)
    {
        var vtbl = Marshal.ReadIntPtr(pUnknown);
        return Marshal.ReadIntPtr(vtbl, slotIndex * IntPtr.Size);
    }

    private static int QueryInterface(IntPtr pUnknown, Guid iid, out IntPtr ppvObject)
    {
        // IUnknown::QueryInterface is method index 0.
        var slot = GetVtableSlot(pUnknown, 0);
        var fn = Marshal.GetDelegateForFunctionPointer<QueryInterfaceFn>(slot);
        return fn(pUnknown, ref iid, out ppvObject);
    }

    private static uint Release(IntPtr pUnknown)
    {
        if (pUnknown == IntPtr.Zero) return 0;
        var slot = GetVtableSlot(pUnknown, 2);
        var fn = Marshal.GetDelegateForFunctionPointer<ReleaseFn>(slot);
        return fn(pUnknown);
    }

    private static int GetParent(IntPtr pUnknown, Guid iid, out IntPtr ppParent)
    {
        // IDXGIObject::GetParent — method index 6 on IDXGIObject (after
        // QueryInterface/AddRef/Release + SetPrivateData/SetPrivateDataInterface/GetPrivateData).
        var slot = GetVtableSlot(pUnknown, 6);
        var fn = Marshal.GetDelegateForFunctionPointer<GetParentFn>(slot);
        return fn(pUnknown, ref iid, out ppParent);
    }

    private static int EnumOutputs(IntPtr pAdapter, uint output, out IntPtr ppOutput)
    {
        // IDXGIAdapter::EnumOutputs — method index 7.
        var slot = GetVtableSlot(pAdapter, 7);
        var fn = Marshal.GetDelegateForFunctionPointer<EnumOutputsFn>(slot);
        return fn(pAdapter, output, out ppOutput);
    }

    private static int GetDesc(IntPtr pOutput, out DXGI_OUTPUT_DESC desc)
    {
        // IDXGIOutput::GetDesc — method index 7.
        var slot = GetVtableSlot(pOutput, 7);
        var fn = Marshal.GetDelegateForFunctionPointer<OutputGetDescFn>(slot);
        return fn(pOutput, out desc);
    }

    private static int DuplicateOutput(IntPtr pOutput1, IntPtr pDevice, out IntPtr ppOutputDuplication)
    {
        // IDXGIOutput1::DuplicateOutput — method index 22.
        var slot = GetVtableSlot(pOutput1, 22);
        var fn = Marshal.GetDelegateForFunctionPointer<DuplicateOutputFn>(slot);
        return fn(pOutput1, pDevice, out ppOutputDuplication);
    }

    private static int AcquireNextFrame(IntPtr pDuplication, uint timeoutMs,
        out DXGI_OUTDUPL_FRAME_INFO frameInfo, out IntPtr ppDesktopResource)
    {
        // IDXGIOutputDuplication::AcquireNextFrame — method index 8.
        var slot = GetVtableSlot(pDuplication, 8);
        var fn = Marshal.GetDelegateForFunctionPointer<AcquireNextFrameFn>(slot);
        return fn(pDuplication, timeoutMs, out frameInfo, out ppDesktopResource);
    }

    private static int GetFrameDirtyRects(IntPtr pDuplication, uint bufferSize,
        IntPtr pDirtyRectsBuffer, out uint requiredSize)
    {
        // IDXGIOutputDuplication::GetFrameDirtyRects — method index 9,
        // immediately after AcquireNextFrame (8) and before
        // GetFrameMoveRects (10). Valid only between Acquire and Release.
        var slot = GetVtableSlot(pDuplication, 9);
        var fn = Marshal.GetDelegateForFunctionPointer<GetFrameDirtyRectsFn>(slot);
        return fn(pDuplication, bufferSize, pDirtyRectsBuffer, out requiredSize);
    }

    private static int ReleaseFrame(IntPtr pDuplication)
    {
        // IDXGIOutputDuplication::ReleaseFrame — method index 14.
        var slot = GetVtableSlot(pDuplication, 14);
        var fn = Marshal.GetDelegateForFunctionPointer<ReleaseFrameFn>(slot);
        return fn(pDuplication);
    }

    /// <summary>
    /// Union of the regions DXGI says changed since our previous
    /// AcquireNextFrame, clamped to the desktop. Returns false when we can't
    /// trust the metadata — no rects reported, a buffer that doesn't divide
    /// into whole RECTs, or a call failure — in which case the caller must
    /// fall back to a full frame rather than guess.
    ///
    /// A single bounding box rather than the individual rects: one JPEG
    /// encode and one DataChannel message instead of N. The pathological
    /// case (cursor in one corner, clock in the other) produces a big box,
    /// but the caller measures the box against the screen and sends a full
    /// frame when it isn't worth it — so the worst case is exactly today's
    /// behaviour, never worse.
    /// </summary>
    private static bool TryGetDirtyBounds(IntPtr duplication,
        in DXGI_OUTDUPL_FRAME_INFO info, uint screenW, uint screenH,
        out RECT bounds)
    {
        bounds = default;
        if (info.TotalMetadataBufferSize == 0) return false;

        var buffer = Marshal.AllocHGlobal((int)info.TotalMetadataBufferSize);
        try
        {
            var hr = GetFrameDirtyRects(duplication, info.TotalMetadataBufferSize,
                buffer, out var required);
            if (hr != S_OK || required == 0) return false;

            var rectSize = Marshal.SizeOf<RECT>();
            if (required % rectSize != 0) return false;
            var count = (int)(required / rectSize);
            if (count <= 0) return false;

            int left = int.MaxValue, top = int.MaxValue;
            int right = int.MinValue, bottom = int.MinValue;
            for (int i = 0; i < count; i++)
            {
                var r = Marshal.PtrToStructure<RECT>(buffer + i * rectSize);
                if (r.Right <= r.Left || r.Bottom <= r.Top) continue;
                if (r.Left < left) left = r.Left;
                if (r.Top < top) top = r.Top;
                if (r.Right > right) right = r.Right;
                if (r.Bottom > bottom) bottom = r.Bottom;
            }
            if (left == int.MaxValue) return false; // every rect was empty

            // Clamp — a rect can legitimately extend to the desktop edge, and
            // a malformed one must never produce an out-of-bounds crop.
            left = Math.Max(0, left);
            top = Math.Max(0, top);
            right = Math.Min((int)screenW, right);
            bottom = Math.Min((int)screenH, bottom);
            if (right <= left || bottom <= top) return false;

            bounds = new RECT { Left = left, Top = top, Right = right, Bottom = bottom };
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int CreateTexture2D(IntPtr pDevice, ref D3D11_TEXTURE2D_DESC desc,
        IntPtr pInitialData, out IntPtr ppTexture2D)
    {
        // ID3D11Device::CreateTexture2D — method index 5.
        var slot = GetVtableSlot(pDevice, 5);
        var fn = Marshal.GetDelegateForFunctionPointer<CreateTexture2DFn>(slot);
        return fn(pDevice, ref desc, pInitialData, out ppTexture2D);
    }

    private static void CopyResource(IntPtr pContext, IntPtr pDst, IntPtr pSrc)
    {
        // ID3D11DeviceContext::CopyResource — method index 47.
        var slot = GetVtableSlot(pContext, 47);
        var fn = Marshal.GetDelegateForFunctionPointer<CopyResourceFn>(slot);
        fn(pContext, pDst, pSrc);
    }

    private static int Map(IntPtr pContext, IntPtr pResource, uint subresource,
        D3D11_MAP mapType, uint mapFlags, out D3D11_MAPPED_SUBRESOURCE mapped)
    {
        // ID3D11DeviceContext::Map — method index 14.
        var slot = GetVtableSlot(pContext, 14);
        var fn = Marshal.GetDelegateForFunctionPointer<MapFn>(slot);
        return fn(pContext, pResource, subresource, mapType, mapFlags, out mapped);
    }

    private static void Unmap(IntPtr pContext, IntPtr pResource, uint subresource)
    {
        // ID3D11DeviceContext::Unmap — method index 15.
        var slot = GetVtableSlot(pContext, 15);
        var fn = Marshal.GetDelegateForFunctionPointer<UnmapFn>(slot);
        fn(pContext, pResource, subresource);
    }

    // ── Delegate types for the COM method pointers above ───────────────────────

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int QueryInterfaceFn(IntPtr pThis, ref Guid iid, out IntPtr ppv);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint ReleaseFn(IntPtr pThis);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetParentFn(IntPtr pThis, ref Guid iid, out IntPtr ppParent);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int EnumOutputsFn(IntPtr pThis, uint output, out IntPtr ppOutput);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int OutputGetDescFn(IntPtr pThis, out DXGI_OUTPUT_DESC desc);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DuplicateOutputFn(IntPtr pThis, IntPtr pDevice, out IntPtr ppDup);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int AcquireNextFrameFn(IntPtr pThis, uint timeoutMs,
        out DXGI_OUTDUPL_FRAME_INFO frameInfo, out IntPtr ppDesktopResource);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetFrameDirtyRectsFn(IntPtr pThis, uint bufferSize,
        IntPtr pDirtyRectsBuffer, out uint pRequired);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ReleaseFrameFn(IntPtr pThis);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CreateTexture2DFn(IntPtr pThis,
        ref D3D11_TEXTURE2D_DESC desc, IntPtr pInitialData, out IntPtr ppTex);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void CopyResourceFn(IntPtr pThis, IntPtr pDst, IntPtr pSrc);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int MapFn(IntPtr pThis, IntPtr pResource, uint subresource,
        D3D11_MAP mapType, uint mapFlags, out D3D11_MAPPED_SUBRESOURCE mapped);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void UnmapFn(IntPtr pThis, IntPtr pResource, uint subresource);
}
