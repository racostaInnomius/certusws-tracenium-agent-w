// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/InputInjection.cs
//
// RCP M3.S4 — synthetic input injection (mouse + keyboard).
//
// Receives input ops from the Node agent (forwarded over IPC from the
// browser's DataChannel) and translates them to Win32 SendInput calls.
//
// Operates in Session 0 because the privsvc runs as LocalSystem service.
// For SendInput to reach the interactive desktop, the call still works
// from Session 0 in most modern Windows builds (10/11) — the input is
// queued onto the active console session via the kernel. If the device
// is locked or no user is logged in, SendInput silently no-ops (returns
// 0 events injected); we surface that as a soft error in the response.
//
// Supported ops:
//   mouseMove   — absolute coords (display pixels)
//   mouseDown   — button 0/1/2 (left/middle/right)
//   mouseUp     — button 0/1/2
//   wheel       — vertical + horizontal scroll deltas
//   keyDown     — by JS KeyboardEvent.code (e.g., "KeyA", "Enter")
//   keyUp       — same
//   releaseAll  — best-effort release of all known mouse buttons + a
//                 small set of common modifiers, to recover from focus
//                 loss without leaking held keys on the remote.

using System.Runtime.InteropServices;

namespace Tracenium.PrivSvc.Windows.Ipc;

internal static class InputInjection
{
    // ── Win32 SendInput structures ────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int    dx;
        public int    dy;
        public uint   mouseData;
        public uint   dwFlags;
        public uint   time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint   dwFlags;
        public uint   time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUTUNION
    {
        [FieldOffset(0)] public MOUSEINPUT    mi;
        [FieldOffset(0)] public KEYBDINPUT    ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint       type;
        public INPUTUNION U;
    }

    private const uint INPUT_MOUSE    = 0;
    private const uint INPUT_KEYBOARD = 1;

    // MOUSEINPUT.dwFlags
    private const uint MOUSEEVENTF_MOVE        = 0x0001;
    private const uint MOUSEEVENTF_LEFTDOWN    = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP      = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN   = 0x0008;
    private const uint MOUSEEVENTF_RIGHTUP     = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN  = 0x0020;
    private const uint MOUSEEVENTF_MIDDLEUP    = 0x0040;
    private const uint MOUSEEVENTF_WHEEL       = 0x0800;
    private const uint MOUSEEVENTF_HWHEEL      = 0x01000;
    private const uint MOUSEEVENTF_ABSOLUTE    = 0x8000;
    private const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;

    // KEYBDINPUT.dwFlags
    private const uint KEYEVENTF_KEYUP       = 0x0002;
    private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;

    // ── Public API ─────────────────────────────────────────────────────────────

    public static PrivSvcResponse Inject(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var op = GetString(p, "op") ?? "";

            switch (op)
            {
                case "mouseMove":
                    return DoMouseMove(req.Id, p);
                case "mouseDown":
                    return DoMouseButton(req.Id, p, down: true);
                case "mouseUp":
                    return DoMouseButton(req.Id, p, down: false);
                case "wheel":
                    return DoWheel(req.Id, p);
                case "keyDown":
                    return DoKey(req.Id, p, down: true);
                case "keyUp":
                    return DoKey(req.Id, p, down: false);
                case "releaseAll":
                    return DoReleaseAll(req.Id);
                default:
                    return PrivSvcResponse.Fail(req.Id, "input_unknown_op",
                        $"unknown input op: {op}");
            }
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "input_inject_error", ex.Message);
        }
    }

    // ── Mouse handlers ─────────────────────────────────────────────────────────

    private static PrivSvcResponse DoMouseMove(string reqId, Dictionary<string, object> p)
    {
        var (ax, ay) = AbsoluteFromPixels(p);
        var inp = new INPUT
        {
            type = INPUT_MOUSE,
            U = new INPUTUNION
            {
                mi = new MOUSEINPUT
                {
                    dx = ax,
                    dy = ay,
                    dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
                }
            }
        };
        return Send(reqId, new[] { inp });
    }

    private static PrivSvcResponse DoMouseButton(string reqId, Dictionary<string, object> p, bool down)
    {
        var (ax, ay) = AbsoluteFromPixels(p);
        var btn = GetInt(p, "button", 0);
        uint flag = btn switch
        {
            0 => down ? MOUSEEVENTF_LEFTDOWN   : MOUSEEVENTF_LEFTUP,
            1 => down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP,
            2 => down ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP,
            _ => 0
        };
        if (flag == 0)
            return PrivSvcResponse.Fail(reqId, "input_invalid_button", $"button {btn}");

        // Combine move + click in a single SendInput call so the click
        // lands exactly where the browser intended even if the previous
        // mouseMove hasn't been processed yet.
        var inp = new INPUT
        {
            type = INPUT_MOUSE,
            U = new INPUTUNION
            {
                mi = new MOUSEINPUT
                {
                    dx = ax,
                    dy = ay,
                    dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | flag
                }
            }
        };
        return Send(reqId, new[] { inp });
    }

    private static PrivSvcResponse DoWheel(string reqId, Dictionary<string, object> p)
    {
        // Browser wheel deltas come in pixels (deltaMode = 0 in JS).
        // Win32 expects WHEEL_DELTA (120) units per notch. Convert by
        // dividing by ~3 (a typical wheel tick is ~100px in a browser).
        // We send vertical and horizontal as two separate INPUT events.
        var deltaY = GetInt(p, "deltaY", 0);
        var deltaX = GetInt(p, "deltaX", 0);

        // Negate Y because browser deltaY is positive when scrolling
        // DOWN, while WHEEL expects positive = scroll UP.
        int amountY = -(deltaY * 120 / 100);
        int amountX =   deltaX * 120 / 100;

        var list = new List<INPUT>();
        if (amountY != 0)
        {
            list.Add(new INPUT
            {
                type = INPUT_MOUSE,
                U = new INPUTUNION
                {
                    mi = new MOUSEINPUT { mouseData = unchecked((uint)amountY), dwFlags = MOUSEEVENTF_WHEEL }
                }
            });
        }
        if (amountX != 0)
        {
            list.Add(new INPUT
            {
                type = INPUT_MOUSE,
                U = new INPUTUNION
                {
                    mi = new MOUSEINPUT { mouseData = unchecked((uint)amountX), dwFlags = MOUSEEVENTF_HWHEEL }
                }
            });
        }
        if (list.Count == 0)
            return PrivSvcResponse.Success(reqId, new { ok = true, injected = 0 });
        return Send(reqId, list.ToArray());
    }

    // ── Keyboard handlers ──────────────────────────────────────────────────────

    private static PrivSvcResponse DoKey(string reqId, Dictionary<string, object> p, bool down)
    {
        var code = GetString(p, "code") ?? "";
        var vk = JsCodeToVk(code);
        if (vk == 0)
            return PrivSvcResponse.Fail(reqId, "input_unknown_key", $"no VK mapping for '{code}'");

        uint flags = down ? 0u : KEYEVENTF_KEYUP;
        // Extended-key flag for nav cluster + numpad enter + arrows.
        if (IsExtendedKey(code)) flags |= KEYEVENTF_EXTENDEDKEY;

        var inp = new INPUT
        {
            type = INPUT_KEYBOARD,
            U = new INPUTUNION
            {
                ki = new KEYBDINPUT { wVk = vk, dwFlags = flags }
            }
        };
        return Send(reqId, new[] { inp });
    }

    private static PrivSvcResponse DoReleaseAll(string reqId)
    {
        // Best-effort: send keyup for the common modifier set + mouseup
        // for each button. Idempotent — releasing an already-released
        // key is a no-op for the OS.
        var inputs = new List<INPUT>();

        // Modifiers
        foreach (var vk in new ushort[] {
            0x10, // VK_SHIFT
            0xA0, // VK_LSHIFT
            0xA1, // VK_RSHIFT
            0x11, // VK_CONTROL
            0xA2, // VK_LCONTROL
            0xA3, // VK_RCONTROL
            0x12, // VK_MENU (Alt)
            0xA4, // VK_LMENU
            0xA5, // VK_RMENU
            0x5B, // VK_LWIN
            0x5C  // VK_RWIN
        })
        {
            inputs.Add(new INPUT
            {
                type = INPUT_KEYBOARD,
                U = new INPUTUNION { ki = new KEYBDINPUT { wVk = vk, dwFlags = KEYEVENTF_KEYUP } }
            });
        }

        // Mouse buttons (UP only — no coords change).
        foreach (var flag in new uint[] { MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTUP })
        {
            inputs.Add(new INPUT
            {
                type = INPUT_MOUSE,
                U = new INPUTUNION { mi = new MOUSEINPUT { dwFlags = flag } }
            });
        }

        return Send(reqId, inputs.ToArray());
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static PrivSvcResponse Send(string reqId, INPUT[] inputs)
    {
        var injected = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        if (injected == 0)
        {
            var err = Marshal.GetLastWin32Error();
            // err=5 (ACCESS_DENIED) typically means the workstation is locked
            // or no interactive session exists. Soft-fail: return ok with a
            // hint so the agent doesn't spin on retries.
            return PrivSvcResponse.Success(reqId, new
            {
                ok = false,
                injected = 0,
                hint = $"SendInput blocked (Win32 err={err})"
            });
        }
        return PrivSvcResponse.Success(reqId, new { ok = true, injected });
    }

    // Convert pixel coords (within the display) to the absolute 0..65535
    // coord space SendInput expects under MOUSEEVENTF_ABSOLUTE. We map
    // against the primary monitor; multi-monitor support would need
    // VIRTUALDESK + VirtualScreen metrics (deferred).
    private static (int x, int y) AbsoluteFromPixels(Dictionary<string, object> p)
    {
        int px = GetInt(p, "x", 0);
        int py = GetInt(p, "y", 0);
        int sw = Math.Max(1, GetSystemMetrics(SM_CXSCREEN));
        int sh = Math.Max(1, GetSystemMetrics(SM_CYSCREEN));
        int ax = (int)Math.Round(px * 65535.0 / sw);
        int ay = (int)Math.Round(py * 65535.0 / sh);
        return (ax, ay);
    }

    // ── KeyboardEvent.code → VK code mapping ──────────────────────────────────
    //
    // The browser's `KeyboardEvent.code` is layout-independent (e.g.,
    // "KeyA" always means the physical A position on the keyboard).
    // Mapping straight to Win32 VK codes lets the OS handle the active
    // keyboard layout — perfect for remote control across locales.

    private static ushort JsCodeToVk(string code)
    {
        if (string.IsNullOrEmpty(code)) return 0;

        // Letters: "KeyA" .. "KeyZ" → VK_A .. VK_Z (0x41 .. 0x5A)
        if (code.Length == 4 && code.StartsWith("Key"))
        {
            char c = code[3];
            if (c >= 'A' && c <= 'Z') return (ushort)c;
        }

        // Top-row digits: "Digit0" .. "Digit9" → 0x30 .. 0x39
        if (code.Length == 6 && code.StartsWith("Digit"))
        {
            char c = code[5];
            if (c >= '0' && c <= '9') return (ushort)c;
        }

        // F1..F24: VK_F1=0x70 .. VK_F24=0x87
        if (code.StartsWith("F") && code.Length >= 2 && code.Length <= 3)
        {
            if (int.TryParse(code.Substring(1), out int fn) && fn >= 1 && fn <= 24)
                return (ushort)(0x6F + fn);
        }

        // Numpad
        if (code.StartsWith("Numpad"))
        {
            var rest = code.Substring(6);
            if (rest.Length == 1 && rest[0] >= '0' && rest[0] <= '9')
                return (ushort)(0x60 + (rest[0] - '0')); // VK_NUMPAD0..9
            switch (rest)
            {
                case "Add":      return 0x6B;
                case "Subtract": return 0x6D;
                case "Multiply": return 0x6A;
                case "Divide":   return 0x6F;
                case "Decimal":  return 0x6E;
                case "Enter":    return 0x0D; // VK_RETURN (extended)
            }
        }

        return code switch
        {
            "Enter"        => 0x0D,
            "Escape"       => 0x1B,
            "Tab"          => 0x09,
            "Backspace"    => 0x08,
            "Space"        => 0x20,
            "ShiftLeft"    => 0xA0,
            "ShiftRight"   => 0xA1,
            "ControlLeft"  => 0xA2,
            "ControlRight" => 0xA3,
            "AltLeft"      => 0xA4,
            "AltRight"     => 0xA5,
            "MetaLeft"     => 0x5B,
            "MetaRight"    => 0x5C,
            "CapsLock"     => 0x14,
            "NumLock"      => 0x90,
            "ScrollLock"   => 0x91,
            "PrintScreen"  => 0x2C,
            "Pause"        => 0x13,
            "Insert"       => 0x2D,
            "Delete"       => 0x2E,
            "Home"         => 0x24,
            "End"          => 0x23,
            "PageUp"       => 0x21,
            "PageDown"     => 0x22,
            "ArrowLeft"    => 0x25,
            "ArrowUp"      => 0x26,
            "ArrowRight"   => 0x27,
            "ArrowDown"    => 0x28,
            "Minus"        => 0xBD,
            "Equal"        => 0xBB,
            "BracketLeft"  => 0xDB,
            "BracketRight" => 0xDD,
            "Backslash"    => 0xDC,
            "Semicolon"    => 0xBA,
            "Quote"        => 0xDE,
            "Backquote"    => 0xC0,
            "Comma"        => 0xBC,
            "Period"       => 0xBE,
            "Slash"        => 0xBF,
            "IntlBackslash"=> 0xE2,
            _              => 0
        };
    }

    private static bool IsExtendedKey(string code) => code switch
    {
        "ArrowLeft" or "ArrowUp" or "ArrowRight" or "ArrowDown"
            or "Home" or "End" or "PageUp" or "PageDown"
            or "Insert" or "Delete"
            or "NumpadEnter" or "NumpadDivide"
            or "ControlRight" or "AltRight"
            or "MetaLeft" or "MetaRight" => true,
        _ => false
    };

    // ── Param parsing helpers ──────────────────────────────────────────────────

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var v) || v == null) return null;
        return v switch
        {
            string s => s,
            System.Text.Json.JsonElement je =>
                je.ValueKind == System.Text.Json.JsonValueKind.String ? je.GetString() : je.ToString(),
            _ => v.ToString()
        };
    }

    private static int GetInt(Dictionary<string, object> p, string key, int fallback)
    {
        if (!p.TryGetValue(key, out var v) || v == null) return fallback;
        switch (v)
        {
            case int i: return i;
            case long l: return (int)l;
            case double d: return (int)Math.Round(d);
            case System.Text.Json.JsonElement je:
                if (je.ValueKind == System.Text.Json.JsonValueKind.Number)
                    return je.TryGetInt32(out var n) ? n : (int)Math.Round(je.GetDouble());
                if (je.ValueKind == System.Text.Json.JsonValueKind.String &&
                    int.TryParse(je.GetString(), out var parsed))
                    return parsed;
                return fallback;
            default:
                return int.TryParse(v.ToString(), out var x) ? x : fallback;
        }
    }
}
