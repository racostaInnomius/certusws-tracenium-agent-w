# Remote Control Plugin — platform support matrix

What works on which OS, what's intentionally out of scope, and where the
limits come from. Keep this file honest — the operator UI surfaces the
errors but does not explain them, so this is the canonical reference.

## Capability x OS matrix

|                | rcp.shell | rcp.file | rcp.screen                       |
|----------------|-----------|----------|----------------------------------|
| Windows 10/11  | ✅        | ✅        | ✅ (DXGI Desktop Duplication)    |
| Windows Server | ✅        | ✅        | ⚠️  only with active console     |
| macOS 14+      | ✅        | ✅        | ✅ (ScreenCaptureKit)            |
| macOS 12.3–13  | ✅        | ✅        | ✅ (Quartz CGWindowList fallback)|
| macOS < 12.3   | ✅        | ✅        | ❌ (helper requires SCK / Quartz)|
| Linux X11      | ✅        | ✅        | ✅ (XGetImage on root window)    |
| Linux Wayland  | ✅        | ✅        | ❌ returns `wayland_unsupported` |

✅ = implemented and tested
⚠️  = works but only in narrow case, see notes below
❌ = intentionally not in scope this milestone

## Component layout

```
   ┌────────────────────────────────────────────────────────────┐
   │  AgentCore (Node 22, cross-platform, ships everywhere)     │
   │  src/plugins/rcp/*            session-manager, peer-       │
   │                               session, pty-session,        │
   │                               file-session, screen-session │
   │  src/transport/grpc-stream    server-bound RCP messages    │
   │  src/transport/grpc-client    PrivSvc IPC dispatcher       │
   └────────────────────────────────────────────────────────────┘
                        │ JSON-RPC over named pipe / unix socket
                        ▼
   ┌──────────────────────┬───────────────────────┬─────────────┐
   │ PrivSvc Windows (C#) │ PrivSvc macOS (TS)    │ PrivSvc     │
   │ - gRPC bridge        │ - gRPC bridge         │ Linux (TS)  │
   │ - ScreenCaptureDxgi  │ - tracenium-screencap │ - gRPC br.  │
   │   (DXGI Desktop      │   helper (Swift,      │ - tracenium │
   │   Duplication, P/    │   universal binary,   │   -screencap│
   │   Invoke direct)     │   SCK + Quartz)       │   helper (C,│
   │                      │                       │   X11 XGet  │
   │                      │                       │   Image +   │
   │                      │                       │   libjpeg)  │
   └──────────────────────┴───────────────────────┴─────────────┘
```

The AgentCore is the same TypeScript bundle on every OS — `process.platform`
selects the right PrivSvc client at boot. PrivSvc is the *only* code that
ever calls platform-specific APIs.

## Why every platform has these limits

### Linux Wayland — `wayland_unsupported`

XGetImage works against the X server's root window. Under Wayland there
is no X server; the compositor (Mutter, KWin, Sway, …) owns every pixel
and exposes it only through XDG portals or pipewire. Implementing that
requires:
- `org.freedesktop.portal.ScreenCast` D-Bus client
- pipewire native bindings on Node
- per-distro portal config (Mutter has rolled the protocol twice)

We chose X11-only for the initial Linux release. Operator UI maps the
error to a clear message ("Ask the user to log in via Xorg session
instead"). XDG portal support is a tracked roadmap item.

### macOS < 12.3 — helper requires SCK or Quartz

The Swift helper imports `ScreenCaptureKit` unconditionally. SCK ships
in 12.3. Older OS would link-fail. We could fork the helper to omit the
SCK import but the install base of macOS 11 / early 12 on managed
endpoints is negligible at this point.

### Windows Server without console — DXGI returns NOT_CURRENTLY_AVAILABLE

DXGI Desktop Duplication needs an *active* interactive desktop to
duplicate. A Windows Server installed in core mode, or sitting on
disconnected RDP session, has none. ScreenCaptureDxgi maps the failure
to `no_interactive_desktop` and the UI tells the operator to use a Shell
session instead. The architectural fix is a virtual display driver
(VDD) — see `HEADLESS_SERVER_LIMITATION.md`.

### Windows Server with console — works

If the server has an active interactive desktop (someone is RDP'd in,
or the VM console is showing), DXGI duplicates that desktop just fine.
This is the common case for managed-RDP server fleets and is treated as
the supported path.

## Codepath cross-references

When a bug is reported, here's where to look first.

| Symptom                                    | First file                                  |
|--------------------------------------------|---------------------------------------------|
| "Establishing session…" forever            | UI WS handler + agent `[rcp] dispatch entered` |
| Connects then drops every 30-60s           | `iceRestart.js` + agent libdatachannel logs  |
| "BitBlt failed" Windows                    | should be impossible — ScreenCaptureDxgi.cs replaced GDI |
| "wayland_unsupported"                      | privsvc/linux/src/screen-capture.ts          |
| "no_interactive_desktop" Windows           | privsvc/windows/.../ScreenCaptureDxgi.cs     |
| "no_interactive_desktop" macOS             | privsvc/macos/src/screen-capture.ts (TCC)    |
| Frame is all black                         | macOS: TCC permission denied; Win: protected DRM content |
| Safari "ICE failed" but Chrome works       | docs note — mDNS resolver; documented Task #3|

## Field flag: which capability is allowed

`features.{remoteShell,remoteFile,remoteScreen}` in the runtime policy
snapshot — set per tenant via the backend. The agent enforces it at
`session-manager.onOffer` capability check. The UI greys out the action
button when the capability is missing from the device's advertised
capabilities array (control-plane responds with the union of policy
features and OS-supported features).
