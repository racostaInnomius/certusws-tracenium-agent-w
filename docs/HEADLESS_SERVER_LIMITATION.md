# Headless server limitation for rcp.screen

Servers with no logged-in interactive user cannot be screen-shared via
rcp.screen. This is not a Tracenium bug — it is the OS reality of every
mainstream platform's screen capture stack.

## Where the limit comes from per platform

| OS      | Capture API used         | What it needs                  |
|---------|--------------------------|--------------------------------|
| Windows | DXGI Desktop Duplication | An active interactive desktop  |
| macOS   | ScreenCaptureKit + Quartz| A logged-in GUI session        |
| Linux   | X11 XGetImage            | A running X server with a root |

Each one of these APIs reads pixels that exist in the kernel-side
compositor (DWM, WindowServer, X server). When no user is logged in, the
compositor on most modern OSes doesn't create the surface to read from
at all — there is nothing to capture.

## What we surface to the operator

The agent returns these error codes (see `RCP_PLATFORM_MATRIX.md`):

- Windows: `no_interactive_desktop`
- macOS: `no_interactive_desktop` (when WindowServer reports none)
- Linux: `screen_capture_failed` with details when XOpenDisplay returns NULL

The operator UI maps each of these to a clear message: "Use rcp.shell
instead, this device has no active desktop."

## Why this is the right answer for the current sprint

Implementing headless server support means shipping a Virtual Display
Driver (VDD) — a kernel-mode display adapter that creates a synthetic
desktop the agent can capture even without a user. Every commercial
unattended-access vendor does this (AnyDesk, TeamViewer, Splashtop,
Parsec all ship a custom VDD). The cost:

1. Microsoft WHQL signing (months and money)
2. Per-OS kernel driver maintenance (Linux nouveau/amdgpu/i915 paths)
3. macOS — Apple essentially forbids third-party kernel display drivers
   on Apple Silicon; the only way in is DriverKit (DEXT) with their
   approval
4. Significant attack surface on a security agent

For our threat model (controlled IT-managed devices with Tracenium for
inventory + remote assist) the workaround is fine: rcp.shell covers the
"reach the server" case, and rcp.screen serves the dominant user
support case where someone IS at the keyboard.

## Path forward — if the requirement changes

In approximate effort order:

1. **AutoLogon dedicated user (Windows only)**. Configure Windows to
   auto-login as a service account at boot, then immediately lock it.
   DWM creates the desktop. rcp.screen works. Security hole but bounded.
2. **RDP loopback session**. Agent opens an RDP session to localhost with
   pre-provisioned credentials. Same effect as #1, more moving parts.
3. **Integrate an existing VDD**. `IddSampleDriver` (Microsoft sample),
   `usbmmidd` (Amyuni, commercial). License review needed; some don't
   support Server SKUs.
4. **Build our own VDD**. Months of work; requires kernel-driver signing
   pipeline.

If the product moves toward unattended-server screen-share, expect #3 to
be the realistic plan. #1 and #2 are quick demo-grade workarounds.

## What we *don't* do

- We don't fake-claim success and return a black/blank frame. That
  produces support tickets and erodes trust in the rest of the agent's
  reporting. The honest error is the better product.
- We don't auto-spawn a user session. That requires a level of
  privilege we don't have and don't want to acquire.
- We don't downgrade to a generic "Connection error". The operator
  needs to know that a *different* RCP capability (shell) would work
  on this device.
