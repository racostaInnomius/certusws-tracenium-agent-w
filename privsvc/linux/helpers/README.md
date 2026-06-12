# Linux screen-capture helper (`tracenium-screencap`)

RCP M3.S1 — the native screen-capture path for the Linux agent. Source:
[`screencap.c`](screencap.c).

## Why a separate helper

The PrivSvc runs as a **root systemd service**, outside any graphical
session. X11 capture needs the session's `DISPLAY`, an `XAUTHORITY`
cookie, and ideally the session user's identity — none available to a
faceless root daemon. The orchestrator
([`../src/screen-capture.ts`](../src/screen-capture.ts)) discovers the
active session via `loginctl`, resolves `DISPLAY` + `XAUTHORITY`, and runs
this helper as the session user:

```
runuser -u <user> -- env DISPLAY=:0 XAUTHORITY=<path> \
    tracenium-screencap --quality <1-100>
```

## I/O contract

One JSON line on stdout:

- success: `{"ok":true,"data":"<base64 jpeg>","width":W,"height":H,"cursorX":X,"cursorY":Y}`
- failure: `{"ok":false,"code":"<stable_code>","message":"…"}`

`width/height` and `cursorX/Y` are in X11 root-window pixels. Stable
codes: `x11_connect_failed`, `screen_capture_no_display`,
`screen_capture_failed`, `screen_capture_encode_failed`, `out_of_memory`.

## Scope

- **X11 only.** Wayland is rejected upstream in the orchestrator
  (`wayland_unsupported`) before this helper is spawned — Xwayland
  refuses `XGetImage` of native Wayland windows, so a portal/PipeWire
  path is required and is deferred to a future sprint.
- Captures the whole X root window (union of all monitors). Per-monitor
  cropping (RandR) is a follow-up.

## Build

Handled automatically by `scripts/build-linux-binaries.sh` (the
"screen capture helper" step). Manual build:

```bash
cc -O2 -Wall screencap.c -o tracenium-screencap -lX11 -ljpeg
```

Build-host dependencies:

| Distro family | Packages                                  |
|---------------|-------------------------------------------|
| Debian/Ubuntu | `libx11-dev libjpeg-dev`                  |
| RHEL/Fedora   | `libX11-devel libjpeg-turbo-devel`        |

Runtime dependencies (`libX11.so.6`, `libjpeg.so.*`) are present on any
system running an X11 desktop. The binary is staged next to
`privsvc/index.js` and listed in
[`packaging/linux/nfpm.yaml.tmpl`](../../../packaging/linux/nfpm.yaml.tmpl)
so it lands at `/usr/lib/tracenium/privsvc/tracenium-screencap` (mode
0755) in the `.deb`/`.rpm`.

Cross-compiling for a non-native arch: point `CC` at a cross toolchain
(e.g. `CC=aarch64-linux-gnu-gcc`) with the matching cross `-dev`
libraries. `TRACENIUM_SKIP_SCREENCAP=1` installs a graceful stub instead
(returns `screen_capture_helper_missing`) for hosts without the X11/JPEG
dev headers during local iteration — **not** for release packages.

## ⚠️ On-device validation pending

`loginctl` session discovery, `XAUTHORITY` resolution, and `runuser`
need a smoke test on real Xorg desktops across the major DMs (gdm,
lightdm, sddm) — they place the auth cookie in different locations.
