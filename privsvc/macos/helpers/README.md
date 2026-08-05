# macOS screen-capture helper (`tracenium-screencap`)

RCP M3.S1 — the native screen-capture path for the macOS agent. Source:
[`screencap/main.swift`](screencap/main.swift).

## Why a separate helper

The PrivSvc runs as a **root LaunchDaemon** (see
`privsvc/macos/launchd/com.certusws.tracenium.privsvc.plist` — no
`UserName`, so it runs as root in the *system* bootstrap context). macOS
ScreenCaptureKit **and** the legacy Quartz `CGWindowListCreateImage`
require (1) a TCC "Screen Recording" grant and (2) execution inside the
active GUI session. A faceless root daemon has neither — this is the
macOS analog of the Windows Session-0 problem, and macOS has no
DXGI-Desktop-Duplication-style escape hatch.

So capture is delegated to this small **signed** helper, which the
orchestrator ([`../src/screen-capture.ts`](../src/screen-capture.ts))
spawns into the console user's Aqua session:

```
launchctl asuser <consoleUID> sudo -n -u <consoleUser> \
    tracenium-screencap --quality <1-100>
```

## I/O contract

One JSON line on stdout, nothing else:

- success: `{"ok":true,"data":"<base64 jpeg>","width":W,"height":H,"cursorX":X,"cursorY":Y}`
- failure: `{"ok":false,"code":"<stable_code>","message":"…"}`

`width/height` and `cursorX/Y` are in display **points**, so the UI cursor
overlay aligns on Retina. Stable error codes match the cross-platform
vocabulary: `no_screen_recording_permission`, `screen_capture_no_display`,
`screen_capture_encode_failed`, `screen_capture_failed`.

## Capture strategy

| macOS    | Path                                                   |
|----------|--------------------------------------------------------|
| 14.0+    | ScreenCaptureKit one-shot (`SCScreenshotManager`)      |
| 12.3–13  | Quartz `CGWindowListCreateImage` (`.nominalResolution`)|

On 14+ a non-permission SCK failure falls back to Quartz before giving
up. Extending the SCK path down to 12.3 via a one-frame `SCStream` is a
follow-up if Quartz proves insufficient on Ventura.

## Build

Handled automatically by `scripts/build-macos-pkg.sh` →
`build_screencap_helper()`. Manual build:

```bash
swiftc -O -target arm64-apple-macos12.3  screencap/main.swift -o screencap.arm64
swiftc -O -target x86_64-apple-macos12.3 screencap/main.swift -o screencap.x86_64
lipo -create screencap.arm64 screencap.x86_64 -output tracenium-screencap
codesign --force --options runtime --timestamp \
  -i com.certusws.tracenium.screencap \
  --sign "Developer ID Application: CERTUS ITM LLC (3CN673MCWH)" tracenium-screencap
```

The binary is staged next to `privsvc.js` (the orchestrator resolves it
via `path.resolve(__dirname, "tracenium-screencap")`) and ships inside
the `.pkg` automatically (`pkgbuild --root` packages the whole tree).

## TCC — PPPC profile (required, no interactive prompt)

Screen Recording is pre-granted fleet-wide via a **PPPC** (Privacy
Preferences Policy Control) configuration profile keyed to the helper's
signing identity. The helper *preflights* and never *requests*
permission, so without this profile it returns
`no_screen_recording_permission` instead of prompting.

> **Who delivers this profile.** A PPPC payload can only be installed by
> an MDM — no agent, however privileged, can grant itself TCC. Tracenium
> is building its **own** MDM for exactly this class of control
> (configuration profiles, restrictions, managed preferences); until
> that ships, the profile has to come from whatever MDM the customer
> already runs, and endpoints with no MDM at all will keep returning
> `no_screen_recording_permission`. Earlier revisions of this file
> assumed a third-party MDM was a given — that is no longer the plan.

Payload — `com.apple.TCC.configuration-profile-policy`:

```xml
<key>Services</key>
<dict>
  <key>ScreenCapture</key>
  <array>
    <dict>
      <key>Identifier</key>
      <string>com.certusws.tracenium.screencap</string>
      <key>IdentifierType</key>
      <string>bundleID</string>
      <key>CodeRequirement</key>
      <string>identifier "com.certusws.tracenium.screencap" and anchor apple generic and certificate leaf[subject.OU] = "3CN673MCWH"</string>
      <key>Authorization</key>
      <string>Allow</string>
      <key>StaticCode</key>
      <false/>
    </dict>
  </array>
</dict>
```

Notes:
- `3CN673MCWH` is the CERTUS ITM LLC Team ID (matches the Developer ID
  used to sign every shipped binary).
- `Authorization: Allow` requires macOS 11+. For 10.15 fall back to the
  legacy `Allowed: <true/>` key.
- Screen Recording **cannot** be granted by a PPPC profile silently on
  macOS 10.15 (Apple restriction); 11+ is required for the no-prompt
  flow. 10.15 endpoints would need an interactive grant (out of scope —
  the fleet baseline is 12.3+).

## ⚠️ On-device validation pending

The `launchctl asuser` + `sudo` incantation and the PPPC grant must be
smoke-tested on a real **managed** Mac with a user logged into the GUI —
same "untested in Session-0/real-session context" caveat the Windows DXGI
path carries. The error codes are designed so the UI degrades gracefully
if any step is misconfigured.
