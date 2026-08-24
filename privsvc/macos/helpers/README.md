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

## TCC — Grabación de Pantalla: la aprueba una PERSONA

> **Corrección (agosto 2026).** Este documento afirmaba durante meses que
> Screen Recording se concedía en flota vía perfil PPPC. **Es falso.** Apple
> trata `kTCCServiceScreenCapture` como **deny-only** en PPPC: un perfil puede
> DENEGARLO a apps concretas, nunca concederlo. Es una decisión de diseño de
> Apple sobre privacidad, no una limitación del MDM que se use. La sección
> anterior incluso documentaba `Authorization: Allow` y un "no-prompt flow" en
> macOS 11+ que no existe.
>
> Confirmado en documentación de Kandji, la comunidad de Jamf, dataJAR y
> ControlUp. El `⚠️` de validación pendiente que llevaba este fichero desde el
> principio tenía razón, y nadie lo resolvió hasta que el módulo falló en campo.

**Consecuencia de producto:** screen share en macOS exige **una aprobación
humana, una vez por Mac**. No hay despliegue silencioso y no lo habrá. Windows
y Linux no tienen esta restricción.

### Cómo funciona ahora

1. El helper viaja como **bundle** `Tracenium Screen Helper.app`, no como
   ejecutable suelto. Un binario Unix pelado no aparece de forma fiable en la
   lista de Grabación de Pantalla — hay una regresión abierta en macOS 26.1 —
   y el selector de Ajustes solo deja escoger aplicaciones, así que el permiso
   no se podía conceder ni a mano. Además el nombre del bundle es lo que ve la
   persona que aprueba: tiene que ser reconocible.

2. El helper **PIDE** el permiso una vez por proceso, al arrancar:
   `CGPreflightScreenCaptureAccess()` solo consulta y **no registra** el
   binario en Ajustes. Solo `CGRequestScreenCaptureAccess()` lo hace. Mientras
   el helper únicamente consultaba, no aparecía en la lista y no había forma de
   autorizarlo.

3. Si sigue sin concederse, devuelve `screen_recording_permission_pending`, que
   la UI presenta como acción pendiente y no como error: hay alguien mirando un
   diálogo.

4. La firma estable con Developer ID sigue importando, pero **no** para que un
   perfil conceda nada: sirve para que la aprobación que hizo una persona
   sobreviva a las actualizaciones del agente. Si la identidad cambiara en cada
   build, habría que volver a aprobar en cada versión.

### Lo único que MDM sí aporta

`AllowStandardUserToSetSystemService` (macOS 11+) permite que un usuario **sin
privilegios de administrador** apruebe el permiso. No lo concede — sigue
haciendo falta que alguien pulse — pero quita la fricción de tener que pasar
por un admin, que en un parque gestionado es la barrera real.

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
      <!-- NO "Allow": Apple lo ignora para ScreenCapture. Esto solo evita que
           haga falta un administrador para aprobar. -->
      <key>Authorization</key>
      <string>AllowStandardUserToSetSystemService</string>
      <key>StaticCode</key>
      <false/>
    </dict>
  </array>
</dict>
```

`3CN673MCWH` es el Team ID de CERTUS ITM LLC, el mismo con el que se firma todo
lo que enviamos.

El mismo payload sirve además para **denegar** ScreenCapture a otras apps, que
es para lo que PPPC sí funciona en este servicio.

## ⚠️ On-device validation pending

The `launchctl asuser` + `sudo` incantation and the PPPC grant must be
smoke-tested on a real **managed** Mac with a user logged into the GUI —
same "untested in Session-0/real-session context" caveat the Windows DXGI
path carries. The error codes are designed so the UI degrades gracefully
if any step is misconfigured.
