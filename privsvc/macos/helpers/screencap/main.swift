// privsvc/macos/helpers/screencap/main.swift
//
// tracenium-screencap — one-shot macOS screen capture helper for RCP.
//
// Invoked by the PrivSvc orchestrator (privsvc/macos/src/screen-capture.ts)
// INSIDE the console user's GUI session via:
//
//   launchctl asuser <uid> sudo -u <user> tracenium-screencap --quality N
//
// Contract (one JSON line on stdout, nothing else):
//   success: {"ok":true,"data":"<base64 jpeg>","width":W,"height":H,
//             "cursorX":X,"cursorY":Y}
//   failure: {"ok":false,"code":"<stable_code>","message":"…"}
//
// The width/height + cursorX/Y are reported in the SAME coordinate unit
// (display points) so the operator UI's cursor overlay (M3.S3) lines up
// regardless of Retina scale. Stable error codes mirror the Windows DXGI
// vocabulary so the UI branches identically across all three OSes:
//   no_screen_recording_permission, screen_capture_no_display,
//   screen_capture_encode_failed, screen_capture_failed.
//
// ── Capture strategy ─────────────────────────────────────────────────
//   macOS 14.0+ : ScreenCaptureKit one-shot (SCScreenshotManager) —
//                 the modern, non-deprecated path.
//   macOS <14.0 : Quartz CGWindowListCreateImage (covers 12.3–13.x and
//                 older). SCScreenshotManager is 14.0+ only; extending
//                 the SCK path down to 12.3 via a one-frame SCStream is
//                 a follow-up if Quartz proves insufficient on Ventura.
//   On 14+ we also fall back to Quartz if SCK throws a non-permission
//   error, so a single transient SCK failure doesn't drop the frame.
//
// ── TCC ──────────────────────────────────────────────────────────────
//   ⚠️ LA PREMISA ORIGINAL DE ESTE FICHERO ERA FALSA. Decía que Screen
//   Recording se concede en flota vía perfil PPPC de MDM. No se puede:
//   Apple trata kTCCServiceScreenCapture como DENY-ONLY en PPPC — un
//   perfil puede denegarlo a otras apps, nunca concederlo. Lo único que
//   MDM aporta es Authorization = AllowStandardUserToSetSystemService,
//   que permite que un usuario SIN privilegios de admin lo apruebe; pero
//   alguien tiene que pulsar igualmente.
//
//   Consecuencia de diseño: screen share en macOS EXIGE una aprobación
//   humana, una vez por Mac. No hay despliegue silencioso posible.
//
//   Y preflight NO basta para que el helper aparezca en Ajustes:
//   CGPreflightScreenCaptureAccess() solo consulta. Solo
//   CGRequestScreenCaptureAccess() registra el binario en la lista de
//   Grabación de Pantalla. Por eso el operador no encontraba a
//   com.certusws.tracenium.screencap por ningún lado: nunca lo pidió.
//
// Build (see scripts/build-macos-pkg.sh):
//   swiftc -O -target arm64-apple-macos12.3  main.swift -o screencap.arm64
//   swiftc -O -target x86_64-apple-macos12.3 main.swift -o screencap.x86_64
//   lipo -create screencap.arm64 screencap.x86_64 -output tracenium-screencap
//   codesign --options runtime --timestamp -s "Developer ID Application: …" \
//            tracenium-screencap
// ScreenCaptureKit / CoreGraphics / ImageIO are auto-linked from the
// imports below; no explicit -framework flags required.

import Foundation
import CoreGraphics
import ImageIO
import ScreenCaptureKit

// Carries a stable error code + human message through `Result`'s
// Failure channel (which requires conformance to `Error`).
struct CaptureError: Error {
    let code: String
    let message: String
}

// ── Output helpers ───────────────────────────────────────────────────

func emit(_ obj: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: obj, options: []),
       let line = String(data: data, encoding: .utf8) {
        // Single line; orchestrator reads the last non-empty stdout line.
        print(line)
        fflush(stdout)
    }
}

func emitError(_ code: String, _ message: String) -> Never {
    emit(["ok": false, "code": code, "message": message])
    // Exit 0: the JSON IS the result. The orchestrator distinguishes
    // success from failure on the `ok` field, not the exit code.
    exit(0)
}

func finish(_ image: CGImage, quality: Int, cursorX: Int, cursorY: Int) -> Never {
    guard let b64 = jpegBase64(image, quality: quality) else {
        emitError("screen_capture_encode_failed", "JPEG encode failed")
    }
    emit([
        "ok": true,
        "data": b64,
        "width": image.width,
        "height": image.height,
        "cursorX": cursorX,
        "cursorY": cursorY
    ])
    exit(0)
}

// ── JPEG encode → base64 ─────────────────────────────────────────────

func jpegBase64(_ image: CGImage, quality: Int) -> String? {
    let out = NSMutableData()
    guard let dest = CGImageDestinationCreateWithData(out, "public.jpeg" as CFString, 1, nil) else {
        return nil
    }
    let q = max(0.0, min(1.0, Double(quality) / 100.0))
    let props: [CFString: Any] = [kCGImageDestinationLossyCompressionQuality: q]
    CGImageDestinationAddImage(dest, image, props as CFDictionary)
    guard CGImageDestinationFinalize(dest) else { return nil }
    return (out as Data).base64EncodedString()
}

// ── Cursor position (global, top-left origin, in points) ─────────────
//
// CGEvent location is in the same flipped (top-left) coordinate space
// as the captured display image, and in points — matching the SCK
// output (config sized in points) and the Quartz `.nominalResolution`
// image, so the UI overlay aligns on Retina. -1,-1 means "unknown".

func cursorPoint() -> (Int, Int) {
    if let loc = CGEvent(source: nil)?.location {
        return (Int(loc.x.rounded()), Int(loc.y.rounded()))
    }
    return (-1, -1)
}

// ── Quartz fallback ──────────────────────────────────────────────────
//
// `.nominalResolution` yields a points-sized image (not the 2x Retina
// backing) so its dimensions match the cursor's point coordinates.

func captureQuartz() -> CGImage? {
    return CGWindowListCreateImage(
        CGRect.infinite,
        .optionOnScreenOnly,
        kCGNullWindowID,
        .nominalResolution
    )
}

// ── ScreenCaptureKit (macOS 14+) ─────────────────────────────────────

@available(macOS 14.0, *)
func captureSCK() async -> Result<CGImage, CaptureError> {
    do {
        let content = try await SCShareableContent.excludingDesktopWindows(
            false,
            onScreenWindowsOnly: false
        )
        guard let display = content.displays.first else {
            return .failure(CaptureError(code: "screen_capture_no_display", message: "No displays available"))
        }
        let filter = SCContentFilter(display: display, excludingWindows: [])
        let config = SCStreamConfiguration()
        // Size the output in points (display.width/height are points) so
        // it matches the cursor's point coordinates on Retina.
        config.width = display.width
        config.height = display.height
        // The UI renders its own teal cursor ring from cursorX/Y, and
        // the Windows DXGI frame likewise has no composited cursor — keep
        // parity so the cursor isn't drawn twice.
        config.showsCursor = false
        let image = try await SCScreenshotManager.captureImage(
            contentFilter: filter,
            configuration: config
        )
        return .success(image)
    } catch {
        // A TCC denial surfaces here. We can't reliably distinguish it
        // from other SCK errors via error code, but the preflight below
        // already catches the common deny case before we get here, so
        // anything reaching this point is treated as a soft SCK failure
        // (caller falls back to Quartz).
        return .failure(CaptureError(code: "sck_failed", message: "ScreenCaptureKit error: \(error.localizedDescription)"))
    }
}

// ── Argument parsing ─────────────────────────────────────────────────

func parseQuality() -> Int {
    let args = CommandLine.arguments
    if let i = args.firstIndex(of: "--quality"), i + 1 < args.count, let v = Int(args[i + 1]) {
        return max(1, min(100, v))
    }
    return 80
}

// ── Main ─────────────────────────────────────────────────────────────

let quality = parseQuality()

// TCC: consultar y, si hace falta, PEDIR una vez.
//
// Pedir no es opcional aunque parezca intrusivo:
// CGPreflightScreenCaptureAccess() solo consulta y NO registra el binario en
// Ajustes › Privacidad y seguridad › Grabación de pantalla. Solo
// CGRequestScreenCaptureAccess() lo hace. Mientras este helper solo
// consultaba, no aparecía en la lista y NO HABÍA FORMA de autorizarlo — ni
// siquiera a mano, porque el selector de Ajustes busca aplicaciones. Ese fue
// el callejón sin salida que nos tuvo dando vueltas.
//
// Se pide UNA sola vez por proceso, aquí en el arranque y no por fotograma:
// el helper es de vida larga, así que una petición por sesión de screen share
// es el mínimo que registra la entrada sin convertirse en spam de diálogos.
//
// La llamada NO espera a que el usuario decida. Devuelve el estado actual —
// normalmente false la primera vez — mientras el diálogo sigue abierto. Por
// eso el código que emitimos distingue los dos casos: si acabamos de pedirlo,
// el operador tiene que saber que hay alguien mirando un diálogo, no que algo
// está roto.
if !CGPreflightScreenCaptureAccess() {
    let grantedNow = CGRequestScreenCaptureAccess()
    if !grantedNow {
        emitError(
            "screen_recording_permission_pending",
            "Screen Recording is not granted yet. macOS has been asked for it and the entry now exists in System Settings > Privacy & Security > Screen Recording — someone at the Mac has to enable Tracenium there. Apple does not allow MDM to grant this."
        )
    }
}

let (cursorX, cursorY) = cursorPoint()

if #available(macOS 14.0, *) {
    let sem = DispatchSemaphore(value: 0)
    Task {
        switch await captureSCK() {
        case .success(let image):
            finish(image, quality: quality, cursorX: cursorX, cursorY: cursorY)
        case .failure(let err):
            // SCK failed for a non-permission reason — try Quartz before
            // giving up so one transient hiccup doesn't drop the frame.
            if let img = captureQuartz() {
                finish(img, quality: quality, cursorX: cursorX, cursorY: cursorY)
            }
            emitError(err.code, err.message)
        }
        sem.signal() // unreachable (both branches exit) — defensive only
    }
    sem.wait()
} else {
    // macOS 12.3 – 13.x : Quartz path.
    if let img = captureQuartz() {
        finish(img, quality: quality, cursorX: cursorX, cursorY: cursorY)
    }
    emitError("screen_capture_failed", "Quartz capture returned nil (no active display?)")
}
