// privsvc/macos/src/screen-capture.ts
//
// RCP M3.S1 — screen capture for macOS.
//
// ── Why this is NOT a pure-TS BitBlt-equivalent ──────────────────────
//
//   PrivSvc runs as a root LaunchDaemon (see
//   launchd/com.certusws.tracenium.privsvc.plist — no UserName key, so
//   it runs as root in the *system* bootstrap context, NOT the logged-in
//   user's Aqua/GUI session).
//
//   macOS ScreenCaptureKit AND the legacy Quartz CGWindowListCreateImage
//   both require (1) a TCC "Screen Recording" grant and (2) execution
//   inside the active GUI session. A faceless root daemon satisfies
//   neither. This is the macOS analog of the Windows Session-0 problem —
//   except macOS has no equivalent of DXGI Desktop Duplication that lets
//   a Session-0 service read the active desktop directly. There is no
//   in-process path; capture MUST happen inside the user's session.
//
// ── Architecture ─────────────────────────────────────────────────────
//
//   Capture is delegated to a small signed Swift helper
//   (`tracenium-screencap`, see privsvc/macos/helpers/) that does the
//   actual ScreenCaptureKit / Quartz work. This orchestrator:
//
//     1. finds the active console user (the GUI session owner),
//     2. spawns the helper INTO that user's session via
//        `launchctl asuser <uid> sudo -u <user> …` so it inherits the
//        Aqua bootstrap ScreenCaptureKit needs to attach to,
//     3. reads a single JSON line from the helper's stdout, and
//     4. maps it onto the SAME response shape the Windows DXGI path
//        returns: { ok, data(base64 jpeg), width, height, cursorX,
//        cursorY }. The caller (src/plugins/rcp/screen-session.ts:252)
//        is platform-agnostic and reads this shape without a branch.
//
//   TCC is pre-granted fleet-wide via an MDM PPPC profile keyed to the
//   helper's code-signing identity (Team ID + bundle id) — no
//   interactive prompt. An unsigned / unprovisioned helper is denied by
//   TCC; the helper detects that and reports
//   `no_screen_recording_permission` so the operator UI can surface a
//   useful message instead of a black frame.

import { execFile } from "child_process";
import path from "path";
import fs from "fs";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

// A single capture must return well within the screen-session capture
// loop's frame budget. The helper's own ScreenCaptureKit timeout is
// shorter; this is the hard outer bound that also covers launchctl /
// sudo process spin-up.
const HELPER_TIMEOUT_MS = 5000;

// base64 JPEG of a 5K display at high quality can approach a few MB.
// 16 MB of stdout headroom is generous without being abusable (the
// helper hard-caps quality at 100 and only ever emits one frame).
const HELPER_MAX_STDOUT = 16 * 1024 * 1024;

// Real macOS user accounts start at uid 501. Anything below 500 is a
// system/service account (root, _windowserver, _mbsetupuser, …) which
// means no human is logged into the GUI.
const MIN_INTERACTIVE_UID = 500;

/**
 * Absolute path to the bundled Swift capture helper.
 *
 * Layout: in the installed bundle the helper ships beside privsvc.js
 * under the PrivSvc/macos dir; in dev (`node dist/index.js`) it resolves
 * relative to __dirname. `TRACENIUM_SCREENCAP_HELPER` overrides both for
 * the build/test harness.
 */
export function helperPath(): string {
  const override = process.env.TRACENIUM_SCREENCAP_HELPER;
  if (override && override.trim()) return override.trim();
  // dist/screen-capture.js → ./tracenium-screencap (installed sibling)
  // Dentro del bundle. El helper dejó de ser un ejecutable suelto porque TCC
  // no le daba sitio: un binario Unix pelado no aparece de forma fiable en la
  // lista de Grabación de Pantalla, y el selector de Ajustes solo deja escoger
  // aplicaciones — así que el permiso no se podía conceder ni a mano.
  //
  // Se lanza el ejecutable de dentro, no `open` el bundle: necesitamos su
  // stdout. TCC lee igualmente la identidad del bundle que lo contiene, que es
  // lo que hace que el permiso se ancle donde debe.
  const bundled = path.resolve(
    __dirname,
    "Tracenium Screen Helper.app/Contents/MacOS/tracenium-screencap"
  );
  if (fs.existsSync(bundled)) return bundled;

  // Reserva para la ventana de actualización: un agente con el .pkg anterior
  // todavía tiene el ejecutable suelto. Falla por TCC igual que antes, pero
  // con el error de siempre en vez de uno sobre un fichero que falta.
  return path.resolve(__dirname, "tracenium-screencap");
}

/**
 * The user who owns the active GUI session, or null when the Mac is at
 * the login window / has no interactive desktop.
 *
 * `/dev/console` is owned by the console (GUI) user while someone is
 * logged in, and by root at the login window. `stat -f "%u %Su"` gives
 * both the numeric uid and the name in one shot.
 */
export function activeConsoleUser(): Promise<{ uid: number; name: string } | null> {
  return new Promise((resolve) => {
    execFile("/usr/bin/stat", ["-f", "%u %Su", "/dev/console"], { timeout: 2000 }, (err, stdout) => {
      if (err) {
        logger.warn("screencap_console_user_failed", { error: err.message });
        return resolve(null);
      }
      const m = String(stdout).trim().match(/^(\d+)\s+(\S+)$/);
      if (!m) return resolve(null);
      const uid = Number(m[1]);
      const name = m[2];
      if (!Number.isInteger(uid) || uid < MIN_INTERACTIVE_UID || name === "root") {
        return resolve(null);
      }
      resolve({ uid, name });
    });
  });
}

type HelperRun = { code: number | null; stdout: string; stderr: string };

/**
 * Spawn the capture helper inside the console user's GUI session.
 *
 *   launchctl asuser <uid> sudo -n -u <name> <helper> --quality <q>
 *
 * - `launchctl asuser <uid>` re-parents the spawn into the user's Aqua
 *   (per-user) Mach bootstrap — without this ScreenCaptureKit has no
 *   GUI session to attach to and fails.
 * - `sudo -n -u <name>` drops from root (the daemon's identity) to the
 *   console user so TCC attributes the Screen-Recording grant to the
 *   right subject. `-n` = never prompt (root sudo is non-interactive);
 *   a prompt would mean misconfiguration, and we want a fast failure,
 *   not a hang.
 *
 * ⚠️ The exact incantation + the PPPC grant must be validated on a real
 * managed Mac (smoke test) — same caveat the Windows DXGI path carries
 * for Session-0 capture. The error codes below are designed so the UI
 * degrades gracefully if it isn't.
 */
function runHelper(uid: number, name: string, helper: string, quality: number): Promise<HelperRun> {
  return new Promise((resolve) => {
    const args = ["asuser", String(uid), "sudo", "-n", "-u", name, helper, "--quality", String(quality)];
    execFile(
      "/bin/launchctl",
      args,
      { timeout: HELPER_TIMEOUT_MS, maxBuffer: HELPER_MAX_STDOUT },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as any).code === "number"
            ? (err as any).code
            : err
              ? 1
              : 0;
        resolve({ code, stdout: String(stdout || ""), stderr: String(stderr || "") });
      }
    );
  });
}

/**
 * IPC entry-point for `screen.capture`. Mirrors the contract of the
 * Windows IpcGrpcHandlers.HandleScreenCapture → ScreenCaptureDxgi.Capture
 * path: returns { ok, data, width, height, cursorX, cursorY } on success
 * and a stable error code on failure.
 */
export async function handleScreenCapture(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  let quality = Number(req.params?.quality ?? 80);
  if (!Number.isFinite(quality)) quality = 80;
  quality = Math.max(1, Math.min(100, Math.round(quality)));

  const user = await activeConsoleUser();
  if (!user) {
    return fail(
      req.id,
      "no_interactive_desktop",
      "No active interactive desktop. Screen sharing requires a user logged into the Mac. " +
        "For the login window / headless state, use rcp.shell instead."
    );
  }

  const helper = helperPath();
  if (!fs.existsSync(helper)) {
    logger.error("screencap_helper_missing", { helper });
    return fail(req.id, "screen_capture_helper_missing", "Screen capture helper not installed");
  }

  let result: HelperRun;
  try {
    result = await runHelper(user.uid, user.name, helper, quality);
  } catch (err: any) {
    return fail(req.id, "screen_capture_spawn_failed", err?.message || String(err));
  }

  // The helper prints exactly one JSON line on stdout. stderr is human
  // log noise (and any sudo/launchctl diagnostics) — keep it in the
  // privsvc log (root-owned, on-host) and never forward it across IPC.
  const line =
    result.stdout
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
      .pop() || "";

  if (!line) {
    logger.warn("screencap_helper_no_output", {
      code: result.code,
      stderr: result.stderr.slice(0, 500)
    });
    return fail(
      req.id,
      "screen_capture_no_output",
      result.code === 0 ? "Helper produced no output" : `Helper exited with code ${result.code}`
    );
  }

  let parsed: any;
  try {
    parsed = JSON.parse(line);
  } catch {
    logger.warn("screencap_helper_bad_json", { code: result.code, head: line.slice(0, 200) });
    return fail(req.id, "screen_capture_bad_output", "Helper output was not valid JSON");
  }

  if (!parsed || parsed.ok !== true) {
    // Pass the helper's own stable code through (e.g.
    // no_screen_recording_permission, screen_capture_no_display) so the
    // UI branches on the same vocabulary across all three OSes.
    const code = String(parsed?.code || "screen_capture_failed");
    const message = String(parsed?.message || "Screen capture failed");
    logger.warn("screencap_helper_error", { code, message: message.slice(0, 200) });
    return fail(req.id, code, message);
  }

  return success(req.id, {
    ok: true,
    data: String(parsed.data || ""),
    width: Number(parsed.width ?? 0),
    height: Number(parsed.height ?? 0),
    cursorX: Number(parsed.cursorX ?? -1),
    cursorY: Number(parsed.cursorY ?? -1)
  });
}
