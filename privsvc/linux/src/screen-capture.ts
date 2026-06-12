// privsvc/linux/src/screen-capture.ts
//
// RCP M3.S1 — screen capture for Linux (X11 only, initial).
//
// ── Why this is NOT a pure-TS capture ────────────────────────────────
//
//   PrivSvc runs as a root systemd service, outside any graphical
//   session. X11 capture (XGetImage on the root window) requires:
//     1. the X server's DISPLAY (e.g. :0), and
//     2. an XAUTHORITY cookie authorising a connection, and
//     3. ideally running as the session user.
//   None of these are available to a faceless root daemon by default,
//   so capture is delegated to a small C helper (`tracenium-screencap`,
//   see privsvc/linux/helpers/) linked against libX11 + libjpeg. This
//   orchestrator discovers the active session, hands the helper a
//   DISPLAY + XAUTHORITY, runs it as the session user, and maps its
//   one-line JSON output onto the SAME response shape the Windows DXGI
//   and macOS Swift-helper paths return:
//     { ok, data(base64 jpeg), width, height, cursorX, cursorY }.
//
// ── Wayland ──────────────────────────────────────────────────────────
//
//   Per the sprint decision, Wayland is out of scope for the initial
//   landing: there is no portable screenshot API without the
//   xdg-desktop-portal + PipeWire dance, which needs an in-session agent
//   and user consent. When the active session is Wayland we return a
//   stable `wayland_unsupported` code so the operator UI shows a clear
//   message instead of a black frame. (Most GNOME/KDE Wayland sessions
//   still run Xwayland, but Xwayland refuses XGetImage of native Wayland
//   client windows for security — capturing it would yield a mostly
//   empty desktop, which is worse than an honest error.)

import { execFile } from "child_process";
import path from "path";
import fs from "fs";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const HELPER_TIMEOUT_MS = 5000;
const HELPER_MAX_STDOUT = 16 * 1024 * 1024;

type GraphicalSession = {
  uid: number;
  user: string;
  display: string;
  type: string; // "x11" | "wayland" | "tty" | ...
};

function helperPath(): string {
  const override = process.env.TRACENIUM_SCREENCAP_HELPER;
  if (override && override.trim()) return override.trim();
  return path.resolve(__dirname, "tracenium-screencap");
}

function execText(cmd: string, args: string[], timeout = 2500): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 1024 * 1024 }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(String(stdout || ""));
    });
  });
}

/**
 * Parse `loginctl show-session <id> -p Key` output (`Key=Value` lines).
 */
function parseLoginctlProps(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const idx = raw.indexOf("=");
    if (idx <= 0) continue;
    out[raw.slice(0, idx).trim()] = raw.slice(idx + 1).trim();
  }
  return out;
}

/**
 * Find the active graphical session via logind. Picks the first local,
 * active session that has a usable Display. Returns its type so the
 * caller can short-circuit Wayland.
 */
async function activeGraphicalSession(): Promise<GraphicalSession | null> {
  const list = await execText("loginctl", ["list-sessions", "--no-legend"]);
  if (!list) {
    logger.warn("screencap_loginctl_unavailable");
    return null;
  }

  // Columns: SESSION UID USER SEAT TTY  (whitespace separated)
  const sessionIds: string[] = [];
  for (const line of list.split("\n")) {
    const cols = line.trim().split(/\s+/);
    if (cols[0]) sessionIds.push(cols[0]);
  }

  let fallback: GraphicalSession | null = null;

  for (const id of sessionIds) {
    const props = await execText("loginctl", [
      "show-session",
      id,
      "-p",
      "Active",
      "-p",
      "Remote",
      "-p",
      "Type",
      "-p",
      "Display",
      "-p",
      "Name",
      "-p",
      "User"
    ]);
    if (!props) continue;
    const p = parseLoginctlProps(props);

    if (p.Remote === "yes") continue; // SSH / remote — no local framebuffer
    const uid = Number(p.User);
    const user = p.Name || "";
    const type = (p.Type || "").toLowerCase();
    const display = p.Display || "";

    if (!Number.isInteger(uid) || !user) continue;

    // A Wayland session still reports here; we keep it so the caller can
    // emit `wayland_unsupported` rather than silently moving on and
    // claiming "no desktop".
    if (type === "wayland") {
      const candidate = { uid, user, display, type };
      if (p.Active === "yes") return candidate;
      fallback ||= candidate;
      continue;
    }

    if (type === "x11" || display) {
      const candidate = { uid, user, display: display || ":0", type: type || "x11" };
      if (p.Active === "yes") return candidate;
      fallback ||= candidate;
    }
  }

  return fallback;
}

/**
 * Best-effort XAUTHORITY discovery for an X11 session.
 *
 * Strategy, most-reliable first:
 *   1. Parse `-auth <path>` from the running Xorg/X process cmdline —
 *      display managers (gdm/lightdm/sddm) always pass this and it's the
 *      cookie that actually authorises us.
 *   2. Probe well-known per-DM locations.
 *   3. Give up and return null — the helper then tries $HOME/.Xauthority
 *      on its own, and as a last resort an unauthenticated local connect.
 */
async function resolveXauthority(session: GraphicalSession, home: string | null): Promise<string | null> {
  // 1. Xorg -auth
  const ps = await execText("pgrep", ["-a", "-x", "Xorg"]);
  const psFallback = ps || (await execText("pgrep", ["-af", "X"]));
  if (psFallback) {
    for (const line of psFallback.split("\n")) {
      if (session.display && !line.includes(session.display)) {
        // Prefer the line matching our display, but don't hard-require it.
      }
      const m = line.match(/-auth\s+(\S+)/);
      if (m && fs.existsSync(m[1])) return m[1];
    }
  }

  // 2. Known locations
  const candidates = [
    `/run/user/${session.uid}/gdm/Xauthority`,
    `/run/user/${session.uid}/.Xauthority`,
    session.display ? `/var/run/lightdm/root/${session.display}` : "",
    home ? path.join(home, ".Xauthority") : ""
  ].filter(Boolean) as string[];

  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }

  return null;
}

function homeForUser(user: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile("getent", ["passwd", user], { timeout: 2000 }, (err, stdout) => {
      if (err) return resolve(null);
      // name:x:uid:gid:gecos:home:shell
      const parts = String(stdout).trim().split(":");
      resolve(parts[5] || null);
    });
  });
}

type HelperRun = { code: number | null; stdout: string; stderr: string };

/**
 * Run the helper as the session user with DISPLAY + XAUTHORITY in env.
 *
 *   runuser -u <user> -- env DISPLAY=<d> [XAUTHORITY=<x>] <helper> --quality <q>
 *
 * `runuser` (util-linux) drops privileges without a PAM password when
 * the caller is root — cleaner than `su -c` (no shell quoting, no login
 * scripts). If runuser is absent we fall back to `su`.
 */
function runHelper(
  session: GraphicalSession,
  xauthority: string | null,
  helper: string,
  quality: number
): Promise<HelperRun> {
  const envArgs = [`DISPLAY=${session.display || ":0"}`];
  if (xauthority) envArgs.push(`XAUTHORITY=${xauthority}`);

  return new Promise((resolve) => {
    const finish = (err: any, stdout: string, stderr: string) => {
      const code =
        err && typeof (err as any).code === "number" ? (err as any).code : err ? 1 : 0;
      resolve({ code, stdout: String(stdout || ""), stderr: String(stderr || "") });
    };

    const args = ["-u", session.user, "--", "env", ...envArgs, helper, "--quality", String(quality)];
    execFile(
      "runuser",
      args,
      { timeout: HELPER_TIMEOUT_MS, maxBuffer: HELPER_MAX_STDOUT },
      (err, stdout, stderr) => {
        // runuser missing (ENOENT) → fall back to su.
        if (err && (err as any).code === "ENOENT") {
          const suCmd = `env ${envArgs.join(" ")} ${helper} --quality ${quality}`;
          execFile(
            "su",
            [session.user, "-c", suCmd],
            { timeout: HELPER_TIMEOUT_MS, maxBuffer: HELPER_MAX_STDOUT },
            (e2, out2, errr2) => finish(e2, String(out2 || ""), String(errr2 || ""))
          );
          return;
        }
        finish(err, String(stdout || ""), String(stderr || ""));
      }
    );
  });
}

export async function handleScreenCapture(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  let quality = Number(req.params?.quality ?? 80);
  if (!Number.isFinite(quality)) quality = 80;
  quality = Math.max(1, Math.min(100, Math.round(quality)));

  const session = await activeGraphicalSession();
  if (!session) {
    return fail(
      req.id,
      "no_interactive_desktop",
      "No active graphical session. Screen sharing requires a user logged into a local desktop. " +
        "For headless servers, use rcp.shell instead."
    );
  }

  if (session.type === "wayland") {
    return fail(
      req.id,
      "wayland_unsupported",
      "The active session is Wayland, which is not supported for screen sharing in this release. " +
        "Switch the session to X11 (Xorg) to enable screen capture."
    );
  }

  const helper = helperPath();
  if (!fs.existsSync(helper)) {
    logger.error("screencap_helper_missing", { helper });
    return fail(req.id, "screen_capture_helper_missing", "Screen capture helper not installed");
  }

  const home = await homeForUser(session.user);
  const xauthority = await resolveXauthority(session, home);
  if (!xauthority) {
    logger.warn("screencap_no_xauthority", { display: session.display, user: session.user });
  }

  let result: HelperRun;
  try {
    result = await runHelper(session, xauthority, helper, quality);
  } catch (err: any) {
    return fail(req.id, "screen_capture_spawn_failed", err?.message || String(err));
  }

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
