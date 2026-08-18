// src/plugins/rcp/pty-session.ts
//
// RCP M1.S2 — bridges a node-pty PTY with the WebRTC DataChannel.
//
// Why node-pty (not child_process):
//   - PTY (pseudo terminal) gives the shell the terminal semantics
//     it expects: interactive prompt, line editing, signal handling,
//     window-size events. A bare `child_process.spawn` produces
//     ugly output for `cmd.exe` and outright breaks `bash` line
//     editing.
//   - node-pty is the de-facto cross-platform PTY for Node. Pulls
//     in `winpty` on Windows + `pty.cc` on Unix; same JS API on
//     both.
//
// Wire protocol on the DataChannel (M1.S2):
//
//   Browser → Agent:
//     {"type": "stdin", "data": "<utf8>"}
//     {"type": "resize", "cols": N, "rows": N}
//     {"type": "close"}
//
//   Agent → Browser:
//     {"type": "stdout", "data": "<utf8>"}    (stdout + stderr merged
//                                              — PTY conflates them)
//     {"type": "exit", "code": N}
//
// JSON framing chosen for readability + future extensibility. Per-
// keystroke overhead is ~20 bytes — negligible on any modern path.
// If profiling ever shows we're packet-bound (unlikely; keystrokes
// are sparse), Sprint 3+ can swap to a binary protocol.
//
// What this module does NOT do:
//   - Transcript recording. Sprint 3 hooks `onPtyData` to publish
//     chunks via the backend's gRPC stream for audit.
//   - Privilege escalation. M1 spawns under the agent's identity
//     (LocalSystem on Windows, the service account on Unix).
//     `allowPrivilegedShell` policy gate comes in M3.

// node-pty is CommonJS at runtime; the TS types ship via
// node-pty/typings but the require keeps interop predictable.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const nodePty = require("node-pty");
import * as fs from "node:fs";
import type { AgentContext } from "../../core/agent-context";

const IS_WINDOWS = process.platform === "win32";
const IS_MACOS = process.platform === "darwin";

// Sane defaults — overridden by the first resize message from the
// browser within milliseconds of channel open. 80x24 was the
// terminal default since VT100 and remains xterm.js's initial
// dimensions before its fit-addon measures the actual viewport.
const DEFAULT_COLS = 80;
const DEFAULT_ROWS = 24;

/**
 * Shell selection. M1.S2 hard-defaults to the platform's native
 * shell. M3 (or whenever we add session metadata in the offer)
 * will accept a `{shell: "powershell"}` override.
 */
function pickShell(): { file: string; args: string[] } {
  if (IS_WINDOWS) {
    // ComSpec resolves to cmd.exe on every supported Windows. We
    // default to cmd over powershell because: (a) cmd starts ~5x
    // faster, (b) PowerShell's COM-based progress bars don't render
    // well over a 80x24 terminal, (c) admins prefer to pick PS
    // explicitly when they need it.
    const file = process.env.ComSpec || "cmd.exe";
    return { file, args: [] };
  }
  // macOS + Linux. SHELL viene del login interactivo, que un demonio no
  // tiene: LaunchDaemon y systemd arrancan sin él, así que en la práctica
  // manda el fallback.
  if (process.env.SHELL) return { file: process.env.SHELL, args: [] };

  // En macOS el fallback histórico a /bin/bash hacía que cada sesión
  // empezara con el aviso de deprecación de Apple ("The default
  // interactive shell is now zsh…"), porque macOS congeló bash en la 3.2
  // de 2007 por la licencia GPLv3. Ruido en el primer renglón de cada
  // sesión de soporte, y encima invita al operador a correr un `chsh`
  // que cambiaría el shell de la cuenta en la máquina remota.
  // zsh es el shell por defecto desde 10.15 y está en todas las que
  // soportamos; comprobamos que exista igual, porque este fallback no es
  // sitio para dar por hecho nada.
  if (IS_MACOS && fs.existsSync("/bin/zsh")) return { file: "/bin/zsh", args: [] };

  return { file: "/bin/bash", args: [] };
}

export type PtySessionArgs = {
  sessionId: string;
  ctx: AgentContext;
  // Wired up by the caller (PeerSession). Called with a UTF-8
  // string to send across the DataChannel back to the browser.
  send: (text: string) => void;
  // Called when the PTY exits (operator typed `exit`, process
  // crashed, or we killed it on close). Caller (PeerSession)
  // uses this to tear down the WebRTC peer + send
  // RemoteSessionClose to the backend.
  onExit: (code: number, reason: string) => void;
};

export class PtySession {
  private pty: any;
  private disposed = false;
  private cols = DEFAULT_COLS;
  private rows = DEFAULT_ROWS;

  constructor(private readonly args: PtySessionArgs) {
    const { sessionId, ctx } = args;
    const { file, args: shellArgs } = pickShell();

    try {
      this.pty = nodePty.spawn(file, shellArgs, {
        name: "xterm-color",
        cols: this.cols,
        rows: this.rows,
        // Inherit cwd from the agent process. On Windows that's
        // typically System32; ops can `cd` after the prompt is up.
        cwd: process.cwd(),
        // Drop sensitive env vars before passing to the shell — an
        // operator with shell access shouldn't be able to inspect
        // privsvc tokens from /proc/<pid>/environ.
        env: redactedEnv()
      });
    } catch (err: any) {
      ctx.logger?.error?.("[rcp pty] spawn failed", {
        sessionId,
        shell: file,
        err: err?.message || String(err)
      });
      throw err;
    }

    ctx.logger?.info?.("[rcp pty] shell spawned", {
      sessionId,
      shell: file,
      pid: this.pty.pid,
      cols: this.cols,
      rows: this.rows
    });

    // PTY → DataChannel. Stdout + stderr are merged by the PTY.
    // We frame each chunk as a JSON 'stdout' message.
    this.pty.onData((data: string) => {
      if (this.disposed) return;
      args.send(JSON.stringify({ type: "stdout", data }));
    });

    this.pty.onExit(({ exitCode, signal }: { exitCode: number; signal?: number }) => {
      if (this.disposed) return;
      ctx.logger?.info?.("[rcp pty] shell exited", {
        sessionId,
        exitCode,
        signal
      });
      // Tell the browser first; then notify the caller so it can
      // tear down the WebRTC peer. Order matters: the close
      // message gets serialized through the DataChannel BEFORE the
      // peer goes away.
      try {
        args.send(JSON.stringify({ type: "exit", code: exitCode }));
      } catch {
        /* channel may already be down — ignore */
      }
      args.onExit(exitCode, signal ? `signal:${signal}` : "shell_exit");
    });
  }

  /**
   * Forward an inbound DataChannel message from the browser into
   * the PTY. Errors are swallowed + logged — a malformed message
   * from the browser shouldn't take down the shell.
   */
  handleMessage(raw: string): void {
    if (this.disposed) return;
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.args.ctx.logger?.warn?.("[rcp pty] bad JSON from browser", {
        sessionId: this.args.sessionId,
        sample: raw.slice(0, 80)
      });
      return;
    }
    if (!parsed || typeof parsed !== "object") return;

    switch (parsed.type) {
      case "stdin": {
        const data = typeof parsed.data === "string" ? parsed.data : "";
        if (!data) return;
        try {
          this.pty.write(data);
        } catch (err: any) {
          this.args.ctx.logger?.warn?.("[rcp pty] write failed", {
            sessionId: this.args.sessionId,
            err: err?.message
          });
        }
        return;
      }
      case "resize": {
        const cols = Number(parsed.cols);
        const rows = Number(parsed.rows);
        // Defensive caps — xterm.js will never request these but
        // a malicious client could.
        if (
          !Number.isFinite(cols) ||
          !Number.isFinite(rows) ||
          cols < 1 ||
          rows < 1 ||
          cols > 500 ||
          rows > 500
        ) {
          return;
        }
        this.cols = cols;
        this.rows = rows;
        try {
          this.pty.resize(cols, rows);
        } catch (err: any) {
          this.args.ctx.logger?.warn?.("[rcp pty] resize failed", {
            sessionId: this.args.sessionId,
            err: err?.message
          });
        }
        return;
      }
      case "close": {
        // Polite close — browser asked us to terminate. Same path
        // as `exit` typed at the prompt.
        this.dispose("operator_closed");
        return;
      }
      default:
        // Ignore unknown types — forward-compat with future
        // protocol additions.
        return;
    }
  }

  dispose(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;
    try {
      this.pty?.kill?.();
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp pty] kill failed", {
        sessionId: this.args.sessionId,
        err: err?.message
      });
    }
    this.args.ctx.logger?.info?.("[rcp pty] disposed", {
      sessionId: this.args.sessionId,
      reason
    });
  }
}

/**
 * Filter env vars that shouldn't be visible inside the operator's
 * shell. Conservative blacklist — anything that looks like a
 * secret keyword. Operator can still inspect what's set; that's by
 * design (auditors do this), they just can't pull our service
 * credentials.
 */
function redactedEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  const blocked = /TOKEN|SECRET|API_KEY|PASSWORD|PRIVSVC|TRACENIUM_/i;
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (blocked.test(k)) continue;
    out[k] = v;
  }
  // Mark the session for shells that read PROMPT_COMMAND / PS1 —
  // useful for audit ("you're inside a Tracenium remote session").
  out.TRACENIUM_REMOTE_SESSION = "1";
  return out;
}
