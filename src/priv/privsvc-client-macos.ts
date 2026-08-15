// src/priv/privsvc-client-macos.ts
import net from "net";
import { randomUUID } from "crypto";
import { EventEmitter } from "events";
import type { PrivSvcRequest, PrivSvcResponse, PrivSvcPush } from "./ipc-types";

const SOCKET_PATH = "/var/run/tracenium/privsvc.sock";
const DEFAULT_TIMEOUT_MS = 8000;

export function getTimeoutForMethod(method: string): number {
  switch (method) {
    case "grpc.connect":
      return 60000;
    case "grpc.facts.send":
    case "grpc.facts.chunk":
    case "grpc.ack":
    case "grpc.close":
      return 30000;
    case "grpc.heartbeat":
      // Short timeout — heartbeat is a fire-and-forget write to the
      // local bridge; if PrivSvc is unresponsive the agent should know
      // quickly and trigger a reconnect.
      return 5000;
    // ── RCP signaling + audit (agent → backend) ──────────────────────
    // The handler on the PrivSvc side is a single write to the gRPC
    // stream — microseconds of work. This budget is NOT about the
    // handler being slow; it exists because the IPC pipe is a SERIAL
    // lane: one request is served at a time, and the client's clock
    // starts at the write, not when PrivSvc picks the request up.
    //
    // ICE candidates are the pathological case. libdatachannel emits
    // them in a BURST (4-5 at once as gathering completes), so the
    // 2nd-5th sit queued behind the 1st plus whatever else was already
    // in flight. At the 8s default they expired before ever reaching
    // the stream, the browser got no remote candidates, and the session
    // died with `ice_failed` — observed in production on 2026-08-15:
    //   "PrivSvc timeout: grpc.send.remoteSessionIce did not answer
    //    within 8000ms"
    //
    // ⚠️ This is MITIGATION, not a cure. If the lane is occupied by a
    // long privileged operation (sdp.install budgets 1800s) no signaling
    // budget saves us. The real fix is a separate lane / priority for
    // latency-critical signaling — see the IPC serialization ADR.
    //
    // 30s: comfortably longer than any realistic queue behind a normal
    // request, and past the point where a late ICE candidate is still
    // useful anyway (the browser's connectivity checks have moved on).
    case "grpc.send.remoteSessionAnswer":
    case "grpc.send.remoteSessionIce":
    case "grpc.send.remoteSessionClose":
    case "grpc.send.remoteSessionError":
    case "grpc.send.remoteSessionTranscript":
    case "grpc.send.remoteFileTransferAudit":
    case "grpc.send.remoteScreenAudit":
      return 30000;
    case "software.inventory":
      return 60000;
    case "security.compliance":
      // 90s (was 30s, which violated THE INVARIANT below): the handler's
      // parallel phase is bounded by system_profiler at 25s, then
      // collectSmb (8s) and collectSsh (8s) run sequentially, and
      // per-share `ls -lde` risk probes (8s each) stretch the worst
      // case past 40s on hosts with several shares. 45s ceiling
      // (see test/priv/ipc-timeout-ordering.test.ts) + margin.
      return 90000;
    // ── Patch Management ─────────────────────────────────────────────
    //
    // THE INVARIANT: job timeout > THIS client budget > privsvc handler
    // budget. If the caller does not outwait the handler, a handler that
    // hits its own ceiling can never deliver its diagnostic — the client
    // has already given up — and the failure surfaces as a bare timeout
    // with an empty result. That is precisely how a macOS patch_install
    // failed in production on 2026-08-11: privsvc, client and job were all
    // 3600s, so all three expired together and the job completed with no
    // result_json at all.
    //
    // privsvc ceilings these must stay above:
    //   patch.install — Windows 90min (WUA), macOS/Linux 60min
    //   patch.scan    — macOS 120s (softwareupdate --list), Windows 60s
    case "patch.install":
      return 95 * 60 * 1000; // privsvc: 90min (Windows) + 5min margin
    case "patch.scan":
      return 180 * 1000; // privsvc: 120s (macOS) + margin
    // ── SDP + self-update ────────────────────────────────────────────
    //
    // These were falling through to the 8s default while the privsvc side
    // budgets 600s for a download and 1740s for an install: the client gave
    // up long before the handler could answer, surfacing as "PrivSvc
    // timeout" even though the privileged work was still running fine. A
    // failed agent self-update on a live endpoint was traced to exactly
    // this. The invariant is that the CALLER must outwait the handler, so
    // each budget sits just above the privsvc-side ceiling.
    case "sdp.download":
      return 700 * 1000; // privsvc: 600s + margin
    case "sdp.install":
    case "sdp.uninstall":
      return 1800 * 1000; // privsvc: 1740s + margin
    case "sdp.dp.prefetch":
      return 900 * 1000; // agent asks privsvc for 840s + margin
    case "sdp.verifySignature":
      // Signature verification is not instant: building the trust chain can
      // block on network I/O inside the OS call (AIA fetch of intermediates)
      // on hosts without a direct outbound path.
      return 60 * 1000;
    case "sdp.detect":
      // command_exit rules run operator-supplied probes; the privsvc caps
      // each at 15-30s.
      return 60 * 1000;
    case "agent.install":
      return 1800 * 1000;
    default:
      return DEFAULT_TIMEOUT_MS;
  }
}

const CONNECT_TIMEOUT_MS = 8000;
const MAX_PENDING = 500;
const MAX_BUFFER_CHARS = 2 * 1024 * 1024;

type Pending = {
  resolve: (r: PrivSvcResponse) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
};

export class PrivSvcClient extends EventEmitter {
  private socket: net.Socket | null = null;
  private buffer = "";
  private connecting: Promise<void> | null = null;
  private pending = new Map<string, Pending>();
  private closedByClient = false;

  private earlyPushQueue: PrivSvcPush[] = [];
  private pushListenerAttached = false;

  onPush(cb: (msg: PrivSvcPush) => void) {
    this.pushListenerAttached = true;
    this.removeAllListeners("push");
    this.on("push", cb);

    if (this.earlyPushQueue.length > 0) {
      for (const msg of this.earlyPushQueue) {
        try {
          this.emit("debug", { stage: "push_flush", msg });
          cb(msg);
        } catch (e) {
          this.emit("error", e);
        }
      }
      this.earlyPushQueue = [];
    }
  }

  private async ensureConnected(): Promise<void> {
    if (this.socket?.destroyed) this.socket = null;
    if (this.socket && !this.socket.destroyed) return;
    if (this.connecting) return this.connecting;
    if (this.closedByClient) throw new Error("PrivSvc client is closed");

    this.connecting = new Promise<void>((resolve, reject) => {
      const s = new net.Socket();

      // `settle` guarantees the connecting promise ALWAYS resolves or
      // rejects exactly once AND always clears `this.connecting`. The prior
      // version cleared the connect-timeout on 'error'/'close' but never
      // rejected the promise nor nulled `this.connecting`, so a connect that
      // FAILED (ECONNREFUSED while PrivSvc was mid-restart) left
      // `this.connecting` pending forever. Every later call() then hit
      // `if (this.connecting) return this.connecting` and awaited that dead
      // promise with NO timeout — wedging grpc.connect + heartbeat +
      // inventory + compliance for days (the macOS/W11 zombie 2026-07-19).
      let settled = false;
      const settle = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(t);
        this.connecting = null;
        if (err) reject(err); else resolve();
      };

      s.on("data", (data) => this.onData(data));
      s.on("error", (err) => {
        this.onSocketError(err);
        settle(err instanceof Error ? err : new Error(String(err)));
      });
      s.on("close", () => {
        this.onSocketClose();
        settle(new Error("PrivSvc socket closed during connect"));
      });
      s.on("connect", () => {
        this.socket = s;
        this.closedByClient = false;
        settle();
      });

      const t = setTimeout(() => {
        try {
          s.destroy();
        } catch {}
        settle(new Error("PrivSvc connect timeout"));
      }, CONNECT_TIMEOUT_MS);

      s.connect(SOCKET_PATH);
    });

    const conn = this.connecting;
    if (!conn) return;
    await conn;

    if (!this.socket || this.socket.destroyed) {
      throw new Error("PrivSvc connection failed after connect attempt");
    }
  }

  private onData(data: Buffer | string) {
    const chunk = typeof data === "string" ? data : data.toString("utf8");
    this.emit("debug", { stage: "raw_chunk" });
    this.buffer += chunk;

    if (this.buffer.length > MAX_BUFFER_CHARS) {
      this.buffer = "";
      this.onSocketError(new Error("PrivSvc buffer overflow"));
      try {
        this.socket?.destroy();
      } catch {}
      return;
    }

    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() || "";

    for (const line of lines) {
      const txt = line.replace(/\r$/, "").trim();
      if (!txt) continue;

      let msg: any;
      try {
        msg = JSON.parse(txt);
        this.emit("debug", { stage: "parsed" });
      } catch {
        this.emit("debug", { stage: "parse_error", raw: txt });
        continue;
      }

      this.emit("debug", {
        stage: "dispatch",
        id: msg?.id,
        method: msg?.method,
        hasOk: Object.prototype.hasOwnProperty.call(msg, "ok"),
        hasError: Object.prototype.hasOwnProperty.call(msg, "error"),
        pendingSize: this.pending.size
      });

      const id = msg?.id;
      const isResponse =
        typeof id === "string" &&
        (Object.prototype.hasOwnProperty.call(msg, "ok") ||
          Object.prototype.hasOwnProperty.call(msg, "error"));

      if (isResponse) {
        if (!id) {
          this.emit("error", new Error("PrivSvc response without id"));
          continue;
        }

        if (this.pending.has(id)) {
          const p = this.pending.get(id)!;
          this.pending.delete(id);
          clearTimeout(p.timer);
          this.emit("debug", { stage: "response_match", id });
          p.resolve(msg as PrivSvcResponse);
        } else {
          this.emit("debug", {
            stage: "orphan_response",
            id,
            pendingSize: this.pending.size
          });
        }
        continue;
      }

      const isPush = typeof msg?.method === "string";
      if (isPush) {
        if (this.pushListenerAttached) {
          this.emit("debug", { stage: "push_emit", msg });
          this.emit("push", msg as PrivSvcPush);
        } else {
          this.emit("debug", { stage: "push_buffered", msg });
          if (this.earlyPushQueue.length < 1000) {
            this.earlyPushQueue.push(msg as PrivSvcPush);
          }
        }
        continue;
      }

      this.emit("debug", { stage: "unknown_message", msg });
    }
  }

  private onSocketError(err: any) {
    const errCode = String(err?.code || "");
    const errMessage = String(err?.message || err || "");

    if (errCode === "EPIPE" || /EPIPE/i.test(errMessage)) {
      this.emit("debug", { stage: "epipe_detected", errCode, errMessage });
    }

    const sock = this.socket;
    this.socket = null;

    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(errMessage || `PrivSvc socket error (${id})`));
    }

    try {
      sock?.destroy();
    } catch {}

    // EventEmitter contract: emitting "error" without a listener throws
    // synchronously. No consumer in the codebase subscribes to our
    // "error" event (checked at grep-time), so this throw used to land
    // in service.ts's uncaughtException handler. Before the fix to that
    // handler, the process kept running with the socket gone and every
    // subsequent .call() would queue against a null socket. After the
    // handler fix, this throw IS the trigger for a process exit + clean
    // restart — but exiting on transient privsvc-restart events is
    // overkill, and there's a more useful signal we can emit instead.
    //
    // The right model: privsvc restarting is a recoverable event for
    // grpc-client (it pushes `grpc.disconnected` which triggers a
    // reconnect). The socket error is just the local manifestation of
    // the same underlying state — so emit "disconnect" (a non-error
    // event name that EventEmitter doesn't auto-throw), include the
    // error payload for diagnostics, and let onSocketClose drive the
    // recovery as it already does.
    //
    // We still emit "error" IF a listener is attached — preserving the
    // public contract for any future consumer that wants the strong
    // signal. Listener-guard is the canonical Node pattern for opt-in
    // error broadcasting on EventEmitters.
    if (this.listenerCount("error") > 0) {
      this.emit("error", err);
    } else {
      this.emit("disconnect", { err, code: errCode, message: errMessage });
    }
  }

  private onSocketClose() {
    const wasManual = this.closedByClient;

    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(`PrivSvc connection closed (${id})`));
    }

    const disconnectMsg: PrivSvcPush = {
      v: 1,
      method: "grpc.disconnected",
      params: { manual: wasManual }
    };

    if (this.pushListenerAttached) {
      this.emit("debug", { stage: "push_emit", msg: disconnectMsg });
      this.emit("push", disconnectMsg);
    } else {
      this.emit("debug", { stage: "push_buffered", msg: disconnectMsg });
      if (this.earlyPushQueue.length < 1000) {
        this.earlyPushQueue.push(disconnectMsg);
      }
    }

    this.emit("close");
    this.buffer = "";
    this.socket = null;
  }

  async call(req: PrivSvcRequest): Promise<PrivSvcResponse> {
    await this.ensureConnected();

    if (this.pending.size >= MAX_PENDING) {
      throw new Error(`PrivSvc pending requests overflow (${MAX_PENDING})`);
    }

    if (!req.id) req.id = randomUUID();

    return new Promise<PrivSvcResponse>((resolve, reject) => {
      const id = req.id!;
      const timeoutMs = getTimeoutForMethod(req.method);

      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.emit("debug", { stage: "timeout", id, method: req.method });
        // Name the method and the budget: a bare "PrivSvc timeout" told an
        // operator nothing about WHICH privileged call hung, which is what
        // made a stalled self-update take a code read to diagnose.
        reject(new Error(`PrivSvc timeout: ${req.method} did not answer within ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(id, { resolve, reject, timer });

      try {
        const sock = this.socket;
        if (!sock || sock.destroyed || sock.writable === false) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(new Error("PrivSvc socket not available"));
          return;
        }

        let wrote = false;
        try {
          const payload = JSON.stringify(req) + "\n";
          this.emit("debug", { stage: "call_write", id, method: req.method });
          wrote = sock.write(payload);
        } catch (e: any) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(e);
          return;
        }

        if (!wrote) {
          sock.once("drain", () => {});
        }
      } catch (e: any) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e);
      }
    });
  }

  close() {
    this.closedByClient = true;

    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(`PrivSvc client closed (${id})`));
    }

    try {
      this.socket?.end();
    } catch {}
    try {
      this.socket?.destroy();
    } catch {}

    this.socket = null;
    this.buffer = "";
    this.connecting = null;
  }
}
