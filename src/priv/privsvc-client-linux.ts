// src/priv/privsvc-client-linux.ts
import net from "net";
import { randomUUID } from "crypto";
import { EventEmitter } from "events";
import type { PrivSvcRequest, PrivSvcResponse, PrivSvcPush } from "./ipc-types";

const SOCKET_PATH = "/var/run/tracenium/privsvc.sock";
const DEFAULT_TIMEOUT_MS = 8000;

function getTimeoutForMethod(method: string): number {
  switch (method) {
    case "grpc.connect":
      return 60000;
    case "grpc.facts.send":
    case "grpc.facts.chunk":
    case "grpc.ack":
    case "grpc.close":
      return 30000;
    case "grpc.heartbeat":
      return 5000;
    case "software.inventory":
      return 60000;
    case "security.compliance":
    case "patch.scan":
      return 30000;
    case "patch.install":
      return 60 * 60 * 1000;
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
    // synchronously. See the macOS sibling (privsvc-client-macos.ts) for
    // the full rationale. Short version: no caller in src/ subscribes
    // to our "error" event, so an unguarded emit ended up as an
    // uncaughtException — and after we hardened the service-level
    // handler to exit on uncaught, every transient privsvc restart
    // would unnecessarily recycle the whole agent. The downstream
    // grpc-client already drives recovery off of the `grpc.disconnected`
    // push that onSocketClose generates, so a non-error "disconnect"
    // event is the right contract here. Listener-guard preserves
    // future opt-in if a consumer ever wants the strong error signal.
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
