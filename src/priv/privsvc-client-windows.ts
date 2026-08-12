// src/priv/privsvc-client-windows.ts
import net from "net";
import { randomUUID } from "crypto";
import { EventEmitter } from "events";
import type { PrivSvcRequest, PrivSvcResponse, PrivSvcPush } from "./ipc-types";

const PIPE_PATH = "\\\\.\\pipe\\tracenium.privsvc.v1";
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
      return 60000; // inventory can be heavy (WMI/registry)
    case "security.compliance":
      // 90s. Bumped from 30s because the Windows privsvc handler runs
      // ~10 PowerShell scripts in series (bitlocker, defender, firewall,
      // smb, shares, antivirus, domain/gpo, ciphers, protocols, patches),
      // and the patches call alone — `Microsoft.Update.Session.
      // QueryHistory()` — is notoriously slow on hosts with hundreds of
      // historical updates AND/OR a WSUS policy pointing at a remote
      // server. We observed DESKTOP-9G467VM intermittently exceeding the
      // 30s budget (~30% of scans) and the agent giving up while
      // privsvc was still processing — the response landed seconds
      // later but was already dropped, so `patches.count` went to 0
      // and the dashboard regressed to "Last patch = unknown".
      //
      // 90s is generous enough that even a heavily-patched WSUS host
      // completes, while still bounded so a genuinely-broken privsvc
      // doesn't wedge the agent's compliance pipeline indefinitely.
      return 90000;
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
const MAX_PENDING = 500; // hard cap to prevent unbounded growth
const MAX_BUFFER_CHARS = 2 * 1024 * 1024; // 2MB safety cap

type Pending = {
  resolve: (r: PrivSvcResponse) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
  method: string;
};

export class PrivSvcClient extends EventEmitter {
  private socket: net.Socket | null = null;
  private buffer = "";
  private connecting: Promise<void> | null = null;
  private pending = new Map<string, Pending>();
  private closedByClient = false;

  private earlyPushQueue: PrivSvcPush[] = [];
  private pushListenerAttached = false;

  private hasPushListeners(): boolean {
    return this.listenerCount("push") > 0 || this.pushListenerAttached;
  }

  onPush(cb: (msg: PrivSvcPush) => void) {
    this.on("push", cb);
    this.pushListenerAttached = true;

    this.emit("debug", {
      stage: "push_listener_attached",
      listenerCount: this.listenerCount("push"),
      earlyQueue: this.earlyPushQueue.length
    });

    // Flush any early buffered pushes through the same EventEmitter path
    if (this.earlyPushQueue.length > 0) {
      for (const msg of this.earlyPushQueue) {
        try {
          this.emit("debug", {
            stage: "push_flush",
            method: (msg as any)?.method,
            msg
          });
          this.emit("push", msg);
        } catch (e) {
          // Guarded: a bare emit("error") with no listener re-throws as an
          // uncaughtException (see onSocketError for the full rationale).
          if (this.listenerCount("error") > 0) this.emit("error", e);
          else this.emit("debug", { stage: "push_flush_error", err: String((e as any)?.message || e) });
        }
      }
      this.earlyPushQueue = [];
    }
  }

  private async ensureConnected(): Promise<void> {
    if (this.socket?.destroyed) this.socket = null;
    if (this.socket && !this.socket.destroyed) return;
    if (this.connecting) return this.connecting; // prevent parallel connect attempts
    if (this.closedByClient) throw new Error("PrivSvc client is closed");

    this.connecting = new Promise<void>((resolve, reject) => {
      const s = new net.Socket();

      // `settle` guarantees the connecting promise ALWAYS resolves or
      // rejects exactly once AND always clears `this.connecting`. The prior
      // version cleared the connect-timeout on 'error'/'close' but never
      // rejected the promise nor nulled `this.connecting`, so a connect that
      // FAILED (pipe not ready while PrivSvc was mid-restart) left
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

      // safety timeout for connect
      const t = setTimeout(() => {
        try { s.destroy(); } catch {}
        settle(new Error("PrivSvc connect timeout"));
      }, CONNECT_TIMEOUT_MS);

      s.connect(PIPE_PATH);
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
    this.buffer += chunk;

    this.emit("debug", {
      stage: "raw_chunk_full",
      chunk,
      bufferLength: this.buffer.length
    });

    let newlineIndex: number;
    while ((newlineIndex = this.buffer.indexOf("\n")) >= 0) {
      const raw = this.buffer.slice(0, newlineIndex);
      this.buffer = this.buffer.slice(newlineIndex + 1);

      const txt = raw.replace(/\r$/, "").trim();
      if (!txt) continue;

      let msg: any;
      try {
        msg = JSON.parse(txt);
        this.emit("debug", {
          stage: "ipc_raw_message",
          method: msg?.method,
          id: msg?.id,
          hasOk: Object.prototype.hasOwnProperty.call(msg ?? {}, "ok"),
          hasError: Object.prototype.hasOwnProperty.call(msg ?? {}, "error"),
          listenerCount: this.listenerCount("push"),
          pushListenerAttached: this.pushListenerAttached,
          raw: msg
        });
      } catch {
        this.emit("debug", { stage: "parse_error", raw: txt });
        continue;
      }

      const id = msg?.id;
      const isResponse =
        typeof id === "string" &&
        (Object.prototype.hasOwnProperty.call(msg, "ok") ||
         Object.prototype.hasOwnProperty.call(msg, "error"));

      if (isResponse) {
        if (!id) {
          // Guarded: see onSocketError. A malformed response must not be
          // able to crash the process via an unlistened "error" emit.
          if (this.listenerCount("error") > 0) {
            this.emit("error", new Error("PrivSvc response without id"));
          } else {
            this.emit("debug", { stage: "response_without_id", msg });
          }
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
            pendingSize: this.pending.size,
          });
        }
        continue;
      }

      const isPush = typeof msg?.method === "string";

      if (isPush) {
        if (this.hasPushListeners()) {
          this.emit("debug", {
            stage: "push_emit",
            method: msg?.method,
            listenerCount: this.listenerCount("push"),
            msg
          });
          this.emit("push", msg as PrivSvcPush);
        } else {
          this.emit("debug", {
            stage: "push_buffered",
            method: msg?.method,
            listenerCount: this.listenerCount("push"),
            msg
          });
          if (this.earlyPushQueue.length < 1000) {
            this.earlyPushQueue.push(msg as PrivSvcPush);
          } else {
            this.emit("debug", {
              stage: "push_buffer_overflow_drop",
              method: msg?.method,
              queued: this.earlyPushQueue.length
            });
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

    // Always-on diagnostic (stderr → err.log, NOT gated behind
    // DEBUG_PRIVSVC): when the IPC named pipe breaks we must know WHAT was
    // in flight to find root cause. The rich `debug` events below are
    // gated (off in prod), which left prior EPIPE incidents with only a
    // bare `read EPIPE` stack and zero context — e.g. we couldn't tell it
    // died on `grpc.facts.chunk` for the stale event 266. console.error
    // mirrors index.ts's crash handler and is guaranteed to land in the
    // err.log regardless of logger/verbosity config. Snapshot BEFORE the
    // pending map is cleared below.
    const inFlight = Array.from(this.pending.entries()).map(([id, p]) => `${p.method}#${id}`);
    console.error("[PrivSvc IPC] socket error", {
      errCode,
      errMessage,
      pendingCount: this.pending.size,
      inFlight
    });

    if (errCode === "EPIPE" || /EPIPE/i.test(errMessage)) {
      this.emit("debug", { stage: "epipe_detected", errCode, errMessage });
    }

    const sock = this.socket;
    this.socket = null;

    // fail all pending
    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(errMessage || `PrivSvc socket error (${id})`));
    }

    try { sock?.destroy(); } catch {}

    // Only emit if someone is listening. On an EventEmitter, emitting
    // "error" with NO registered listener makes Node RE-THROW the error,
    // which surfaces as an uncaughtException. Nothing in the agent
    // subscribes to `priv.on("error")` (only "push" and "debug"), so an
    // unguarded emit here turned every transient named-pipe EPIPE /
    // ECONNRESET into `[FATAL] uncaughtException: read EPIPE` — the exact
    // W11 crash that outlived the idle-churn fix (logs 2026-07-01, event
    // 266 chunked send at the 1h mark). Recovery does NOT depend on this
    // emit: `sock.destroy()` above triggers the socket "close" event →
    // `onSocketClose()` → `grpc.disconnected` push → reconnect. This
    // guard matches privsvc-client-macos.ts / -linux.ts, which already
    // had it — Windows was simply missed when that fix landed.
    if (this.listenerCount("error") > 0) {
      this.emit("error", err);
    }
  }

  private onSocketClose() {
    const wasManual = this.closedByClient;
    // fail all pending
    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(`PrivSvc connection closed (${id})`));
    }
    // Notify higher layers (bridge) that the stream is gone
    const disconnectMsg: PrivSvcPush = {
      v: 1,
      method: "grpc.disconnected",
      params: { manual: wasManual }
    };

    if (this.hasPushListeners()) {
      this.emit("debug", {
        stage: "push_emit",
        method: disconnectMsg.method,
        listenerCount: this.listenerCount("push"),
        msg: disconnectMsg
      });
      this.emit("push", disconnectMsg);
    } else {
      this.emit("debug", {
        stage: "push_buffered",
        method: disconnectMsg.method,
        listenerCount: this.listenerCount("push"),
        msg: disconnectMsg
      });
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

      this.pending.set(id, { resolve, reject, timer, method: req.method });

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

  public getPendingCount(): number {
    return this.pending.size;
  }

  public getPendingMethods(): string[] {
    const out: string[] = [];
    for (const entry of this.pending.values()) {
      out.push(entry.method);
    }
    return out;
  }

  close() {
    this.closedByClient = true;
    // fail all pending immediately
    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(`PrivSvc client closed (${id})`));
    }
    try { this.socket?.end(); } catch {}
    try { this.socket?.destroy(); } catch {}
    this.socket = null;
    this.buffer = "";
    this.connecting = null;
  }
}
