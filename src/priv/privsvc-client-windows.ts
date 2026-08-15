// src/priv/privsvc-client-windows.ts
import net from "net";
import { randomUUID } from "crypto";
import { EventEmitter } from "events";
import type { PrivSvcRequest, PrivSvcResponse, PrivSvcPush } from "./ipc-types";

const PIPE_PATH = "\\\\.\\pipe\\tracenium.privsvc.v1";
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
      return 60000; // inventory can be heavy (WMI/registry)
    case "security.compliance":
      // 270s. History: 30s → 90s after DESKTOP-9G467VM's slow WU
      // history query (~30% of scans gave up mid-handler and the
      // dashboard regressed to "Last patch = unknown"). But 90s still
      // violated THE INVARIANT (caller must outwait handler): the
      // handler runs every section SEQUENTIALLY, each RunPs bounded at
      // DEFAULT_PS_TIMEOUT_MS=15s, plus 45s for patches and a 15s
      // Get-HotFix fallback — worst case ≈ 240s when several sections
      // time out on the same sick host. Exactly the hosts where the
      // diagnostic matters most were the ones whose response the
      // client dropped. 240s ceiling + margin = 270s; the scheduler's
      // 30-min stuck-worker guard stays the outer bound.
      return 270000;
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
    // ── CDP ──────────────────────────────────────────────────────────
    //
    // 5th victim of the 8s default. The handler walks 7 LocalMachine
    // X509Stores and reads HasPrivateKey per certificate, which opens a
    // CNG/CSP handle — on a host whose keys live in a TPM, a smart card
    // or a network-backed KSP that is not a constant-time lookup. The
    // handler had NO ceiling of its own until this fix, so "the client
    // must outwait the handler" was not even a statable claim; it now
    // budgets 45s (CdpCertificates.HandlerBudgetMs) and returns what it
    // has, so this sits above it with margin.
    case "cdp.certs.read":
      return 60 * 1000; // privsvc: 45s + margin
    default:
      return DEFAULT_TIMEOUT_MS;
  }
}
const CONNECT_TIMEOUT_MS = 8000;
const MAX_PENDING = 500; // hard cap to prevent unbounded growth

type Pending = {
  resolve: (r: PrivSvcResponse) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
  method: string;
};

/**
 * A request accepted by `call()` but not yet written to the pipe.
 *
 * WHY A QUEUE AT ALL — the invariant had a hole.
 *
 * `NamedPipeServer.HandleClientAsync` is strictly serial per connection:
 * it awaits the handler before it even READS the next line. We keep one
 * connection, so every privileged call in the agent shares one lane.
 * Until this change the client ignored that: `call()` wrote immediately
 * and started the method's timer at WRITE time, so a request could burn
 * its whole budget queued behind somebody else's handler and be rejected
 * having never been dispatched.
 *
 * That is what "PrivSvc timeout: cdp.certs.read did not answer within
 * 8000ms" actually was in production (2026-08-13, 4 of 16 CDP scans on
 * the pilot fleet). Every occurrence landed within ~40s of a gRPC
 * reconnect, and on agents whose event sequence was still in the double
 * digits — i.e. freshly restarted. On reconnect the policy handlers call
 * `startPipelines`, which fires inventory + compliance + cdp + patch with
 * no await between them; `software.inventory` (60s) and
 * `security.compliance` (270s) went into the lane first and CDP, holding
 * the smallest budget in the agent, was the one that lost. Long-running
 * agents at sequence 3600+ never failed: same host, same stores, empty
 * lane.
 *
 * So the documented invariant — job > client > handler — was necessary
 * but not sufficient. It assumed a budget only has to cover its OWN
 * handler. With one serial lane it must cover the queue ahead of it too.
 * Rather than inflate every constant to hide that, the client now models
 * the lane: one request in flight, and the method budget starts at
 * DISPATCH. Each number then means what it says.
 *
 * Windows only, deliberately. The macOS/Linux privsvc handles each
 * `data` event in its own async callback, so those servers really do
 * interleave requests; serialising their clients would remove
 * concurrency that exists, and would park a 5s heartbeat behind a 60s
 * compliance run that today overtakes it.
 *
 * THE WAIT IS SELF-BOUNDING, so there is no separate queue deadline.
 * Whatever is in the lane leaves it when its own budget expires — the
 * timeout path frees the lane and pumps the next entry — so a queued
 * request waits at most the sum of the budgets ahead of it, by
 * construction. An extra timer derived from that same sum could only
 * fire after the thing it was guarding had already fired, which is a
 * safety net that cannot catch anything. The outer bound stays the
 * scheduler's 30-minute stuck-worker guard.
 *
 * The cost of this is a real behaviour change: a request that used to
 * fail fast behind a long handler now waits for it instead. That is the
 * intended trade — failing fast on a lane you were never going to get is
 * how CDP lost 25% of its scans — but it means a heartbeat issued during
 * a 29-minute `sdp.install` is now late rather than rejected.
 */
type Queued = {
  req: PrivSvcRequest;
  budgetMs: number;
  resolve: (r: PrivSvcResponse) => void;
  reject: (e: Error) => void;
  settled: boolean;
  /** For the timeout diagnostic: how long the lane was busy, and with what. */
  queuedAt: number;
  queuedBehind: string[];
};

export class PrivSvcClient extends EventEmitter {
  private socket: net.Socket | null = null;
  private buffer = "";
  private connecting: Promise<void> | null = null;
  private pending = new Map<string, Pending>();
  private closedByClient = false;

  /** Requests accepted but not yet written. See `Queued`. */
  private queue: Queued[] = [];
  /** The single request currently occupying the pipe's serial lane. */
  private inFlight: { id: string; method: string; budgetMs: number; startedAt: number } | null =
    null;

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

    // Drain the queue FIRST. Rejecting a pending request runs the
    // continuation that pumps the lane, and we do not want it dispatching
    // queued work onto a socket we just gave up on — they would come back
    // with a vaguer "socket not available" than the error we actually have.
    this.drainQueue(new Error(errMessage || "PrivSvc socket error"));

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

  /**
   * Reject everything still waiting for the lane. Without this a dropped
   * pipe would leave queued callers hanging until their queue deadline —
   * the reconnect burst is exactly when the queue is deepest, so it is
   * also exactly when the socket is most likely to go away underneath it.
   */
  private drainQueue(err: Error) {
    const queued = this.queue.splice(0, this.queue.length);
    for (const entry of queued) {
      if (entry.settled) continue;
      entry.settled = true;
      entry.reject(err);
    }
    this.inFlight = null;
  }

  private onSocketClose() {
    const wasManual = this.closedByClient;
    // Drain before pending, for the reason given in onSocketError.
    this.drainQueue(new Error("PrivSvc connection closed"));
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

  /** Methods occupying the lane ahead of a queued request, for diagnostics. */
  private laneAhead(): string[] {
    const ahead = this.inFlight ? [this.inFlight.method] : [];
    return ahead.concat(this.queue.map((q) => q.req.method));
  }

  /**
   * Dispatch the head of the queue if the lane is free. Called on every
   * enqueue and every time a request leaves the lane — including on
   * timeout, so one wedged handler cannot stall the queue behind it
   * forever.
   */
  private pump() {
    if (this.inFlight) return;

    const entry = this.queue.shift();
    if (!entry || entry.settled) {
      if (entry) this.pump();
      return;
    }

    const id = entry.req.id!;
    const method = entry.req.method;
    const timeoutMs = entry.budgetMs;
    const waitedMs = Date.now() - entry.queuedAt;
    const waitedBehind = entry.queuedBehind;

    const finish = () => {
      if (this.inFlight?.id === id) this.inFlight = null;
      this.pump();
    };

    const sock = this.socket;
    if (!sock || sock.destroyed || sock.writable === false) {
      entry.settled = true;
      entry.reject(new Error("PrivSvc socket not available"));
      this.pump();
      return;
    }

    const timer = setTimeout(() => {
      this.pending.delete(id);
      this.emit("debug", { stage: "timeout", id, method, waitedMs, waitedBehind });
      // Name the method and the budget: a bare "PrivSvc timeout" told an
      // operator nothing about WHICH privileged call hung, which is what
      // made a stalled self-update take a code read to diagnose.
      //
      // The budget now covers only this handler, so this sentence is true
      // as written. The queue context is appended rather than folded in,
      // because "waited 61s for the lane behind security.compliance, then
      // got 60s of its own" is the difference between a slow certificate
      // scan and a busy pipe — and the old message could not tell them
      // apart at all.
      entry.settled = true;
      const lane =
        waitedBehind.length > 0
          ? ` (waited ${waitedMs}ms for the IPC lane behind ${waitedBehind.join(", ")})`
          : "";
      entry.reject(
        new Error(`PrivSvc timeout: ${method} did not answer within ${timeoutMs}ms${lane}`)
      );
      finish();
    }, timeoutMs);

    this.inFlight = { id, method, budgetMs: timeoutMs, startedAt: Date.now() };
    this.pending.set(id, {
      method,
      timer,
      resolve: (r) => {
        entry.settled = true;
        entry.resolve(r);
        finish();
      },
      reject: (e) => {
        entry.settled = true;
        entry.reject(e);
        finish();
      }
    });

    try {
      const payload = JSON.stringify(entry.req) + "\n";
      this.emit("debug", { stage: "call_write", id, method });
      const wrote = sock.write(payload);
      if (!wrote) sock.once("drain", () => {});
    } catch (e: any) {
      clearTimeout(timer);
      this.pending.delete(id);
      entry.settled = true;
      entry.reject(e);
      finish();
    }
  }

  async call(req: PrivSvcRequest): Promise<PrivSvcResponse> {
    await this.ensureConnected();

    if (this.pending.size + this.queue.length >= MAX_PENDING) {
      throw new Error(`PrivSvc pending requests overflow (${MAX_PENDING})`);
    }

    if (!req.id) req.id = randomUUID();

    return new Promise<PrivSvcResponse>((resolve, reject) => {
      const entry: Queued = {
        req,
        budgetMs: getTimeoutForMethod(req.method),
        resolve,
        reject,
        settled: false,
        queuedAt: Date.now(),
        queuedBehind: this.laneAhead()
      };

      this.queue.push(entry);
      this.pump();
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
