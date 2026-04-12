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
    case "software.inventory":
      return 60000; // inventory can be heavy (WMI/registry)
    case "security.compliance":
      return 30000;
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
          this.emit("error", e);
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

      s.on("data", (data) => this.onData(data));
      s.on("error", (err) => this.onSocketError(err));
      s.on("close", () => this.onSocketClose());

      s.on("connect", () => {
        this.socket = s;
        this.closedByClient = false;
        this.connecting = null;
        resolve();
      });

      // safety timeout for connect
      const t = setTimeout(() => {
        try { s.destroy(); } catch {}
        this.connecting = null;
        reject(new Error("PrivSvc connect timeout"));
      }, CONNECT_TIMEOUT_MS);

      s.once("connect", () => clearTimeout(t));
      s.once("error", () => clearTimeout(t));
      s.once("close", () => clearTimeout(t));

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

    this.emit("error", err);
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
        reject(new Error("PrivSvc timeout"));
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
