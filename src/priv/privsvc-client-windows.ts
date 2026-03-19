// src/priv/privsvc-client-windows.ts
import net from "net";
import { randomUUID } from "crypto";
import { EventEmitter } from "events";
import type { PrivSvcRequest, PrivSvcResponse } from "./ipc-types";

const PIPE_PATH = "\\\\.\\pipe\\tracenium.privsvc.v1";
const DEFAULT_TIMEOUT_MS = 8000;
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

  private earlyPushQueue: any[] = [];
  private pushListenerAttached = false;

  onPush(cb: (msg: any) => void) {
    this.pushListenerAttached = true;
    this.removeAllListeners("push");
    this.on("push", cb);

    // Flush any early buffered pushes
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
    //this.emit("debug", { stage: "raw_chunk", chunk });
    this.emit("debug", { stage: "raw_chunk" });
    this.buffer += chunk;
    // Safety: prevent unbounded memory growth on malformed streams
    if (this.buffer.length > MAX_BUFFER_CHARS) {
      // Drop buffer and signal error; the caller can reconnect.
      this.buffer = "";
      this.onSocketError(new Error("PrivSvc buffer overflow"));
      try { this.socket?.destroy(); } catch {}
      return;
    }
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() || "";

    for (const line of lines) {
      let txt = line.replace(/\r$/, "").trim();
      if (!txt) continue;

      let msg: any;
      try {
        msg = JSON.parse(txt);
        //this.emit("debug", { stage: "parsed", msg });
        this.emit("debug", { stage: "parsed" });
      } catch {
        this.emit("debug", { stage: "parse_error", raw: txt });
        continue;
      }

      //this.emit("debug", { stage: "dispatch", msg });
      this.emit("debug", { stage: "dispatch" });

      // Response path: has id + ok/error shape
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
          p.resolve(msg as PrivSvcResponse);
        } else {
          //this.emit("debug", { stage: "orphan_response", msg });
          this.emit("debug", { stage: "orphan_response" });
        }
        continue;
      }

      // Push path: must have method
      const isPush = typeof msg?.method === "string";

      if (isPush) {
        if (this.pushListenerAttached) {
          this.emit("debug", { stage: "push_emit", msg });
          this.emit("push", msg);
        } else {
          this.emit("debug", { stage: "push_buffered", msg });
          if (this.earlyPushQueue.length < 1000) {
            this.earlyPushQueue.push(msg);
          }
        }
        continue;
      }

      // Unknown message shape
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
    const disconnectMsg = { method: "win.grpc.disconnected", params: { manual: wasManual } };

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

      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("PrivSvc timeout"));
      }, DEFAULT_TIMEOUT_MS);

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
          this.emit("debug", id);
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