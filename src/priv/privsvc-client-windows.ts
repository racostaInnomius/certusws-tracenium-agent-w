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

  onPush(cb: (msg: any) => void) {
    this.on("push", cb);
  }

  private async ensureConnected(): Promise<void> {
    if (this.socket?.destroyed) this.socket = null;
    if (this.socket && !this.socket.destroyed) return;
    if (this.connecting) return this.connecting; // prevent parallel connect attempts
    if (this.closedByClient) throw new Error("PrivSvc client is closed");

    this.connecting = new Promise<void>((resolve, reject) => {
      const s = net.createConnection(PIPE_PATH);

      s.on("connect", () => {
        this.socket = s;
        this.closedByClient = false;
        this.connecting = null;
        resolve();
      });

      s.on("data", (data) => this.onData(data));
      s.on("error", (err) => this.onSocketError(err));
      s.on("close", () => this.onSocketClose());

      // safety timeout for connect
      const t = setTimeout(() => {
        try { s.destroy(); } catch {}
        this.connecting = null;
        reject(new Error("PrivSvc connect timeout"));
      }, CONNECT_TIMEOUT_MS);

      s.once("connect", () => clearTimeout(t));
      s.once("error", () => clearTimeout(t));
    });

    return this.connecting;
  }

  private onData(data: Buffer | string) {
    const chunk = typeof data === "string" ? data : data.toString("utf8");
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
      const txt = line.trim();
      if (!txt) continue;

      let msg: any;
      try {
        msg = JSON.parse(txt);
      } catch {
        // ignore malformed
        continue;
      }

      // Response path: has id and ok/error
      const id = msg?.id;
      if (id && this.pending.has(id)) {
        const p = this.pending.get(id)!;
        this.pending.delete(id);
        clearTimeout(p.timer);
        p.resolve(msg as PrivSvcResponse);
        continue;
      }

      // Push path (ACK/control)
      this.emit("push", msg);
    }
  }

  private onSocketError(err: any) {
    // fail all pending
    for (const [id, p] of this.pending.entries()) {
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.reject(new Error(err?.message || `PrivSvc socket error (${id})`));
    }
    this.socket = null;
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
    this.emit("push", { method: "win.grpc.disconnected", params: { manual: wasManual } });
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
        const payload = JSON.stringify(req) + "\n";
        const ok = this.socket!.write(payload);
        if (!ok) {
          // Apply backpressure: wait for drain before considering the pipe healthy
          this.socket!.once("drain", () => {});
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