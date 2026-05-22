// src/plugins/rcp/screen-session.ts
//
// RCP M3.S2 — screen capture + streaming session (chunked transport).
//
// One ScreenSession is created per active rcp.screen DataChannel.
// It drives a periodic capture loop using the PrivSvc screen.capture
// IPC method (C# GDI+, works in Windows Session 0) and streams JPEG
// frames to the browser over the DataChannel.
//
// M3.S2 adds chunked frame delivery to stay within the SCTP ~65 KB
// DataChannel message size limit. Frames ≤ FRAME_CHUNK_MAX chars are
// sent as a single "frame" message (backward-compat with M3.S1 clients).
// Larger frames are split into "frameStart" / "frameChunk[]" / "frameDone".
//
// Protocol (see ScreenShareViewer.jsx for the browser side):
//
//   Agent → Browser:
//     { op: "screenInfo",  width, height, fps }      // once at open
//     { op: "frame",  seq, width, height, data }     // small frame (≤ limit)
//     { op: "frameStart", seq, width, height, chunks } // large frame header
//     { op: "frameChunk", seq, idx, data }           // one chunk
//     { op: "frameDone",  seq }                      // all chunks sent
//     { op: "error", code, message }
//
//   Browser → Agent:
//     { op: "setQuality",  fps, quality }  // 1-100 JPEG quality
//     { op: "stop" }                       // graceful close
//
// The agent also fires RemoteScreenAudit gRPC events at "started" and
// "stopped"/"error" via the sendScreenAudit callback so the backend
// can persist session-level audit rows.

import type { AgentContext } from "../../core/agent-context";

export type ScreenAuditPayload = {
  event: string;      // "started" | "stopped" | "error"
  width: number;
  height: number;
  fps: number;
  errorMessage: string;
};

type ScreenSessionArgs = {
  sessionId: string;
  ctx: AgentContext;
  sendScreenAudit: (audit: ScreenAuditPayload) => void;
  onTeardown: (reason: string) => void;
};

const DEFAULT_FPS = 5;
const DEFAULT_QUALITY = 60;
const MIN_FPS = 1;
const MAX_FPS = 15;
const MIN_QUALITY = 10;
const MAX_QUALITY = 90;

// M3.S2 — max base64 chars per DataChannel message. Keeps each SCTP
// payload under the practical ~65 KB limit including JSON envelope
// overhead. 48 KB base64 ≈ 36 KB binary, well inside the limit.
const FRAME_CHUNK_MAX = 48_000;

export class ScreenSession {
  private readonly dc: any;
  private readonly args: ScreenSessionArgs;
  private disposed = false;
  private captureTimer: NodeJS.Timeout | null = null;
  private fps = DEFAULT_FPS;
  private quality = DEFAULT_QUALITY;
  private seq = 0;
  private lastWidth = 0;
  private lastHeight = 0;
  private auditStartedSent = false;

  constructor(dc: any, args: ScreenSessionArgs) {
    this.dc = dc;
    this.args = args;

    dc.onMessage((raw: any) => {
      if (this.disposed) return;
      try {
        const msg = JSON.parse(
          typeof raw === "string" ? raw : raw.toString()
        );
        this.handleMessage(msg);
      } catch {
        /* malformed JSON — ignore */
      }
    });

    dc.onClosed(() => {
      args.ctx.logger?.info?.("[rcp.screen] data channel closed", {
        sessionId: args.sessionId
      });
      this.stopCapture("data_channel_closed");
    });

    // Start the capture loop after a tick so the constructor returns
    // cleanly before the first async capture fires.
    setImmediate(() => {
      if (!this.disposed) this.scheduleNext();
    });
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  private send(obj: object): void {
    if (this.disposed) return;
    try {
      this.dc.sendMessage(JSON.stringify(obj));
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp.screen] send failed", {
        sessionId: this.args.sessionId,
        err: err?.message
      });
    }
  }

  private handleMessage(msg: any): void {
    const op = String(msg?.op ?? "");
    switch (op) {
      case "setQuality": {
        const fps = Number(msg.fps);
        const quality = Number(msg.quality);
        if (Number.isFinite(fps) && fps > 0)
          this.fps = Math.max(MIN_FPS, Math.min(MAX_FPS, Math.round(fps)));
        if (Number.isFinite(quality) && quality > 0)
          this.quality = Math.max(MIN_QUALITY, Math.min(MAX_QUALITY, Math.round(quality)));
        // Reschedule with new interval.
        if (this.captureTimer) {
          clearTimeout(this.captureTimer);
          this.captureTimer = null;
        }
        if (!this.disposed) this.scheduleNext();
        break;
      }
      case "stop":
        this.stopCapture("operator_stopped");
        break;
    }
  }

  // M3.S2 — split a large base64 JPEG string into FRAME_CHUNK_MAX
  // slices and send them as frameStart / frameChunk[] / frameDone.
  // The browser reassembles before rendering; any chunk dropped by
  // the unreliable DataChannel causes the whole frame to be discarded
  // when the browser receives the next frameStart.
  private sendFrameChunked(
    seq: number,
    width: number,
    height: number,
    data: string
  ): void {
    const chunks: string[] = [];
    for (let i = 0; i < data.length; i += FRAME_CHUNK_MAX) {
      chunks.push(data.slice(i, i + FRAME_CHUNK_MAX));
    }
    this.send({ op: "frameStart", seq, width, height, chunks: chunks.length });
    for (let idx = 0; idx < chunks.length; idx++) {
      this.send({ op: "frameChunk", seq, idx, data: chunks[idx] });
    }
    this.send({ op: "frameDone", seq });
  }

  // ── Capture loop ───────────────────────────────────────────────────────────

  private scheduleNext(): void {
    if (this.disposed) return;
    const intervalMs = Math.round(1000 / this.fps);
    this.captureTimer = setTimeout(async () => {
      if (!this.disposed) await this.captureFrame();
      if (!this.disposed) this.scheduleNext();
    }, intervalMs);
    // Don't keep the Node.js event loop alive just for this timer.
    (this.captureTimer as any).unref?.();
  }

  private async captureFrame(): Promise<void> {
    if (this.disposed) return;
    const { ctx, sessionId, sendScreenAudit } = this.args;

    try {
      const result = await (ctx.priv as any).call({
        v: 1,
        id: `screen.capture.${Date.now()}`,
        method: "screen.capture",
        params: { quality: this.quality }
      });

      if (!result?.ok) {
        const errMsg = String(result?.error?.message ?? result?.error ?? "capture failed");
        ctx.logger?.warn?.("[rcp.screen] capture IPC failed", { sessionId, error: errMsg });
        // Surface to the browser but keep the loop running — a single
        // GDI transient (e.g. lock-screen flicker) shouldn't tear down.
        this.send({ op: "error", code: "CAPTURE_FAILED", message: errMsg });
        return;
      }

      const data: string = String(result.result?.data ?? "");
      const width: number = Number(result.result?.width ?? 0);
      const height: number = Number(result.result?.height ?? 0);

      if (!data) return;

      // Send screenInfo on the first frame or when screen resolution changes.
      if (this.seq === 0 || width !== this.lastWidth || height !== this.lastHeight) {
        this.send({ op: "screenInfo", width, height, fps: this.fps });

        if (!this.auditStartedSent) {
          this.auditStartedSent = true;
          sendScreenAudit({
            event: "started",
            width,
            height,
            fps: this.fps,
            errorMessage: ""
          });
        }

        this.lastWidth = width;
        this.lastHeight = height;
      }

      // M3.S2 — send as a single message when small enough; chunk
      // otherwise to stay under the SCTP DataChannel size limit.
      const frameSeq = this.seq++;
      if (data.length <= FRAME_CHUNK_MAX) {
        this.send({ op: "frame", seq: frameSeq, width, height, data });
      } else {
        this.sendFrameChunked(frameSeq, width, height, data);
      }
    } catch (err: any) {
      ctx.logger?.warn?.("[rcp.screen] capture error", {
        sessionId,
        err: err?.message
      });
      // Non-fatal — loop continues.
    }
  }

  // ── Teardown ───────────────────────────────────────────────────────────────

  private stopCapture(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.captureTimer) {
      clearTimeout(this.captureTimer);
      this.captureTimer = null;
    }
    if (this.auditStartedSent) {
      this.args.sendScreenAudit({
        event: "stopped",
        width: this.lastWidth,
        height: this.lastHeight,
        fps: this.fps,
        errorMessage: ""
      });
    }
    setImmediate(() => this.args.onTeardown(reason));
  }

  dispose(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.captureTimer) {
      clearTimeout(this.captureTimer);
      this.captureTimer = null;
    }
    if (this.auditStartedSent) {
      this.args.sendScreenAudit({
        event: "stopped",
        width: this.lastWidth,
        height: this.lastHeight,
        fps: this.fps,
        errorMessage: ""
      });
    }
    this.args.ctx.logger?.info?.("[rcp.screen] session disposed", {
      sessionId: this.args.sessionId,
      reason
    });
  }
}
