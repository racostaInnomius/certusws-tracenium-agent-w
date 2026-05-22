// src/plugins/rcp/file-session.ts
//
// RCP M2.S1 — file browser / transfer session.
//
// One FileSession is created per active rcp.file DataChannel. It
// implements a simple JSON protocol over the channel; all file bytes
// travel P2P (no bytes transit the backend).
//
// Protocol (see FileBrowserPanel.jsx for the browser side):
//
//   Browser → Agent:
//     { op: "list",       path }
//     { op: "download",   transferId, path }
//     { op: "upload",     transferId, path, name, size }
//     { op: "chunk",      transferId, seq, data }   // base64
//     { op: "uploadDone", transferId }
//     { op: "cancel",     transferId }
//
//   Agent → Browser:
//     { op: "listing",  path, entries: [{name, isDir, size, modifiedAt}] }
//     { op: "chunk",    transferId, seq, data, done? }  // base64
//     { op: "ready",    transferId }   // agent is ready to receive upload
//     { op: "error",    code, message, transferId? }
//
// The agent also fires RemoteFileTransferAudit gRPC events at transfer
// start and completion via the sendFileTransferAudit callback; the
// backend persists those to remote_file_transfers for audit.

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { AgentContext } from "../../core/agent-context";

export type FileTransferAuditPayload = {
  transferId: string;
  direction: string;
  remotePath: string;
  filename: string;
  sizeBytes: number;
  transferredBytes: number;
  status: string;
  errorMessage: string;
};

type FileSessionArgs = {
  sessionId: string;
  ctx: AgentContext;
  sendFileTransferAudit: (audit: FileTransferAuditPayload) => void;
  onTeardown: (reason: string) => void;
};

// Max binary bytes per download chunk. At ~33 % base64 inflation this
// keeps each DataChannel message comfortably under the 64 KB SCTP limit.
const CHUNK_SIZE = 32 * 1024;

type UploadState = {
  path: string;
  tmpPath: string;
  fd: number;
  size: number;
  received: number;
  cancelled: boolean;
};

export class FileSession {
  private readonly dc: any;
  private readonly args: FileSessionArgs;
  private disposed = false;

  // In-progress uploads keyed by transferId.
  private readonly uploads = new Map<string, UploadState>();
  // Transfer IDs of downloads the browser has cancelled.
  private readonly cancelledDownloads = new Set<string>();

  constructor(dc: any, args: FileSessionArgs) {
    this.dc = dc;
    this.args = args;

    dc.onMessage((raw: any) => {
      if (this.disposed) return;
      try {
        const msg = JSON.parse(
          typeof raw === "string" ? raw : raw.toString()
        );
        this.handleMessage(msg);
      } catch (err: any) {
        args.ctx.logger?.warn?.("[rcp.file] message parse error", {
          sessionId: args.sessionId,
          err: err?.message
        });
      }
    });

    dc.onClosed(() => {
      args.ctx.logger?.info?.("[rcp.file] data channel closed", {
        sessionId: args.sessionId
      });
      this.cleanupAllUploads();
      if (!this.disposed) {
        setImmediate(() => args.onTeardown("data_channel_closed"));
      }
    });
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  private send(obj: object): void {
    if (this.disposed) return;
    try {
      this.dc.sendMessage(JSON.stringify(obj));
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp.file] send failed", {
        sessionId: this.args.sessionId,
        err: err?.message
      });
    }
  }

  private handleMessage(msg: any): void {
    const op = String(msg?.op ?? "");
    switch (op) {
      case "list":
        this.handleList(String(msg.path ?? "/")).catch((err: any) => {
          this.send({
            op: "error",
            code: "LIST_FAILED",
            message: err?.message ?? String(err)
          });
        });
        break;

      case "download":
        this.handleDownload(
          String(msg.transferId ?? ""),
          String(msg.path ?? "")
        ).catch((err: any) => {
          this.send({
            op: "error",
            code: "DOWNLOAD_FAILED",
            message: err?.message ?? String(err),
            transferId: msg.transferId
          });
        });
        break;

      case "upload":
        this.handleUploadStart(
          String(msg.transferId ?? ""),
          String(msg.path ?? ""),
          String(msg.name ?? ""),
          Number(msg.size ?? 0)
        );
        break;

      case "chunk":
        this.handleChunk(
          String(msg.transferId ?? ""),
          Number(msg.seq ?? 0),
          String(msg.data ?? "")
        );
        break;

      case "uploadDone":
        this.handleUploadDone(String(msg.transferId ?? "")).catch(() => {});
        break;

      case "cancel":
        this.handleCancel(String(msg.transferId ?? ""));
        break;

      default:
        this.args.ctx.logger?.debug?.("[rcp.file] unknown op", {
          sessionId: this.args.sessionId,
          op
        });
    }
  }

  // ── Handlers ───────────────────────────────────────────────────────────────

  private async handleList(dirPath: string): Promise<void> {
    const resolved = path.resolve(path.normalize(dirPath));
    const names = await fs.promises.readdir(resolved);

    const entries: Array<{
      name: string;
      isDir: boolean;
      size: number | null;
      modifiedAt: string | null;
    }> = [];

    await Promise.all(
      names.map(async (name) => {
        try {
          const full = path.join(resolved, name);
          const stat = await fs.promises.stat(full);
          entries.push({
            name,
            isDir: stat.isDirectory(),
            size: stat.isFile() ? stat.size : null,
            modifiedAt: stat.mtime.toISOString()
          });
        } catch {
          // Skip entries we can't stat (broken symlinks, permission errors).
        }
      })
    );

    // Sort: directories first, then files; both alphabetical.
    entries.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    this.send({ op: "listing", path: resolved, entries });
  }

  private async handleDownload(
    transferId: string,
    filePath: string
  ): Promise<void> {
    if (!transferId) return;
    this.cancelledDownloads.delete(transferId);

    const resolved = path.resolve(path.normalize(filePath));
    let stat: fs.Stats;
    try {
      stat = await fs.promises.stat(resolved);
    } catch (err: any) {
      this.args.sendFileTransferAudit({
        transferId,
        direction: "download",
        remotePath: resolved,
        filename: path.basename(resolved),
        sizeBytes: 0,
        transferredBytes: 0,
        status: "failed",
        errorMessage: err?.message ?? String(err)
      });
      throw err;
    }

    const sizeBytes = stat.size;
    this.args.sendFileTransferAudit({
      transferId,
      direction: "download",
      remotePath: resolved,
      filename: path.basename(resolved),
      sizeBytes,
      transferredBytes: 0,
      status: "started",
      errorMessage: ""
    });

    let transferred = 0;
    let seq = 0;
    let cancelled = false;

    try {
      const fh = await fs.promises.open(resolved, "r");
      try {
        const buf = Buffer.alloc(CHUNK_SIZE);
        while (true) {
          if (this.cancelledDownloads.has(transferId) || this.disposed) {
            cancelled = true;
            break;
          }
          const { bytesRead } = await fh.read(buf, 0, CHUNK_SIZE, null);
          if (bytesRead === 0) break;

          transferred += bytesRead;
          const done = transferred >= sizeBytes;
          this.send({
            op: "chunk",
            transferId,
            seq: seq++,
            data: buf.slice(0, bytesRead).toString("base64"),
            done
          });
        }
      } finally {
        await fh.close();
      }
    } catch (err: any) {
      this.send({
        op: "error",
        code: "READ_FAILED",
        message: err?.message ?? String(err),
        transferId
      });
      this.args.sendFileTransferAudit({
        transferId,
        direction: "download",
        remotePath: resolved,
        filename: path.basename(resolved),
        sizeBytes,
        transferredBytes: transferred,
        status: "failed",
        errorMessage: err?.message ?? String(err)
      });
      return;
    } finally {
      this.cancelledDownloads.delete(transferId);
    }

    this.args.sendFileTransferAudit({
      transferId,
      direction: "download",
      remotePath: resolved,
      filename: path.basename(resolved),
      sizeBytes,
      transferredBytes: transferred,
      status: cancelled ? "cancelled" : "completed",
      errorMessage: ""
    });
  }

  private handleUploadStart(
    transferId: string,
    destPath: string,
    _name: string,
    size: number
  ): void {
    if (!transferId) return;

    const tmpPath = path.join(os.tmpdir(), `rcp-upload-${transferId}`);
    let fd: number;
    try {
      fd = fs.openSync(tmpPath, "w");
    } catch (err: any) {
      this.send({
        op: "error",
        code: "UPLOAD_INIT_FAILED",
        message: err?.message ?? String(err),
        transferId
      });
      return;
    }

    const resolved = path.resolve(path.normalize(destPath));
    this.uploads.set(transferId, {
      path: resolved,
      tmpPath,
      fd,
      size,
      received: 0,
      cancelled: false
    });

    this.args.sendFileTransferAudit({
      transferId,
      direction: "upload",
      remotePath: resolved,
      filename: path.basename(resolved),
      sizeBytes: size,
      transferredBytes: 0,
      status: "started",
      errorMessage: ""
    });

    this.send({ op: "ready", transferId });
  }

  private handleChunk(
    transferId: string,
    _seq: number,
    data: string
  ): void {
    const upload = this.uploads.get(transferId);
    if (!upload || upload.cancelled) return;
    try {
      const buf = Buffer.from(data, "base64");
      fs.writeSync(upload.fd, buf);
      upload.received += buf.length;
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp.file] chunk write error", {
        sessionId: this.args.sessionId,
        transferId,
        err: err?.message
      });
    }
  }

  private async handleUploadDone(transferId: string): Promise<void> {
    const upload = this.uploads.get(transferId);
    if (!upload) return;

    try { fs.closeSync(upload.fd); } catch { /* ignore */ }

    if (upload.cancelled) {
      this.cleanupTmp(upload.tmpPath);
      this.uploads.delete(transferId);
      this.args.sendFileTransferAudit({
        transferId,
        direction: "upload",
        remotePath: upload.path,
        filename: path.basename(upload.path),
        sizeBytes: upload.size,
        transferredBytes: upload.received,
        status: "cancelled",
        errorMessage: ""
      });
      return;
    }

    try {
      await fs.promises.mkdir(path.dirname(upload.path), { recursive: true });
      await fs.promises.rename(upload.tmpPath, upload.path);
      this.uploads.delete(transferId);
      this.args.sendFileTransferAudit({
        transferId,
        direction: "upload",
        remotePath: upload.path,
        filename: path.basename(upload.path),
        sizeBytes: upload.size,
        transferredBytes: upload.received,
        status: "completed",
        errorMessage: ""
      });
    } catch (err: any) {
      this.cleanupTmp(upload.tmpPath);
      this.uploads.delete(transferId);
      this.send({
        op: "error",
        code: "UPLOAD_FINALIZE_FAILED",
        message: err?.message ?? String(err),
        transferId
      });
      this.args.sendFileTransferAudit({
        transferId,
        direction: "upload",
        remotePath: upload.path,
        filename: path.basename(upload.path),
        sizeBytes: upload.size,
        transferredBytes: upload.received,
        status: "failed",
        errorMessage: err?.message ?? String(err)
      });
    }
  }

  private handleCancel(transferId: string): void {
    // Mark in-progress download for cancellation.
    this.cancelledDownloads.add(transferId);
    // Mark in-progress upload for cancellation.
    const upload = this.uploads.get(transferId);
    if (upload) upload.cancelled = true;
  }

  // ── Cleanup ────────────────────────────────────────────────────────────────

  private cleanupTmp(tmpPath: string): void {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }

  private cleanupAllUploads(): void {
    for (const [, upload] of this.uploads) {
      try { fs.closeSync(upload.fd); } catch {}
      this.cleanupTmp(upload.tmpPath);
    }
    this.uploads.clear();
  }

  dispose(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;
    this.cleanupAllUploads();
    this.args.ctx.logger?.info?.("[rcp.file] session disposed", {
      sessionId: this.args.sessionId,
      reason
    });
  }
}
