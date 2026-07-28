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
//     { op: "roots" }                                 // where may I start?
//     { op: "list",       path }
//     { op: "download",   transferId, path }
//     { op: "upload",     transferId, path, name, size }
//     { op: "chunk",      transferId, seq, data }   // base64
//     { op: "uploadDone", transferId }
//     { op: "cancel",     transferId }
//
//   Agent → Browser:
//     { op: "roots",    roots: ["C:\\Users", ...] }
//     { op: "listing",  path, entries: [{name, isDir, size, modifiedAt}] }
//     { op: "chunk",    transferId, seq, data, done? }  // base64
//     { op: "ready",    transferId }   // agent is ready to receive upload
//     { op: "error",    code, message, transferId? }
//
// The agent also fires RemoteFileTransferAudit gRPC events at transfer
// start and completion via the sendFileTransferAudit callback; the
// backend persists those to remote_file_transfers for audit.
//
// ── CONFINEMENT ─────────────────────────────────────────────────────────────
//
// This session runs as LocalSystem (Windows) / root (macOS, Linux). Every
// path arriving from the browser is therefore untrusted input to a fully
// privileged process, and goes through `PathJail.check()` before it reaches
// the filesystem — see path-jail.ts for the model. Two rules that matter for
// anyone editing this file:
//
//   1. NEVER pass the browser-supplied path to an fs call. Use the
//      `realPath` the jail hands back; it is symlink-resolved, and the
//      difference between the two IS the vulnerability.
//   2. Any NEW op that touches the filesystem needs its own check. The jail
//      is not a middleware — it cannot cover a call site that forgot it.

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { AgentContext } from "../../core/agent-context";
import { PathJail, type JailDecision } from "./path-jail";

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

// Flags for creating an upload's staging file.
//   O_CREAT|O_EXCL — fail if anything already exists at that name, so we can
//                    never adopt or truncate a file someone else planted.
//   O_NOFOLLOW     — refuse if the final component is a symlink.
// O_NOFOLLOW is POSIX-only; Windows leaves it undefined, and there the 0700
// per-session directory plus O_EXCL already cover the equivalent junction
// trick. `|| 0` keeps the bitmask valid on that platform.
const UPLOAD_OPEN_FLAGS =
  fs.constants.O_WRONLY |
  fs.constants.O_CREAT |
  fs.constants.O_EXCL |
  ((fs.constants as any).O_NOFOLLOW || 0);

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

  // Built once per session from the policy in force at session start. Not
  // re-read mid-session on purpose: a policy push that narrows the jail
  // shouldn't yank the ground out from under an in-flight transfer, and one
  // that widens it shouldn't take effect without a fresh operator action.
  private readonly jail: PathJail;

  // In-progress uploads keyed by transferId.
  private readonly uploads = new Map<string, UploadState>();
  // Per-session staging directory, created lazily on the first upload and
  // removed on dispose. See stagingDir().
  private staging: string | null = null;
  // Transfer IDs of downloads the browser has cancelled.
  private readonly cancelledDownloads = new Set<string>();

  constructor(dc: any, args: FileSessionArgs) {
    this.dc = dc;
    this.args = args;

    // An unreadable policy must not mean an unconfined session: on any
    // failure we fall back to `{}`, which the jail reads as "platform
    // defaults" — the secure posture, not an open one.
    let jailConfig = {};
    try {
      jailConfig = args.ctx.policyRuntime?.getRcpFileJailConfig?.() ?? {};
    } catch (err: any) {
      args.ctx.logger?.warn?.("[rcp.file] could not read jail policy; using defaults", {
        sessionId: args.sessionId,
        err: err?.message
      });
    }
    this.jail = new PathJail(jailConfig);
    args.ctx.logger?.info?.("[rcp.file] session confined", {
      sessionId: args.sessionId,
      roots: this.jail.listRoots()
    });

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

  /**
   * Validate a browser-supplied transfer id before it is used for ANYTHING.
   *
   * This is not cosmetic. `transferId` reaches the filesystem as part of the
   * upload staging filename, so an id of "../../../etc/cron.d/pwn" made
   * path.join walk straight out of the staging directory and had the agent —
   * running as LocalSystem / root — create, truncate and fill that file with
   * operator-supplied bytes. The destination jail did not catch it: the jail
   * checks `path`, and this is a different string entirely.
   *
   * The UI mints these with crypto.randomUUID(), so a strict charset costs
   * nothing and removes the whole class of problem rather than escaping it.
   */
  private takeTransferId(msg: any): string | null {
    const raw = typeof msg?.transferId === "string" ? msg.transferId : "";
    if (/^[A-Za-z0-9_-]{1,64}$/.test(raw)) return raw;
    this.args.ctx.logger?.warn?.("[rcp.file] rejected malformed transferId", {
      sessionId: this.args.sessionId,
      sample: raw.slice(0, 64)
    });
    this.send({
      op: "error",
      code: "INVALID_TRANSFER_ID",
      message: "Transfer id must be alphanumeric (with - or _), 1-64 characters."
    });
    return null;
  }

  private handleMessage(msg: any): void {
    const op = String(msg?.op ?? "");
    switch (op) {
      case "roots":
        // Tells the browser where it is allowed to begin. Before the jail
        // existed the panel opened on "/" and walked anywhere; now "/" is
        // almost always outside the roots, so it has to ask.
        this.send({ op: "roots", roots: this.jail.listRoots() });
        break;

      case "list":
        this.handleList(String(msg.path ?? "/")).catch((err: any) => {
          this.send({
            op: "error",
            code: "LIST_FAILED",
            message: err?.message ?? String(err)
          });
        });
        break;

      case "download": {
        const transferId = this.takeTransferId(msg);
        if (!transferId) break;
        this.handleDownload(transferId, String(msg.path ?? "")).catch((err: any) => {
          this.send({
            op: "error",
            code: "DOWNLOAD_FAILED",
            message: err?.message ?? String(err),
            transferId
          });
        });
        break;
      }

      case "upload": {
        const transferId = this.takeTransferId(msg);
        if (!transferId) break;
        this.handleUploadStart(
          transferId,
          String(msg.path ?? ""),
          String(msg.name ?? ""),
          Number(msg.size ?? 0)
        );
        break;
      }

      case "chunk": {
        const transferId = this.takeTransferId(msg);
        if (!transferId) break;
        this.handleChunk(transferId, Number(msg.seq ?? 0), String(msg.data ?? ""));
        break;
      }

      case "uploadDone": {
        const transferId = this.takeTransferId(msg);
        if (!transferId) break;
        this.handleUploadDone(transferId).catch(() => {});
        break;
      }

      case "cancel": {
        const transferId = this.takeTransferId(msg);
        if (!transferId) break;
        this.handleCancel(transferId);
        break;
      }

      default:
        this.args.ctx.logger?.debug?.("[rcp.file] unknown op", {
          sessionId: this.args.sessionId,
          op
        });
    }
  }

  // ── Handlers ───────────────────────────────────────────────────────────────

  /**
   * Gate a browser-supplied path. On refusal it reports to the browser and
   * returns null, so every call site reads as:
   *   `const resolved = this.gate(p, ...); if (!resolved) return;`
   */
  private gate(
    input: unknown,
    context: { transferId?: string }
  ): string | null {
    const decision: JailDecision = this.jail.check(input);
    if (decision.allowed) return decision.realPath;

    // Log the path the operator ASKED for — that's the audit-relevant fact,
    // and it's what makes a misconfigured root list diagnosable.
    this.args.ctx.logger?.warn?.("[rcp.file] path refused by jail", {
      sessionId: this.args.sessionId,
      code: decision.code,
      requested: typeof input === "string" ? input.slice(0, 256) : typeof input
    });
    this.send({
      op: "error",
      code: decision.code,
      message: decision.message,
      ...(context.transferId ? { transferId: context.transferId } : {})
    });
    return null;
  }

  private async handleList(dirPath: string): Promise<void> {
    const resolved = this.gate(dirPath, {});
    if (!resolved) return;
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

    // A refused download is an audit-worthy event in its own right — an
    // operator reaching for /etc/shadow should leave a row behind, not just
    // a line in the endpoint's log. Recorded against the path they asked
    // for, since there is no real path to speak of.
    const resolved = this.gate(filePath, { transferId });
    if (!resolved) {
      const asked = typeof filePath === "string" ? filePath : "";
      this.args.sendFileTransferAudit({
        transferId,
        direction: "download",
        remotePath: asked.slice(0, 512),
        filename: asked ? path.basename(asked) : "",
        sizeBytes: 0,
        transferredBytes: 0,
        status: "failed",
        errorMessage: "blocked by remote access path policy"
      });
      return;
    }

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

    // Gate the DESTINATION before opening anything. The old order created
    // the temp file first and only then resolved the destination, so a
    // refused upload still left a file on disk.
    const resolved = this.gate(destPath, { transferId });
    if (!resolved) {
      const asked = typeof destPath === "string" ? destPath : "";
      this.args.sendFileTransferAudit({
        transferId,
        direction: "upload",
        remotePath: asked.slice(0, 512),
        filename: asked ? path.basename(asked) : "",
        sizeBytes: Number(size) || 0,
        transferredBytes: 0,
        status: "failed",
        errorMessage: "blocked by remote access path policy"
      });
      return;
    }

    let tmpPath: string;
    let fd: number;
    try {
      tmpPath = path.join(this.stagingDir(), transferId);
      // O_EXCL: never adopt a file that is already there. O_NOFOLLOW: never
      // follow a symlink at the final component. Together with the 0700
      // mkdtemp directory above, this is what closes the classic
      // world-writable-temp race — previously this was openSync(path, "w"),
      // which happily followed a planted symlink and truncated whatever it
      // pointed at, as root.
      fd = fs.openSync(tmpPath, UPLOAD_OPEN_FLAGS, 0o600);
    } catch (err: any) {
      this.send({
        op: "error",
        code: "UPLOAD_INIT_FAILED",
        message: err?.message ?? String(err),
        transferId
      });
      return;
    }

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

    // Re-gate before the rename. The destination was checked when the upload
    // started, but an upload takes as long as it takes, and on a
    // world-writable tree a local user can plant a symlink at the target in
    // between. Checking again immediately before the write shrinks that
    // window to the syscall itself.
    const finalPath = this.jail.check(upload.path);
    if (!finalPath.allowed) {
      this.cleanupTmp(upload.tmpPath);
      this.uploads.delete(transferId);
      this.args.ctx.logger?.warn?.("[rcp.file] upload destination refused at finalize", {
        sessionId: this.args.sessionId,
        transferId,
        code: finalPath.code
      });
      this.send({
        op: "error",
        code: finalPath.code,
        message: finalPath.message,
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
        errorMessage: "blocked by remote access path policy"
      });
      return;
    }

    try {
      await fs.promises.mkdir(path.dirname(finalPath.realPath), { recursive: true });
      await fs.promises.rename(upload.tmpPath, finalPath.realPath);
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

  /**
   * Private staging directory for this session's uploads.
   *
   * `mkdtemp` is the point: it creates a directory with a name nobody can
   * predict, atomically, failing if it somehow exists — so unlike a fixed
   * path under the world-writable system temp directory, there is no window
   * in which an unprivileged local user can pre-create it (or replace it
   * with a symlink) and steer a root-owned write somewhere else.
   *
   * Mode 0700 on POSIX; on Windows the inherited ACL on the temp directory
   * is what applies, and the unguessable name carries the weight.
   */
  private stagingDir(): string {
    if (this.staging) return this.staging;
    this.staging = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-rcp-"), {
      encoding: "utf8"
    } as any);
    try {
      fs.chmodSync(this.staging, 0o700);
    } catch {
      // Windows chmod is a no-op for anything but the read-only bit.
    }
    return this.staging;
  }

  private cleanupTmp(tmpPath: string): void {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }

  /** Remove the staging directory once no upload can still be using it. */
  private cleanupStaging(): void {
    if (!this.staging) return;
    try {
      fs.rmSync(this.staging, { recursive: true, force: true });
    } catch (err: any) {
      this.args.ctx.logger?.debug?.("[rcp.file] staging cleanup failed", {
        sessionId: this.args.sessionId,
        err: err?.message
      });
    }
    this.staging = null;
  }

  private cleanupAllUploads(): void {
    for (const [, upload] of this.uploads) {
      try { fs.closeSync(upload.fd); } catch {}
      this.cleanupTmp(upload.tmpPath);
    }
    this.uploads.clear();
    // Every fd is closed and every staged file gone — the directory itself
    // can go now. Leaving these behind would accumulate one per session for
    // the lifetime of the host.
    this.cleanupStaging();
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
