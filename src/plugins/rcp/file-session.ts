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
//     { op: "roots",    roots: ["C:\\Users", ...], maxUploadBytes }
//     { op: "listing",  path, entries: [{name, isDir, size, modifiedAt}] }
//     { op: "chunk",    transferId, seq, data, done? }  // base64
//     { op: "ready",    transferId }   // agent is ready to receive upload
//     { op: "uploadComplete", transferId, bytes, sha256 }  // it is on disk
//     { op: "error",    code, message, transferId? }
//
// ⚠️ `uploadComplete` is what makes an upload finished. Before it existed the
// browser marked the transfer done the moment it had sent its last chunk —
// which says only that the bytes left the browser, and the browser was
// dropping them silently whenever the channel was not open. A file could be
// shown as "Completed" having never fully arrived.
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
import * as crypto from "crypto";
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

// Ceiling on a single upload. The endpoint's temp space is the thing being
// protected: an upload lands in the staging directory before it is renamed
// into place, so an unbounded one fills the disk of the machine we are meant
// to be helping. 2 GiB is far above any support-session file and far below
// "the operator can fill /var".
//
// A tenant can lower it via policy (`remoteControl.maxUploadBytes`); raising it
// past the default is deliberately not possible — the number exists to bound
// damage, and a bound a caller can lift is not one.
const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024;

type UploadState = {
  path: string;
  tmpPath: string;
  fd: number;
  size: number;
  received: number;
  cancelled: boolean;
  // Set when the transfer died on its own rather than being cancelled by the
  // operator. Kept apart because the audit row means different things: one
  // says somebody changed their mind, the other says we lost the file.
  failure: string | null;
  // Running SHA-256 of what actually hit the disk. Computed while writing
  // rather than by re-reading the file afterwards: the point is to hash the
  // bytes we received, and a second read would hash whatever is on disk by
  // then — which is the same thing only if nothing else touched it.
  hash: crypto.Hash;
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
        // El tope viaja CON las raíces, no en un mensaje aparte: es la misma
        // pregunta —"¿qué puedo hacer en este equipo?"— y el navegador lo
        // necesita antes de dejar elegir un fichero. Sin él, la única forma de
        // enterarse de que un fichero es demasiado grande era mandarlo entero
        // y que el agente lo rechazara: minutos de subida para un "no".
        this.send({
          op: "roots",
          roots: this.jail.listRoots(),
          maxUploadBytes: this.maxUploadBytes()
        });
        break;

      case "list": {
        const listPath = String(msg.path ?? "/");
        this.handleList(listPath).catch((err: any) => {
          // Loguear, no solo responder. Un rechazo de la jaula sí quedaba
          // registrado, pero un readdir fallido se iba en silencio al
          // DataChannel — y readdir falla a menudo por motivos normales:
          // TCC en macOS le niega ~/Downloads a un LaunchDaemon sin Full
          // Disk Access, y en Linux el servicio no entra en los home de
          // otros usuarios. Sin esta línea el fallo era invisible en los
          // dos extremos a la vez, que es la peor combinación posible.
          this.args.ctx.logger?.warn?.("[rcp.file] list failed", {
            sessionId: this.args.sessionId,
            path: listPath.slice(0, 256),
            err: err?.message ?? String(err)
          });
          this.send({
            op: "error",
            code: "LIST_FAILED",
            message: err?.message ?? String(err)
          });
        });
        break;
      }

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

    // Refuse an oversize upload BEFORE opening a staging file. The declared
    // size is the browser's word and is checked again per chunk below — a
    // client that lies here simply gets stopped later, having written no more
    // than the ceiling.
    const maxBytes = this.maxUploadBytes();
    if (Number.isFinite(size) && size > maxBytes) {
      this.send({
        op: "error",
        code: "UPLOAD_TOO_LARGE",
        message: `This file is ${Math.round(size / 1048576)} MB; the limit for this device is ${Math.round(maxBytes / 1048576)} MB.`,
        transferId
      });
      this.args.sendFileTransferAudit({
        transferId,
        direction: "upload",
        remotePath: typeof destPath === "string" ? destPath.slice(0, 512) : "",
        filename: typeof destPath === "string" && destPath ? path.basename(destPath) : "",
        sizeBytes: Number(size) || 0,
        transferredBytes: 0,
        status: "failed",
        errorMessage: "exceeds the upload size limit"
      });
      return;
    }

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
      cancelled: false,
      failure: null,
      hash: crypto.createHash("sha256")
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

      // The ceiling again, this time against what has actually arrived. The
      // check at `upload` trusted a number the browser sent; this one does
      // not. Anything past the limit is refused mid-flight and the staging
      // file is dropped, so a client that under-declares its size cannot
      // fill the disk one chunk at a time.
      const maxBytes = this.maxUploadBytes();
      if (upload.received + buf.length > maxBytes) {
        upload.cancelled = true;
        try { fs.closeSync(upload.fd); } catch { /* ignore */ }
        this.cleanupTmp(upload.tmpPath);
        this.uploads.delete(transferId);
        this.args.ctx.logger?.warn?.("[rcp.file] upload exceeded the size limit mid-flight", {
          sessionId: this.args.sessionId,
          transferId,
          declared: upload.size,
          received: upload.received + buf.length,
          maxBytes
        });
        this.send({
          op: "error",
          code: "UPLOAD_TOO_LARGE",
          message: "The upload exceeded this device's size limit and was stopped.",
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
          errorMessage: "exceeded the upload size limit mid-transfer"
        });
        return;
      }

      fs.writeSync(upload.fd, buf);
      upload.hash.update(buf);
      upload.received += buf.length;
    } catch (err: any) {
      // ⚠️ A write that fails must not leave the transfer looking healthy.
      // It used to log and carry on, so the missing bytes were discovered by
      // nobody: the browser said "Completed" and the file on disk was short.
      // Cancelling here makes uploadDone take the failure path.
      upload.failure = err?.message ?? "write error";
      this.args.ctx.logger?.warn?.("[rcp.file] chunk write error", {
        sessionId: this.args.sessionId,
        transferId,
        err: err?.message
      });
    }
  }

  /**
   * The per-upload byte ceiling in force for this session.
   *
   * Policy may LOWER it; nothing may raise it. A limit that exists to bound
   * damage stops being one the moment the thing being bounded can widen it.
   */
  private maxUploadBytes(): number {
    // ⚠️ Antes llamaba a `policyRuntime.getFeatureValue`, un método que NUNCA
    // ha existido. Dentro del `try` devolvía `undefined` y el tope por
    // política era código muerto: el agente aplicaba siempre su techo y un
    // tenant no podía bajarlo. El test no lo vio porque su doble inventaba el
    // método — un fixture con una forma que el llamador real no tiene.
    const fromPolicy = this.args.ctx?.policyRuntime?.remoteFileMaxUploadBytes?.();
    if (typeof fromPolicy !== "number" || !Number.isFinite(fromPolicy) || fromPolicy <= 0) {
      return DEFAULT_MAX_UPLOAD_BYTES;
    }
    // Solo BAJA. Un límite que existe para acotar daño deja de serlo en
    // cuanto lo puede ensanchar aquello que acota.
    return Math.min(fromPolicy, DEFAULT_MAX_UPLOAD_BYTES);
  }

  private async handleUploadDone(transferId: string): Promise<void> {
    const upload = this.uploads.get(transferId);
    if (!upload) return;

    try { fs.closeSync(upload.fd); } catch { /* ignore */ }

    const digest = upload.hash.digest("hex");

    // ── The file must be whole ────────────────────────────────────────
    //
    // The browser declares a size up front and then streams chunks. Nothing
    // ever compared the two, and the browser dropped chunks silently whenever
    // the DataChannel was not open — so a short file was renamed into place
    // and audited as `completed`. An operator restoring a config from that
    // audit trail would have been restoring a truncated one.
    //
    // A byte count is what catches the real failure here: the transport is
    // DTLS, so bits do not flip in flight — chunks go MISSING. The digest is
    // computed anyway and reported, because "which file exactly" is the
    // question an audit gets asked a year later.
    if (!upload.cancelled && !upload.failure && upload.size > 0 && upload.received !== upload.size) {
      upload.failure =
        `incomplete: received ${upload.received} of ${upload.size} bytes`;
    }

    if (upload.failure) {
      this.cleanupTmp(upload.tmpPath);
      this.uploads.delete(transferId);
      this.args.ctx.logger?.warn?.("[rcp.file] upload failed; staging file discarded", {
        sessionId: this.args.sessionId,
        transferId,
        reason: upload.failure
      });
      this.send({
        op: "error",
        code: "UPLOAD_INCOMPLETE",
        message: upload.failure,
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
        errorMessage: upload.failure
      });
      return;
    }

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
      // Only NOW is the upload finished, and only now is the browser told.
      // It used to decide that for itself the moment it had sent its last
      // chunk — which proved the bytes left the browser, not that they
      // arrived, and certainly not that the rename succeeded.
      this.send({
        op: "uploadComplete",
        transferId,
        bytes: upload.received,
        sha256: digest
      });
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
