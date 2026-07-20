// privsvc/macos/src/dp.ts
//
// Distribution Phase B — the Distribution Point (DP) role. Three IPC handlers:
//
//   sdp.dp.prefetch — warm the LAN cache: download the package via the normal
//                     multi-source loop (cdn → origin) into a content-addressed
//                     cache file (dp-cache/<sha256>), verify the hash, ensure
//                     the LAN server is running, and report ready.
//   sdp.dp.status   — cache inventory + server state (for the dashboard).
//   (serve)         — the HTTPS blob server is started lazily by prefetch;
//                     there is no standalone start/stop IPC in Phase B.
//
// Security model (deliberate, documented):
//   * INTEGRITY is end-to-end: every peer verifies sha256 + the signature gate
//     AFTER downloading, so the DP is an UNTRUSTED cache — it can never inject
//     code, only fail (and the peer falls back to cdn/origin).
//   * AUTH (confidentiality) reuses the enrollment mTLS material: the server
//     presents the agent's enrollment cert and REQUIRES a client cert chained
//     to the same tenant CA bundle. Only enrolled agents can fetch blobs.
//   * The peer connects by LAN IP while the DP cert's CN is its deviceId, so
//     peers skip hostname verification for the dp tier (bytes are hash-gated;
//     the server-side client-cert check is the real gate — see sdp.ts).
//
// Cache: content-addressed by sha256, size-capped with LRU eviction (atime
// approximated by mtime bump on serve).

import fs from "fs";
import http from "http";
import https from "https";
import path from "path";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
import { DATA_DIR, certPaths } from "./paths";

const execFileAsync = promisify(execFile);

const DP_CACHE_DIR = path.join(DATA_DIR, "dp-cache");
const DEFAULT_DP_PORT = 47821;
const DEFAULT_CACHE_MAX_BYTES = 20 * 1024 * 1024 * 1024; // 20 GB
const DEFAULT_DOWNLOAD_TIMEOUT_S = 900;
const MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024;

function dpPort(): number {
  const n = Number(process.env.TRACENIUM_DP_PORT);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : DEFAULT_DP_PORT;
}

function ensureCacheDir() {
  fs.mkdirSync(DP_CACHE_DIR, { recursive: true });
  try {
    fs.chmodSync(DP_CACHE_DIR, 0o700);
  } catch {
    // best-effort
  }
}

function cachePathFor(sha256: string): string {
  return path.join(DP_CACHE_DIR, sha256.toLowerCase());
}

function sha256OfFileStream(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (c) => hash.update(c));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

/** LRU eviction: delete oldest-mtime files until the cache fits the cap. */
export function evictLru(dir: string, maxBytes: number): number {
  let entries: Array<{ full: string; size: number; mtime: number }> = [];
  try {
    entries = fs
      .readdirSync(dir)
      .map((name) => {
        const full = path.join(dir, name);
        try {
          const st = fs.statSync(full);
          return st.isFile() ? { full, size: st.size, mtime: st.mtimeMs } : null;
        } catch {
          return null;
        }
      })
      .filter(Boolean) as any[];
  } catch {
    return 0;
  }
  let total = entries.reduce((s, e) => s + e.size, 0);
  if (total <= maxBytes) return 0;
  entries.sort((a, b) => a.mtime - b.mtime);
  let evicted = 0;
  for (const e of entries) {
    if (total <= maxBytes) break;
    try {
      fs.unlinkSync(e.full);
      total -= e.size;
      evicted += 1;
    } catch {
      // race — skip
    }
  }
  return evicted;
}

// ── LAN blob server ───────────────────────────────────────────────

let server: https.Server | null = null;

/** Parse+validate a request path. Returns the sha256 or null. Pure. */
export function blobShaFromPath(urlPath: string): string | null {
  const m = /^\/sdp\/blob\/([0-9a-f]{64})$/i.exec(urlPath.split("?")[0] || "");
  return m ? m[1].toLowerCase() : null;
}

/** Parse a single-range header against a file size. Pure. */
export function parseRange(
  header: string | undefined,
  size: number
): { start: number; end: number } | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m) return null;
  const start = m[1] === "" ? NaN : Number(m[1]);
  const end = m[2] === "" ? size - 1 : Number(m[2]);
  if (m[1] === "" && m[2] !== "") {
    // suffix form: last N bytes
    const n = Number(m[2]);
    if (!Number.isInteger(n) || n <= 0) return null;
    return { start: Math.max(0, size - n), end: size - 1 };
  }
  if (!Number.isInteger(start) || start < 0 || start >= size) return null;
  const boundedEnd = Math.min(Number.isInteger(end) ? end : size - 1, size - 1);
  if (boundedEnd < start) return null;
  return { start, end: boundedEnd };
}

function handleBlobRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405).end();
    return;
  }
  const sha = blobShaFromPath(req.url || "");
  if (!sha) {
    res.writeHead(404).end();
    return;
  }
  const file = cachePathFor(sha);
  let st: fs.Stats;
  try {
    st = fs.statSync(file);
  } catch {
    res.writeHead(404).end();
    return;
  }
  // Bump mtime so LRU eviction treats served blobs as fresh.
  try {
    fs.utimesSync(file, new Date(), new Date());
  } catch {}

  const range = parseRange(req.headers.range as string | undefined, st.size);
  const headers: Record<string, string | number> = {
    "Content-Type": "application/octet-stream",
    "Accept-Ranges": "bytes",
  };
  if (range) {
    headers["Content-Range"] = `bytes ${range.start}-${range.end}/${st.size}`;
    headers["Content-Length"] = range.end - range.start + 1;
    res.writeHead(206, headers);
  } else {
    headers["Content-Length"] = st.size;
    res.writeHead(200, headers);
  }
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  const stream = fs.createReadStream(file, range ? { start: range.start, end: range.end } : {});
  stream.on("error", () => res.destroy());
  stream.pipe(res);
}

function ensureDpServer(): { running: boolean; port: number; reason?: string } {
  const port = dpPort();
  if (server) return { running: true, port };
  const paths = certPaths();
  let key: Buffer, cert: Buffer, ca: Buffer;
  try {
    key = fs.readFileSync(paths.clientKey);
    cert = fs.readFileSync(paths.clientCert);
    ca = fs.readFileSync(paths.caBundle);
  } catch (err: any) {
    return { running: false, port, reason: `identity_unavailable:${err?.code || "read_failed"}` };
  }
  try {
    server = https.createServer(
      {
        key,
        cert,
        ca,
        // mTLS: only clients presenting a cert chained to the tenant CA get in.
        requestCert: true,
        rejectUnauthorized: true,
      },
      handleBlobRequest
    );
    server.on("error", (err: any) => {
      logger.error("dp_server_error", { error: err?.message || String(err) });
      try {
        server?.close();
      } catch {}
      server = null;
    });
    server.listen(port, "0.0.0.0");
    logger.info("dp_server_started", { port });
    return { running: true, port };
  } catch (err: any) {
    server = null;
    return { running: false, port, reason: err?.message || "listen_failed" };
  }
}

// ── IPC handlers ──────────────────────────────────────────────────

export async function handleDpPrefetch(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const sha256 = String(params.sha256 || "").toLowerCase();
  const timeoutSeconds = Number.isFinite(Number(params.timeoutSeconds))
    ? Math.max(60, Math.floor(Number(params.timeoutSeconds)))
    : DEFAULT_DOWNLOAD_TIMEOUT_S;
  const cacheMaxBytes = Number.isFinite(Number(params.cacheMaxBytes)) && Number(params.cacheMaxBytes) > 0
    ? Number(params.cacheMaxBytes)
    : DEFAULT_CACHE_MAX_BYTES;

  if (!/^[0-9a-f]{64}$/.test(sha256)) {
    return fail(req.id, "bad_request", "sha256 must be a 64-char hex string");
  }
  const rawSources = Array.isArray(params.sources) ? params.sources : [];
  const candidates = rawSources
    .filter((s: any) => s && typeof s.url === "string" && /^https:\/\//i.test(s.url))
    .map((s: any) => ({ tier: String(s.tier || "origin"), url: String(s.url) }));
  ensureCacheDir();

  const cacheFile = cachePathFor(sha256);

  // Already cached with a good hash → just make sure the server is up.
  if (fs.existsSync(cacheFile)) {
    try {
      const actual = await sha256OfFileStream(cacheFile);
      if (actual === sha256) {
        const srv = ensureDpServer();
        return success(req.id, { ready: srv.running, cached: true, port: srv.port, serverReason: srv.reason });
      }
      fs.unlinkSync(cacheFile);
    } catch {
      try { fs.unlinkSync(cacheFile); } catch {}
    }
  }

  if (candidates.length === 0) {
    return fail(req.id, "bad_request", "no usable sources for prefetch");
  }

  // Download via curl, same contract as sdp.download but into the cache.
  let lastError = "";
  for (const candidate of candidates) {
    const tmp = `${cacheFile}.part-${crypto.randomBytes(4).toString("hex")}`;
    const prefetchArgs = [
      "-fSL",
      "--max-time", String(timeoutSeconds),
      "--max-filesize", String(MAX_DOWNLOAD_BYTES),
      "-o", tmp,
    ];
    // Phase D — the tenant's bandwidth cap applies to the DP's own WAN pull too.
    const rateLimitKbps = Number(params.rateLimitKbps);
    if (Number.isInteger(rateLimitKbps) && rateLimitKbps > 0) {
      prefetchArgs.push("--limit-rate", `${rateLimitKbps}k`);
    }
    prefetchArgs.push(candidate.url);
    try {
      await execFileAsync(
        "/usr/bin/curl",
        prefetchArgs,
        { timeout: (timeoutSeconds + 30) * 1000, maxBuffer: 1024 * 1024 }
      );
    } catch (err: any) {
      try { fs.unlinkSync(tmp); } catch {}
      lastError = String(err?.stderr || err?.message || "curl failed").slice(0, 200);
      logger.warn("dp_prefetch_source_failed", { tier: candidate.tier, error: lastError });
      continue;
    }
    try {
      const actual = await sha256OfFileStream(tmp);
      if (actual !== sha256) {
        try { fs.unlinkSync(tmp); } catch {}
        lastError = `sha256 mismatch from ${candidate.tier}`;
        continue;
      }
      fs.renameSync(tmp, cacheFile);
      try { fs.chmodSync(cacheFile, 0o600); } catch {}
    } catch (err: any) {
      try { fs.unlinkSync(tmp); } catch {}
      lastError = err?.message || "hash/rename failed";
      continue;
    }

    const evicted = evictLru(DP_CACHE_DIR, cacheMaxBytes);
    const srv = ensureDpServer();
    logger.info("dp_prefetch_ok", { sha256, tier: candidate.tier, evicted, serverRunning: srv.running });
    return success(req.id, {
      ready: srv.running,
      cached: false,
      servedFrom: candidate.tier,
      port: srv.port,
      serverReason: srv.reason,
    });
  }

  return fail(req.id, "download_failed", lastError || "all sources failed");
}

export async function handleDpStatus(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  ensureCacheDir();
  let files: Array<{ sha256: string; sizeBytes: number; mtime: number }> = [];
  try {
    files = fs
      .readdirSync(DP_CACHE_DIR)
      .filter((n) => /^[0-9a-f]{64}$/.test(n))
      .map((n) => {
        const st = fs.statSync(path.join(DP_CACHE_DIR, n));
        return { sha256: n, sizeBytes: st.size, mtime: st.mtimeMs };
      });
  } catch {
    files = [];
  }
  return success(req.id, {
    serverRunning: !!server,
    port: dpPort(),
    cacheDir: DP_CACHE_DIR,
    blobCount: files.length,
    cacheBytes: files.reduce((s, f) => s + f.sizeBytes, 0),
  });
}
