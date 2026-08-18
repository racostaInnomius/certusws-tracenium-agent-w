// src/update/update-service.ts

import fs from "fs";
import path from "path";
import crypto from "crypto";
import http from "http";
import https from "https";

import type { AgentContext } from "../core/agent-context";
// Same budget the SDP plugin uses, for the same reason: it must stay under
// the IPC client's sdp.download ceiling. One constant, one invariant.
import { DOWNLOAD_BUDGET_SECONDS } from "../plugins/sdp";
import type {
  AgentBinaryFileMetadata,
  AgentMetadataResponse,
  AgentDownloadResponse,
  UpdateCheckResult,
  DownloadedUpdateInfo
} from "./update-types";
import { updateUpdateState } from "./update-state";
import { runMacosPkgUpdate, runWindowsMsiUpdate } from "./updater-runner";
import { evaluateSignatureGate, normalizeVerifyResponse } from "../plugins/sdp/signature-gate";
import { detectFamily } from "../platform/linux/distro";
import { compareSemver, looksLikeSemver } from "./semver";

function resolveBaseDir() {
  if (process.platform === "win32") {
    return path.join(process.env.ProgramData || "C:\\ProgramData", "Tracenium");
  }

  if (process.platform === "darwin") {
    return "/Library/Application Support/Tracenium";
  }

  return "/var/lib/tracenium";
}

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);

    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

/**
 * Resolve the REST API base URL for update / metadata calls.
 *
 * Previously this function ran five fallback layers:
 *
 *   ctx.config.apiBaseUrl         // never set anywhere
 *   ctx.config.serverBaseUrl      // the real one
 *   process.env.TRACENIUM_API_BASE_URL
 *   process.env.API_BASE_URL
 *   process.env.SERVER_BASE_URL
 *
 * The env-var tiers were redundant with config.ts — which already reads
 * SERVER_BASE_URL (and the Windows registry, and applies a fallback)
 * at process start and bakes the result into `config.serverBaseUrl`.
 * Having a second resolver that also reads env vars meant prod and dev
 * could silently disagree if they happened to set different variables.
 *
 * Single source of truth: `ctx.config.serverBaseUrl`. If a tester
 * really needs a one-off override, set `SERVER_BASE_URL` before the
 * daemon starts — config.ts handles it.
 */
function getApiBaseUrl(ctx: AgentContext): string {
  const url = ctx.config?.serverBaseUrl;

  if (!url) {
    console.error("[update] api base url missing", {
      configKeys: Object.keys(ctx.config || {})
    });
    throw new Error("update_api_base_url_missing");
  }

  const normalized = String(url).replace(/\/+$/, "");
  //console.log("[update] resolved api base url", { normalized });

  return normalized;
}

function getAuthToken(ctx: AgentContext): string | undefined {
  return (
    (ctx.enrollment as any)?.accessToken ||
    (ctx.enrollment as any)?.bootstrap?.accessToken ||
    (ctx.enrollment as any)?.token
  );
}

function getPlatform(): "windows" | "macos" | "linux" {
  if (process.platform === "win32") return "windows";
  if (process.platform === "darwin") return "macos";
  return "linux";
}

/**
 * Borra instaladores viejos del directorio de descargas.
 *
 * Cada intento de actualizacion deja su paquete y, si la descarga se corta, un
 * .tmp a medias. Nadie los recogia: en el servidor de produccion se
 * acumularon 7 versiones — 477 MB — en una maquina que ya habia llegado al 98%
 * de disco. Un endpoint con disco pequeno lo nota mucho antes.
 *
 * Se conserva SOLO el fichero recien validado. Los anteriores no sirven para
 * reintentar: si hace falta otra version se vuelve a descargar, y guardar un
 * paquete cuyo hash ya no se comprueba es peor que no tenerlo.
 *
 * Nunca lanza: una limpieza fallida no puede tumbar una actualizacion que si
 * funciono.
 */
function pruneOldDownloads(dir: string, keepPath: string): void {
  try {
    const keep = path.basename(keepPath);
    for (const name of fs.readdirSync(dir)) {
      if (name === keep) continue;
      if (!/\.(deb|rpm|msi|pkg|tmp)$/i.test(name)) continue;
      try {
        fs.rmSync(path.join(dir, name), { force: true });
      } catch {
        /* un fichero bloqueado no debe abortar el resto */
      }
    }
  } catch {
    /* directorio ilegible: no es motivo para fallar la actualizacion */
  }
}

function getArch(): "x64" | "arm64" {
  const envArch = process.env.TRACENIUM_ARCH;
  if (envArch === "arm64" || envArch === "x64") {
    return envArch;
  }

  if (process.platform === "win32") {
    const arch = process.env.PROCESSOR_ARCHITECTURE;
    const wow64 = process.env.PROCESSOR_ARCHITEW6432;

    if (arch === "ARM64" || wow64 === "ARM64") {
      return "arm64";
    }
  }

  return process.arch === "arm64" ? "arm64" : "x64";
}

// Map (platform, linux-family) → the key in metadata.files we should
// look at. Up through 1.1.21 this was hard-coded to "macOS = pkg,
// everything else = msi" — which meant Linux agents asked for an msi
// section that doesn't exist for `platform=linux` metadata, logged
// `metadata has no msi section`, and silently declared
// `update_completed` without installing anything. Confirmed in the
// wild on the Ubuntu host a169cbd3-…-74e12ccd0177 stuck at 1.1.21.
function getBinaryFormat(): "msi" | "pkg" | "deb" | "rpm" {
  const platform = getPlatform();
  if (platform === "macos") return "pkg";
  if (platform === "windows") return "msi";
  // linux
  return detectFamily().family === "debian" ? "deb" : "rpm";
}

function getBinaryGroupForCurrentPlatform(
  metadata: AgentMetadataResponse
): Record<string, AgentBinaryFileMetadata> | undefined {
  const format = getBinaryFormat();
  return metadata.files?.[format];
}

function getBinaryMetadataForCurrentPlatform(
  metadata: AgentMetadataResponse
): AgentBinaryFileMetadata | undefined {
  const arch = getArch();
  const group = getBinaryGroupForCurrentPlatform(metadata);
  return group?.[arch];
}

function buildHeaders(ctx: AgentContext): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json"
  };

  const token = getAuthToken(ctx);
  //console.log("[update] auth token present:", !!token);
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

function httpJson<T>(
  urlString: string,
  opts?: {
    method?: string;
    headers?: Record<string, string>;
    timeoutMs?: number;
  }
): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const lib = url.protocol === "https:" ? https : http;

    const req = lib.request(url, {
      method: opts?.method || "GET",
      headers: opts?.headers || {}
    }, (res) => {
      const chunks: Buffer[] = [];

      res.on("data", (d) => chunks.push(Buffer.from(d)));

      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");

        if ((res.statusCode || 500) >= 400) {
          reject(new Error(`http_${res.statusCode || 500}: ${raw || "request_failed"}`));
          return;
        }

        try {
          resolve(JSON.parse(raw) as T);
        } catch (err) {
          reject(new Error(`invalid_json_response: ${String(err)}`));
        }
      });

      res.on("error", (err) => {
        reject(err);
      });

      res.on("aborted", () => {
        reject(new Error("http_aborted"));
      });
    });

    // hard timeout (guaranteed)
    const timeoutMs = opts?.timeoutMs ?? 15000;
    const timeout = setTimeout(() => {
      req.destroy(new Error("http_timeout"));
    }, timeoutMs);

    req.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    req.on("close", () => {
      clearTimeout(timeout);
    });

    req.on("finish", () => {
      clearTimeout(timeout);
    });

    req.end();
  });
}

function downloadToFile(
  urlString: string,
  filePath: string,
  timeoutMs = 5 * 60 * 1000,
  idleTimeoutMs = 60 * 1000
): Promise<{ size: number }> {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const lib = url.protocol === "https:" ? https : http;

    ensureDir(path.dirname(filePath));

    const tmpPath = `${filePath}.tmp`;
    const file = fs.createWriteStream(tmpPath);

    let settled = false;
    let idleTimer: NodeJS.Timeout | null = null;
    let expectedBytes: number | null = null;
    let bytes = 0;

    const cleanup = () => {
      if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
      }
      try { file.close(); } catch {}
      try { fs.rmSync(tmpPath, { force: true }); } catch {}
    };

    const finish = (err: Error | null, size?: number) => {
      if (settled) return;
      settled = true;
      if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
      }
      if (err) {
        cleanup();
        reject(err);
      } else {
        resolve({ size: size ?? 0 });
      }
    };

    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      if ((res.statusCode || 500) >= 400) {
        finish(new Error(`download_http_${res.statusCode || 500}`));
        try { res.resume(); } catch {}
        return;
      }

      const cl = Number(res.headers["content-length"]);
      if (Number.isFinite(cl) && cl > 0) {
        expectedBytes = cl;
      }

      // Idle watchdog — if no bytes arrive for `idleTimeoutMs` we consider
      // the TCP pipe stalled (common on flaky Wi-Fi, captive portals, or
      // CDN edge flaps) and give up rather than wait out the 5 min total
      // timeout for a download that will never finish.
      const armIdle = () => {
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
          try { req.destroy(new Error("download_idle_timeout")); } catch {}
        }, idleTimeoutMs);
      };
      armIdle();

      res.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        armIdle();
      });

      // Server closed the socket mid-stream; pipe `finish` may still fire
      // on the writable side, so we need to detect this explicitly.
      res.on("aborted", () => {
        finish(new Error("download_aborted"));
      });

      res.pipe(file);

      file.on("error", (err) => finish(err));

      file.on("finish", () => {
        try { file.close(); } catch {}

        // If the server advertised content-length, enforce it — catches
        // truncated downloads that a middlebox passed through silently.
        if (expectedBytes != null && bytes !== expectedBytes) {
          finish(new Error(`download_truncated:${bytes}/${expectedBytes}`));
          return;
        }

        try {
          fs.renameSync(tmpPath, filePath);
          finish(null, bytes);
        } catch (err: any) {
          finish(err);
        }
      });
    });

    req.on("error", (err) => finish(err));

    req.on("timeout", () => {
      try { req.destroy(new Error("download_timeout")); } catch {}
    });
  });
}

export async function fetchAgentMetadata(
  ctx: AgentContext
): Promise<AgentMetadataResponse> {
  const base = getApiBaseUrl(ctx);
  const platform = getPlatform();
  const arch = getArch();

  const url = `${base}/api/v1/binaries/agent/metadata?platform=${encodeURIComponent(platform)}&arch=${encodeURIComponent(arch)}`;

  console.log("[update] fetching metadata", { url });

  const headers = buildHeaders(ctx);

  //console.log("[update] metadata request headers", headers);

  let metadata: AgentMetadataResponse | null = null;
  let lastError: any;

  // Exponential backoff with jitter. The metadata endpoint is polled by
  // every agent in the fleet on a timer — if it goes down and comes back,
  // a linear retry (`1s, 2s, 3s`) means hundreds of agents hit it within
  // the same 6 s window. Exponential + uniform jitter spreads the herd
  // across ~30 s. We keep the 3-attempt cap; if it's still failing after
  // ~20 s the scheduler will try again on its next tick anyway.
  const BASE_MS = 1_000;
  const MAX_MS = 30_000;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      metadata = await httpJson<AgentMetadataResponse>(url, {
        headers,
        timeoutMs: 15000
      });
      break;
    } catch (err) {
      lastError = err;
      console.warn("[update] metadata fetch failed", {
        attempt,
        error: String(err)
      });

      if (attempt < 3) {
        const exp = Math.min(BASE_MS * Math.pow(2, attempt - 1), MAX_MS);
        const delay = exp + Math.floor(Math.random() * exp);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }

  if (!metadata) {
    console.error("[update] metadata unavailable after retries", {
      lastError: String(lastError)
    });
    throw lastError || new Error("metadata_fetch_failed");
  }

  //console.log("[update] metadata response", metadata);

  return metadata;
}

export function checkForAvailableUpdate(
  currentVersion: string,
  metadata: AgentMetadataResponse
): UpdateCheckResult {
  const latestVersion = String(metadata.latestVersion || "").trim();

  if (!latestVersion || !looksLikeSemver(latestVersion)) {
    console.warn("[update] invalid latestVersion from metadata", {
      latestVersion
    });

    return {
      available: false,
      currentVersion,
      latestVersion,
      reason: "invalid_latest_version" as any,
      metadata
    };
  }

  const arch = getArch();
  const format = getBinaryFormat();
  const binaryGroup = getBinaryGroupForCurrentPlatform(metadata);

  console.log("[update] evaluating metadata", {
    currentVersion,
    latestVersion,
    arch,
    forceUpdate: metadata.forceUpdate === true,
    allowDowngrade: metadata.allowDowngrade === true,
    binaryFormat: format,
    hasBinaryGroup: !!binaryGroup,
    hasArch: !!getBinaryMetadataForCurrentPlatform(metadata)
  });

  if (!binaryGroup) {
    console.warn(`[update] metadata has no ${format} section`);
  }

  const binaryForArch = getBinaryMetadataForCurrentPlatform(metadata);

  if (!binaryForArch) {
    console.warn("[update] no compatible binary found in metadata", {
      arch,
      format,
      availableArchs: Object.keys(binaryGroup || {})
    });

    return {
      available: false,
      currentVersion,
      latestVersion,
      reason: "missing_binary_metadata",
      metadata
    };
  }

  const cmp = compareSemver(currentVersion, latestVersion);
  const forceUpdate = metadata.forceUpdate === true;
  const allowDowngrade = Boolean(metadata.allowDowngrade);

  if (cmp > 0 && !allowDowngrade) {
    console.warn("[update] remote version is older than current; downgrade blocked", {
      currentVersion,
      latestVersion,
      forceUpdate,
      allowDowngrade
    });

    return {
      available: false,
      currentVersion,
      latestVersion,
      reason: "downgrade_blocked",
      metadata
    };
  }

  if (forceUpdate) {
    return {
      available: true,
      currentVersion,
      latestVersion,
      reason: "forced_update",
      metadata
    };
  }

  if (
    metadata.minSupportedVersion &&
    looksLikeSemver(metadata.minSupportedVersion) &&
    compareSemver(currentVersion, metadata.minSupportedVersion) < 0
  ) {
    return {
      available: true,
      currentVersion,
      latestVersion,
      reason: "min_supported_breach",
      metadata
    };
  }

  if (cmp >= 0) {
    return {
      available: false,
      currentVersion,
      latestVersion,
      reason: "same_version",
      metadata
    };
  }

  return {
    available: true,
    currentVersion,
    latestVersion,
    reason: "new_version_available",
    metadata
  };
}

export function getExpectedHashForArch(
  metadata: AgentMetadataResponse
): string | undefined {
  return getBinaryMetadataForCurrentPlatform(metadata)?.hash;
}

export async function fetchWindowsMsiDownloadUrl(
  ctx: AgentContext,
  version = "latest"
): Promise<AgentDownloadResponse> {
  const base = getApiBaseUrl(ctx);
  const arch = getArch();

  const url =
    `${base}/api/v1/binaries/agent` +
    `?platform=windows&arch=${encodeURIComponent(arch)}&format=msi&version=${encodeURIComponent(version)}`;

  console.log("[update] requesting download url", {
    version,
    arch,
    platform: "windows"
  });

  return httpJson<AgentDownloadResponse>(url, {
    headers: buildHeaders(ctx),
    timeoutMs: 15000
  });
}

export async function fetchMacosPkgDownloadUrl(
  ctx: AgentContext,
  version = "latest"
): Promise<AgentDownloadResponse> {
  const base = getApiBaseUrl(ctx);
  const arch = getArch();

  const url =
    `${base}/api/v1/binaries/agent` +
    `?platform=macos&arch=${encodeURIComponent(arch)}&format=pkg&version=${encodeURIComponent(version)}`;

  console.log("[update] requesting download url", {
    version,
    arch,
    platform: "macos"
  });

  return httpJson<AgentDownloadResponse>(url, {
    headers: buildHeaders(ctx),
    timeoutMs: 15000
  });
}

export async function downloadWindowsMsi(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string
): Promise<DownloadedUpdateInfo> {
  const dl = await fetchWindowsMsiDownloadUrl(ctx, latestVersion);

  if (!dl?.downloadUrl) {
    throw new Error("update_download_url_missing");
  }

  const dir = path.join(resolveBaseDir(), "updates");
  ensureDir(dir);

  const arch = getArch();
  const fileName = `Tracenium-Agent-${latestVersion}-${arch}.msi`;
  const filePath = path.join(dir, fileName);

  const { size } = await downloadToFile(dl.downloadUrl, filePath);

  const sha256 = await sha256File(filePath);

  if (!expectedHash) {
    console.warn("[update] expected hash missing for arch", { arch });
  }

  if (expectedHash && expectedHash.toLowerCase() !== sha256.toLowerCase()) {
    fs.rmSync(filePath, { force: true });
    throw new Error("update_hash_mismatch");
  }

  pruneOldDownloads(dir, filePath);

  updateUpdateState({
    lastDownloadedPath: filePath,
    lastDownloadedSha256: sha256,
    arch: getArch()
  });

  return {
    filePath,
    fileName,
    sha256,
    size,
    latestVersion
  };
}

export async function downloadMacosPkg(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string
): Promise<DownloadedUpdateInfo> {
  const dl = await fetchMacosPkgDownloadUrl(ctx, latestVersion);

  if (!dl?.downloadUrl) {
    throw new Error("update_download_url_missing");
  }

  const dir = path.join(resolveBaseDir(), "updates");
  ensureDir(dir);

  const arch = getArch();
  const fileName = `Tracenium-Agent-${latestVersion}-${arch}.pkg`;
  const filePath = path.join(dir, fileName);

  const { size } = await downloadToFile(dl.downloadUrl, filePath);
  const sha256 = await sha256File(filePath);

  if (!expectedHash) {
    console.warn("[update] expected hash missing for arch", { arch });
  }

  if (expectedHash && expectedHash.toLowerCase() !== sha256.toLowerCase()) {
    fs.rmSync(filePath, { force: true });
    throw new Error("update_hash_mismatch");
  }

  pruneOldDownloads(dir, filePath);

  updateUpdateState({
    lastDownloadedPath: filePath,
    lastDownloadedSha256: sha256,
    arch: getArch()
  });

  return {
    filePath,
    fileName,
    sha256,
    size,
    latestVersion
  };
}

/**
 * Verify a downloaded Windows update MSI's Authenticode signature via the OS
 * (WinVerifyTrust, in the privsvc). Throws `update_signature_invalid:<reason>` —
 * and deletes the file + records the failure — when the signature isn't trusted.
 * Self-update always requires a signature, so the gate is unconditional.
 */
async function verifyWindowsUpdateSignatureOrThrow(
  ctx: AgentContext,
  filePath: string,
  latestVersion: string
): Promise<void> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `update-verify-${Date.now()}`,
    method: "sdp.verifySignature",
    params: { stagingPath: filePath, format: "msi" },
    meta: {
      tenantId: ctx.enrollment?.tenantId,
      deviceId: ctx.enrollment?.deviceId,
    },
  });
  const gate = evaluateSignatureGate(true, normalizeVerifyResponse(resp));
  if (!gate.proceed) {
    try { fs.rmSync(filePath, { force: true }); } catch { /* best-effort cleanup */ }
    updateUpdateState({
      updateInProgress: false,
      status: "failed",
      lastError: `update_signature_invalid:${gate.reason}`,
      lastAttemptedAtUtc: new Date().toISOString(),
      lastAttemptedVersion: latestVersion,
      arch: getArch(),
    });
    console.error("[update] signature gate blocked update", {
      version: latestVersion,
      reason: gate.reason,
    });
    throw new Error(`update_signature_invalid:${gate.reason}`);
  }
  console.log("[update] update signature verified (OS trust)", { path: filePath, version: latestVersion });
}

/**
 * Reserved packageId for the agent's own update.
 *
 * `sdp.download` requires a positive integer because catalog packages have one
 * and the staging filename is built from it (`pkg-<packageId>-<nonce>.<fmt>`).
 * The self-update has no catalog row, so it gets a sentinel that cannot collide
 * with a real package id and is obvious in a staging directory listing.
 */
export const SELF_UPDATE_PACKAGE_ID = 999_000_001;

/**
 * Download the update through privsvc's `sdp.download` so it can come from the
 * site's distribution point instead of the internet.
 *
 * Why route the update through the SDP primitive at all: `downloadToFile` is a
 * plain HTTP GET against a single URL from this process. It cannot present the
 * enrollment client certificate a DP requires, has no notion of ordered
 * fallback, and knows nothing about the download budget. Everything needed to
 * pull from a DP already exists on the privsvc side and was proven in the field
 * this week — ordered sources, the sha256 gate, per-source budget slicing, a 5s
 * connect timeout so an unreachable DP costs seconds, and `servedBy` telemetry.
 * Duplicating any of that in Node would be a second implementation to keep
 * honest.
 *
 * Returns null when this route is not usable — no sources, or a privsvc too old
 * to know the method. The caller then falls back to the direct download, so an
 * endpoint whose privsvc has not been upgraded keeps updating exactly as today.
 *
 * A failure REPORTED by privsvc (every source exhausted) is different: it means
 * the origin was in the list and also failed, so there is nothing left to try
 * and the error propagates.
 */
export async function downloadUpdateViaSources(
  ctx: AgentContext,
  opts: {
    version: string;
    format: string;
    expectedHash: string;
    sources: Array<{ tier: string; url: string }>;
    sizeBytes?: number;
  }
): Promise<{ filePath: string; sha256: string; size: number; servedBy?: string } | null> {
  if (!opts.sources?.length || !opts.expectedHash) return null;

  const resp = await ctx.priv.call({
    v: 1,
    id: `update-download-${Date.now()}`,
    method: "sdp.download",
    params: {
      // `url` is the legacy single-source field privsvc falls back to when
      // `sources` is absent; keep the origin there so an older privsvc that
      // ignores `sources` still downloads the right bytes.
      url: opts.sources[opts.sources.length - 1]?.url,
      sources: opts.sources,
      sha256: opts.expectedHash.toLowerCase(),
      format: opts.format,
      packageId: SELF_UPDATE_PACKAGE_ID,
      timeoutSeconds: DOWNLOAD_BUDGET_SECONDS,
      ...(opts.sizeBytes ? { sizeBytes: opts.sizeBytes } : {}),
    },
    meta: {
      tenantId: ctx.enrollment?.tenantId,
      deviceId: ctx.enrollment?.deviceId,
    },
  });

  if (!resp?.ok) {
    const code = String((resp as any)?.error?.code || "");
    // Method missing / rejected outright → this privsvc predates the feature.
    // Fall back rather than failing an update that would otherwise work.
    if (code === "not_supported" || code === "bad_version") {
      console.warn("[update] privsvc has no sdp.download; using direct download");
      return null;
    }
    const msg = String((resp as any)?.error?.message || code || "download_failed");
    throw new Error(`update_download_failed:${msg}`);
  }

  const result = (resp as any).result ?? {};
  const filePath = String(result.stagingPath || "");
  if (!filePath) return null;

  console.log("[update] downloaded via privsvc", {
    version: opts.version,
    servedBy: result.servedBy,
    sizeBytes: result.sizeBytes,
  });

  return {
    filePath,
    sha256: String(result.sha256 || opts.expectedHash).toLowerCase(),
    size: Number(result.sizeBytes || 0),
    servedBy: result.servedBy ? String(result.servedBy) : undefined,
  };
}

export async function performWindowsMsiUpdate(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string,
  downloadUrlOverride?: string,
  /**
   * Ordered download sources (dp → cdn → origin) when the control plane knows
   * this device sits behind a distribution point. Tried through privsvc first;
   * absent or unusable → the direct download below, unchanged.
   */
  sources?: Array<{ tier: string; url: string }>
) {
  let downloaded;

  // ── Distribution point first ────────────────────────────────────
  // When the control plane tells us this device sits behind a DP, pull the
  // update over the LAN instead of the internet. privsvc owns that path (it
  // holds the enrollment cert the DP demands) and falls back through the
  // ordered tiers on its own, so `origin` being last in the list IS the
  // internet fallback. Returning null means the route is unavailable — no
  // sources, or a privsvc too old — and we continue to the direct download.
  if (sources?.length && expectedHash) {
    const viaDp = await downloadUpdateViaSources(ctx, {
      version: latestVersion,
      format: "msi",
      expectedHash,
      sources,
    });
    if (viaDp) {
      updateUpdateState({
        lastDownloadedPath: viaDp.filePath,
        lastDownloadedSha256: viaDp.sha256,
        arch: getArch(),
      });
      downloaded = {
        filePath: viaDp.filePath,
        fileName: path.basename(viaDp.filePath),
        sha256: viaDp.sha256,
        size: viaDp.size,
        latestVersion,
      };
    }
  }

  if (!downloaded && downloadUrlOverride) {
    const dir = path.join(resolveBaseDir(), "updates");
    ensureDir(dir);

    const arch = getArch();
    const fileName = `Tracenium-Agent-${latestVersion}-${arch}.msi`;
    const filePath = path.join(dir, fileName);

    console.log("[update] downloading from override url", {
      url: downloadUrlOverride,
      version: latestVersion
    });

    const { size } = await downloadToFile(downloadUrlOverride, filePath);
    const sha256 = await sha256File(filePath);

    if (expectedHash && expectedHash.toLowerCase() !== sha256.toLowerCase()) {
      fs.rmSync(filePath, { force: true });
      throw new Error("update_hash_mismatch");
    }

    pruneOldDownloads(dir, filePath);

    downloaded = {
      filePath,
      fileName,
      sha256,
      size,
      latestVersion
    };

    updateUpdateState({
      lastDownloadedPath: filePath,
      lastDownloadedSha256: sha256,
      arch: getArch()
    });

  } else if (!downloaded) {
    downloaded = await downloadWindowsMsi(ctx, latestVersion, expectedHash);
  }

  // ── Signature gate ──────────────────────────────────────────────
  // The agent's OWN update MSI must be Authenticode-signed and trusted by the
  // OS — SHA-256 alone only proves the bytes match what the backend served, not
  // that they're a genuine signed Tracenium build. Verify the downloaded MSI via
  // WinVerifyTrust (privsvc, LocalSystem) BEFORE applying. Fail-closed: an
  // unsigned / tampered / untrusted-chain update is refused and deleted.
  await verifyWindowsUpdateSignatureOrThrow(ctx, downloaded.filePath, latestVersion);

  updateUpdateState({
    updateInProgress: true,
    status: "install_started",
    installStartedAtUtc: new Date().toISOString(),
    lastAttemptedAtUtc: new Date().toISOString(),
    lastAttemptedVersion: latestVersion,
    lastError: undefined,
    arch: getArch()
  });

  console.log("[update] executing msi", {
    path: downloaded.filePath,
    version: latestVersion,
    arch: getArch()
  });

  const result = await runWindowsMsiUpdate(downloaded.filePath);

  return result;
}

export async function performMacosPkgUpdate(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string,
  downloadUrlOverride?: string,
  /**
   * Ordered download sources (dp → cdn → origin) when the control plane knows
   * this device sits behind a distribution point. Tried through privsvc first;
   * absent or unusable → the direct download below, unchanged.
   */
  sources?: Array<{ tier: string; url: string }>
) {
  let downloaded;

  // ── Distribution point first ────────────────────────────────────
  // When the control plane tells us this device sits behind a DP, pull the
  // update over the LAN instead of the internet. privsvc owns that path (it
  // holds the enrollment cert the DP demands) and falls back through the
  // ordered tiers on its own, so `origin` being last in the list IS the
  // internet fallback. Returning null means the route is unavailable — no
  // sources, or a privsvc too old — and we continue to the direct download.
  if (sources?.length && expectedHash) {
    const viaDp = await downloadUpdateViaSources(ctx, {
      version: latestVersion,
      format: "pkg",
      expectedHash,
      sources,
    });
    if (viaDp) {
      updateUpdateState({
        lastDownloadedPath: viaDp.filePath,
        lastDownloadedSha256: viaDp.sha256,
        arch: getArch(),
      });
      downloaded = {
        filePath: viaDp.filePath,
        fileName: path.basename(viaDp.filePath),
        sha256: viaDp.sha256,
        size: viaDp.size,
        latestVersion,
      };
    }
  }

  if (!downloaded && downloadUrlOverride) {
    const dir = path.join(resolveBaseDir(), "updates");
    ensureDir(dir);

    const arch = getArch();
    const fileName = `Tracenium-Agent-${latestVersion}-${arch}.pkg`;
    const filePath = path.join(dir, fileName);

    console.log("[update] downloading pkg from override url", {
      url: downloadUrlOverride,
      version: latestVersion
    });

    const { size } = await downloadToFile(downloadUrlOverride, filePath);
    const sha256 = await sha256File(filePath);

    if (expectedHash && expectedHash.toLowerCase() !== sha256.toLowerCase()) {
      fs.rmSync(filePath, { force: true });
      throw new Error("update_hash_mismatch");
    }

    pruneOldDownloads(dir, filePath);

    downloaded = {
      filePath,
      fileName,
      sha256,
      size,
      latestVersion
    };

    updateUpdateState({
      lastDownloadedPath: filePath,
      lastDownloadedSha256: sha256,
      arch: getArch()
    });
  } else if (!downloaded) {
    downloaded = await downloadMacosPkg(ctx, latestVersion, expectedHash);
  }

  updateUpdateState({
    updateInProgress: true,
    status: "install_started",
    installStartedAtUtc: new Date().toISOString(),
    lastAttemptedAtUtc: new Date().toISOString(),
    lastAttemptedVersion: latestVersion,
    lastError: undefined,
    arch: getArch()
  });

  console.log("[update] executing pkg", {
    path: downloaded.filePath,
    version: latestVersion,
    arch: getArch()
  });

  const result = await runMacosPkgUpdate(downloaded.filePath);

  return result;
}

// ── Phase 10 — Linux OTA self-update ─────────────────────────────
//
// Mirror of performMacosPkgUpdate / performWindowsMsiUpdate. The
// only Linux-specific bit is the format selection: debian-family →
// .deb, rhel-family + suse → .rpm. We detect at the agent layer
// (here) so the same `files.deb` / `files.rpm` keys in the backend
// metadata work across all rpm-based distros.

export async function fetchLinuxPkgDownloadUrl(
  ctx: AgentContext,
  version = "latest"
): Promise<AgentDownloadResponse> {
  const base = getApiBaseUrl(ctx);
  const arch = getArch();
  const family = detectFamily().family;
  const format = family === "debian" ? "deb" : "rpm";

  const url =
    `${base}/api/v1/binaries/agent` +
    `?platform=linux&arch=${encodeURIComponent(arch)}&format=${format}&version=${encodeURIComponent(version)}`;

  console.log("[update] requesting download url", {
    version,
    arch,
    platform: "linux",
    family,
    format,
  });

  return httpJson<AgentDownloadResponse>(url, {
    headers: buildHeaders(ctx),
    timeoutMs: 15000,
  });
}

export async function downloadLinuxPkg(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string
): Promise<DownloadedUpdateInfo> {
  const dl = await fetchLinuxPkgDownloadUrl(ctx, latestVersion);

  if (!dl?.downloadUrl) {
    throw new Error("update_download_url_missing");
  }

  const dir = path.join(resolveBaseDir(), "updates");
  ensureDir(dir);

  const arch = getArch();
  const family = detectFamily().family;
  const ext = family === "debian" ? "deb" : "rpm";
  const fileName = `tracenium-agent-${latestVersion}-${arch}.${ext}`;
  const filePath = path.join(dir, fileName);

  const { size } = await downloadToFile(dl.downloadUrl, filePath);
  const sha256 = await sha256File(filePath);

  if (!expectedHash) {
    console.warn("[update] expected hash missing for arch", { arch, family });
  }

  if (expectedHash && expectedHash.toLowerCase() !== sha256.toLowerCase()) {
    fs.rmSync(filePath, { force: true });
    throw new Error("update_hash_mismatch");
  }

  pruneOldDownloads(dir, filePath);

  updateUpdateState({
    lastDownloadedPath: filePath,
    lastDownloadedSha256: sha256,
    arch: getArch(),
  });

  return {
    filePath,
    fileName,
    sha256,
    size,
    latestVersion,
  };
}

export async function performLinuxUpdate(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string,
  downloadUrlOverride?: string,
  /**
   * Ordered download sources (dp → cdn → origin) when the control plane knows
   * this device sits behind a distribution point. Tried through privsvc first;
   * absent or unusable → the direct download below, unchanged.
   */
  sources?: Array<{ tier: string; url: string }>
) {
  let downloaded;

  // ── Distribution point first ────────────────────────────────────
  // When the control plane tells us this device sits behind a DP, pull the
  // update over the LAN instead of the internet. privsvc owns that path (it
  // holds the enrollment cert the DP demands) and falls back through the
  // ordered tiers on its own, so `origin` being last in the list IS the
  // internet fallback. Returning null means the route is unavailable — no
  // sources, or a privsvc too old — and we continue to the direct download.
  if (sources?.length && expectedHash) {
    const viaDp = await downloadUpdateViaSources(ctx, {
      version: latestVersion,
      format: getBinaryFormat(),
      expectedHash,
      sources,
    });
    if (viaDp) {
      updateUpdateState({
        lastDownloadedPath: viaDp.filePath,
        lastDownloadedSha256: viaDp.sha256,
        arch: getArch(),
      });
      downloaded = {
        filePath: viaDp.filePath,
        fileName: path.basename(viaDp.filePath),
        sha256: viaDp.sha256,
        size: viaDp.size,
        latestVersion,
      };
    }
  }

  if (!downloaded && downloadUrlOverride) {
    const dir = path.join(resolveBaseDir(), "updates");
    ensureDir(dir);

    const arch = getArch();
    const family = detectFamily().family;
    const ext = family === "debian" ? "deb" : "rpm";
    const fileName = `tracenium-agent-${latestVersion}-${arch}.${ext}`;
    const filePath = path.join(dir, fileName);

    console.log("[update] downloading linux pkg from override url", {
      url: downloadUrlOverride,
      version: latestVersion,
      family,
      ext,
    });

    const { size } = await downloadToFile(downloadUrlOverride, filePath);
    const sha256 = await sha256File(filePath);

    if (expectedHash && expectedHash.toLowerCase() !== sha256.toLowerCase()) {
      fs.rmSync(filePath, { force: true });
      throw new Error("update_hash_mismatch");
    }

    pruneOldDownloads(dir, filePath);

    downloaded = {
      filePath,
      fileName,
      sha256,
      size,
      latestVersion,
    };

    updateUpdateState({
      lastDownloadedPath: filePath,
      lastDownloadedSha256: sha256,
      arch: getArch(),
    });
  } else if (!downloaded) {
    downloaded = await downloadLinuxPkg(ctx, latestVersion, expectedHash);
  }

  updateUpdateState({
    updateInProgress: true,
    status: "install_started",
    installStartedAtUtc: new Date().toISOString(),
    lastAttemptedAtUtc: new Date().toISOString(),
    lastAttemptedVersion: latestVersion,
    lastError: undefined,
    arch: getArch(),
  });

  console.log("[update] executing linux package", {
    path: downloaded.filePath,
    version: latestVersion,
    arch: getArch(),
    family: detectFamily().family,
  });

  // ── Linux: route the install through privsvc ────────────────────
  //
  // On Linux the agent daemon runs as the unprivileged `tracenium`
  // user. dpkg / rpm need root — calling them from here would fail
  // with EPERM (and silently, because the previous code spawned
  // detached and returned `{ started: true }` before the child died).
  // The privsvc daemon runs as root and exposes `agent.install` for
  // this exact purpose; see privsvc/linux/src/agent-install.ts for
  // the rationale around systemd-run --scope dispatching.
  //
  // privsvc handles format selection internally (deb vs rpm by
  // distro family). We pass the format the agent already computed so
  // privsvc can reject early on a family mismatch rather than
  // letting dpkg/rpm fail with an obscure error.
  const family = detectFamily().family;
  const format = family === "debian" ? "deb" : "rpm";

  const installResp = await ctx.priv.call({
    v: 1,
    id: `agent-install-${Date.now()}`,
    method: "agent.install",
    params: {
      path: downloaded.filePath,
      format,
      version: latestVersion,
    },
    meta: {
      tenantId: ctx.enrollment.tenantId,
      deviceId: ctx.enrollment.deviceId,
    },
  });

  if (installResp.error) {
    throw new Error(
      `agent.install failed: ${installResp.error.code}: ${installResp.error.message}`
    );
  }

  return {
    started: true,
    command: installResp.ok?.command || "privsvc:agent.install",
    args: installResp.ok?.args || [],
  };
}
