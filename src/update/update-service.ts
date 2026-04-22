// src/update/update-service.ts

import fs from "fs";
import path from "path";
import crypto from "crypto";
import http from "http";
import https from "https";

import type { AgentContext } from "../core/agent-context";
import type {
  AgentBinaryFileMetadata,
  AgentMetadataResponse,
  AgentDownloadResponse,
  UpdateCheckResult,
  DownloadedUpdateInfo
} from "./update-types";
import { updateUpdateState } from "./update-state";
import { runMacosPkgUpdate, runWindowsMsiUpdate } from "./updater-runner";
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

function getBinaryFormat(): "msi" | "pkg" {
  return getPlatform() === "macos" ? "pkg" : "msi";
}

function getBinaryMetadataForCurrentPlatform(
  metadata: AgentMetadataResponse
): AgentBinaryFileMetadata | undefined {
  const arch = getArch();
  return getPlatform() === "macos"
    ? metadata.files?.pkg?.[arch]
    : metadata.files?.msi?.[arch];
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

  console.log("[update] evaluating metadata", {
    currentVersion,
    latestVersion,
    arch,
    forceUpdate: metadata.forceUpdate === true,
    allowDowngrade: metadata.allowDowngrade === true,
    binaryFormat: getBinaryFormat(),
    hasBinaryGroup: getPlatform() === "macos" ? !!metadata.files?.pkg : !!metadata.files?.msi,
    hasArch: !!getBinaryMetadataForCurrentPlatform(metadata)
  });

  if (getPlatform() === "macos" && !metadata.files?.pkg) {
    console.warn("[update] metadata has no pkg section");
  }

  if (getPlatform() !== "macos" && !metadata.files?.msi) {
    console.warn("[update] metadata has no msi section");
  }

  const binaryForArch = getBinaryMetadataForCurrentPlatform(metadata);

  if (!binaryForArch) {
    console.warn("[update] no compatible binary found in metadata", {
      arch,
      format: getBinaryFormat(),
      availableArchs: Object.keys((getPlatform() === "macos" ? metadata.files?.pkg : metadata.files?.msi) || {})
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

export async function performWindowsMsiUpdate(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string,
  downloadUrlOverride?: string
) {
  let downloaded;

  if (downloadUrlOverride) {
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

  } else {
    downloaded = await downloadWindowsMsi(ctx, latestVersion, expectedHash);
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
  downloadUrlOverride?: string
) {
  let downloaded;

  if (downloadUrlOverride) {
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
  } else {
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
