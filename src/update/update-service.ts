// src/update/update-service.ts

import fs from "fs";
import path from "path";
import crypto from "crypto";
import http from "http";
import https from "https";

import type { AgentContext } from "../core/agent-context";
import type {
  AgentMetadataResponse,
  AgentDownloadResponse,
  UpdateCheckResult,
  DownloadedUpdateInfo
} from "./update-types";
import { updateUpdateState } from "./update-state";
import { runWindowsMsiUpdate } from "./updater-runner";

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

function compareSemver(a: string, b: string): number {
  const parse = (v: string) =>
    v.split(".").map((x) => {
      const n = Number(x);
      return Number.isFinite(n) ? n : 0;
    });

  const av = parse(a);
  const bv = parse(b);
  const len = Math.max(av.length, bv.length);

  for (let i = 0; i < len; i += 1) {
    const ai = av[i] ?? 0;
    const bi = bv[i] ?? 0;
    if (ai > bi) return 1;
    if (ai < bi) return -1;
  }

  return 0;
}

function looksLikeSemver(v: string): boolean {
  return /^\d+\.\d+\.\d+([.-][A-Za-z0-9]+)?$/.test(v);
}

function getApiBaseUrl(ctx: AgentContext): string {
  const url =
    (ctx.config as any)?.apiBaseUrl ||
    (ctx.config as any)?.serverBaseUrl ||
    process.env.TRACENIUM_API_BASE_URL ||
    process.env.API_BASE_URL ||
    process.env.SERVER_BASE_URL;

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
  if (process.arch === "arm64") return "arm64";
  return "x64";
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

    req.end();
  });
}

function downloadToFile(
  urlString: string,
  filePath: string,
  timeoutMs = 5 * 60 * 1000
): Promise<{ size: number }> {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const lib = url.protocol === "https:" ? https : http;

    ensureDir(path.dirname(filePath));

    const tmpPath = `${filePath}.tmp`;
    const file = fs.createWriteStream(tmpPath);

    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      if ((res.statusCode || 500) >= 400) {
        file.close();
        fs.rmSync(tmpPath, { force: true });
        reject(new Error(`download_http_${res.statusCode || 500}`));
        return;
      }

      let bytes = 0;

      res.on("data", (chunk) => {
        bytes += chunk.length;
      });

      res.pipe(file);

      file.on("finish", () => {
        file.close();

        try {
          fs.renameSync(tmpPath, filePath);
          resolve({ size: bytes });
        } catch (err) {
          fs.rmSync(tmpPath, { force: true });
          reject(err);
        }
      });
    });

    req.on("error", (err) => {
      try {
        file.close();
      } catch {}
      fs.rmSync(tmpPath, { force: true });
      reject(err);
    });

    req.on("timeout", () => {
      req.destroy(new Error("download_timeout"));
    });
  });
}

export async function fetchAgentMetadata(
  ctx: AgentContext
): Promise<AgentMetadataResponse> {
  const base = getApiBaseUrl(ctx);
  const platform = getPlatform();
  const arch = getArch();

  const url = `${base}/api/v1/binaries/agent/metadata?platform=${encodeURIComponent(
    platform
  )}&arch=${encodeURIComponent(arch)}`;

  console.log("[update] fetching metadata", { url });

  const headers = buildHeaders(ctx);

  // metadata endpoint does not require auth; remove Authorization header if present
  delete headers.Authorization;

  //console.log("[update] metadata request headers", headers);

  const metadata = await httpJson<AgentMetadataResponse>(url, {
    headers,
    timeoutMs: 15000
  });

  //console.log("[update] metadata response", metadata);

  return metadata;
}

export function checkForAvailableUpdate(
  currentVersion: string,
  metadata: AgentMetadataResponse
): UpdateCheckResult {
  const latestVersion = String(metadata.latestVersion || "").trim();

  if (!latestVersion || !looksLikeSemver(latestVersion)) {
    return {
      available: false,
      currentVersion,
      latestVersion,
      reason: "invalid_remote_version",
      metadata
    };
  }

  const arch = getArch();
  const msiForArch = metadata.files?.msi?.[arch];

  if (!metadata.files?.msi || !msiForArch) {
    return {
      available: false,
      currentVersion,
      latestVersion,
      reason: "missing_msi_metadata",
      metadata
    };
  }

  if (metadata.forceUpdate) {
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

  const cmp = compareSemver(currentVersion, latestVersion);

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
  const arch = getArch();
  return metadata.files?.msi?.[arch]?.hash;
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

export async function performWindowsMsiUpdate(
  ctx: AgentContext,
  latestVersion: string,
  expectedHash?: string
) {
  const downloaded = await downloadWindowsMsi(ctx, latestVersion, expectedHash);

  updateUpdateState({
    updateInProgress: true,
    lastAttemptedVersion: latestVersion,
    lastAttemptedAtUtc: new Date().toISOString(),
    lastError: undefined,
    arch: getArch()
  });

  console.log("[update] executing msi", {
    path: downloaded.filePath,
    version: latestVersion,
    arch: getArch()
  });

  return runWindowsMsiUpdate(downloaded.filePath);
}