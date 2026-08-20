// src/status/catalog-install-request-watcher.ts
//
// Tray -> core channel for the self-service Software Catalog tab. The
// tray app can't dispatch a job itself — it has no control-plane
// credentials, no network access, nothing beyond the JSON status file
// it already reads. So "please install this" travels the OPPOSITE
// direction from every other tray/core exchange (core -> tray, via
// tray-status.json): the tray writes a small request file, and this
// module — polled from the gRPC stream lifecycle in grpc-stream.ts —
// picks it up and turns it into a SelfInstallRequest over the already-
// authenticated stream.
//
// Same file-mediated shape as LocationSink -> geo.ts's collectMacos()
// (see that pair for the precedent this borrows from): a signed app in
// the console user's session writes where this SYSTEM/root process
// can't reach directly, and the daemon/service polls for it.
//
// macOS: AgentCore runs as a LaunchDaemon (root), which can read any
// user's home directory directly — geo.ts's dscl-backed
// resolveHomeDirectory() is the authoritative lookup there.
//
// Windows: AgentCore also runs privileged (LocalSystem — see
// windows/installer/wix/AgentCoreFiles.wxs), which likewise has
// unrestricted read access to any user's profile. The tray writes to
// its OWN already-writable per-user folder (%LOCALAPPDATA%, i.e.
// C:\Users\<user>\AppData\Local\Tracenium — see CatalogInstallSink.cs)
// instead of the shared C:\ProgramData\Tracenium\Agent\status\ dir the
// status JSON lives in, because that dir's ACL is SYSTEM/Admin-write
// only (paths.ts) — a plain user can read tray-status.json from it but
// not write a new file into it. No ACL changes needed this way.
//
// Unlike macOS's `stat /dev/console` (near-instant), resolving the
// Windows interactive user goes through PowerShell (couple hundred ms
// startup). This module polls every 5s (grpc-stream.ts), so the
// resolved profile dir is cached for RESOLVE_CACHE_TTL_MS — the
// logged-in user essentially never changes within that window, and a
// wrong cached value only costs one missed poll tick, not a lost
// request (the cache expires and the next tick re-resolves either way).

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { parseConsoleUser, resolveHomeDirectory } from "../plugins/amp/providers/geo";
import { getInteractiveUserFromOs } from "../domain/device-facts-builder";

const execFileAsync = promisify(execFile);

const REQUEST_FILE_NAME = "catalog-install-request.json";

// A request older than this is leftover from before an agent restart or
// a stream reconnect gap, not something the user is actively waiting on
// right now — skip it rather than surprise-install something minutes
// after the click.
const MAX_REQUEST_AGE_MS = 2 * 60 * 1000;

const RESOLVE_CACHE_TTL_MS = 60 * 1000;
let windowsUserDirCache: { path: string | null; resolvedAtMs: number } | null = null;

export type CatalogInstallRequest = {
  packageId: string;
};

async function resolveWindowsRequestFilePath(): Promise<string | null> {
  const now = Date.now();
  if (windowsUserDirCache && now - windowsUserDirCache.resolvedAtMs < RESOLVE_CACHE_TTL_MS) {
    return windowsUserDirCache.path;
  }

  let result: string | null = null;
  try {
    const identity = await getInteractiveUserFromOs();
    if (identity?.user) {
      // Assumes the default profile location (C:\Users\<user>) — right
      // on the overwhelming majority of endpoints, same trade-off geo.ts
      // documents for macOS's hardcoded /Users/<name> fallback. A
      // registry ProfileList lookup would handle redirected/roaming
      // profiles too, but isn't worth the extra process spawn for a
      // 5s-polled path.
      const systemDrive = process.env.SystemDrive || "C:";
      result = path.join(
        systemDrive + "\\",
        "Users",
        identity.user,
        "AppData",
        "Local",
        "Tracenium",
        REQUEST_FILE_NAME
      );
    }
  } catch {
    result = null;
  }

  windowsUserDirCache = { path: result, resolvedAtMs: now };
  return result;
}

async function resolveRequestFilePath(): Promise<string | null> {
  if (process.platform === "win32") {
    return resolveWindowsRequestFilePath();
  }

  if (process.platform !== "darwin") return null;
  try {
    const { stdout } = await execFileAsync("/usr/bin/stat", ["-f%Su", "/dev/console"], {
      timeout: 5_000
    });
    const user = parseConsoleUser(stdout);
    if (!user) return null;
    const home = await resolveHomeDirectory(user);
    return path.join(home, "Library/Application Support/Tracenium", REQUEST_FILE_NAME);
  } catch {
    return null;
  }
}

/**
 * Looks for a pending self-install request left by the tray app.
 * Consumes it immediately on read (deletes the file) so a slow poll
 * tick or a stream restart mid-flight can never dispatch the same
 * click twice — the tray's Install button is the only writer, and it
 * writes fresh on every click.
 */
export async function consumePendingCatalogInstallRequest(): Promise<CatalogInstallRequest | null> {
  const filePath = await resolveRequestFilePath();
  if (!filePath) return null;

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return null; // nothing waiting — the overwhelmingly common case
  }

  // Consume-once: delete before we even finish validating, so a
  // malformed file doesn't get re-read (and re-fail) forever.
  try {
    fs.unlinkSync(filePath);
  } catch {
    // Best-effort — a failed delete just means the next tick may see it
    // again; the staleness check below still gates a runaway retry.
  }

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  const packageId = typeof parsed?.packageId === "string" ? parsed.packageId.trim() : "";
  if (!packageId) return null;

  const requestedAtMs = Date.parse(String(parsed?.requestedAtUtc || ""));
  if (!Number.isFinite(requestedAtMs) || Date.now() - requestedAtMs > MAX_REQUEST_AGE_MS) {
    return null;
  }

  return { packageId };
}
