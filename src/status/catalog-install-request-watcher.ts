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
// (see that pair for the precedent this borrows from): a signed .app in
// the console user's session writes where this root LaunchDaemon can't
// reach directly, and the daemon polls for it. macOS only for now — the
// Software Catalog tab doesn't exist on the Windows/Linux tray yet.

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { parseConsoleUser, resolveHomeDirectory } from "../plugins/amp/providers/geo";

const execFileAsync = promisify(execFile);

const REQUEST_FILE_NAME = "catalog-install-request.json";

// A request older than this is leftover from before an agent restart or
// a stream reconnect gap, not something the user is actively waiting on
// right now — skip it rather than surprise-install something minutes
// after the click.
const MAX_REQUEST_AGE_MS = 2 * 60 * 1000;

export type CatalogInstallRequest = {
  packageId: string;
};

async function resolveRequestFilePath(): Promise<string | null> {
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
