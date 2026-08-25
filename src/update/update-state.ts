// src/update/update-state.ts

import fs from "fs";
import path from "path";

export interface UpdateState {
  lastCheckedAtUtc?: string;
  lastAttemptedVersion?: string;
  lastAttemptedAtUtc?: string;
  installStartedAtUtc?: string;
  lastCompletedAtUtc?: string;
  lastSuccessVersion?: string;
  lastDownloadedPath?: string;
  lastDownloadedSha256?: string;
  /**
   * Which source tier served the installer for the run in progress: "dp" when a
   * distribution point did, "origin"/"cdn" otherwise.
   *
   * Rides the update state rather than the per-OS return values because those
   * differ by platform, while this hand-off between download and ACK is exactly
   * what the state already carries (see lastDownloadedPath/Sha256). Cleared at
   * the start of every attempt so a previous run's tier can never be reported
   * as this one's.
   */
  lastServedBy?: string | null;
  updateInProgress?: boolean;
  status?: "idle" | "in_progress" | "install_started" | "success" | "failed";
  lastError?: string;
  arch?: "x64" | "arm64";
}

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

function resolveBaseDir() {
  if (process.platform === "win32") {
    return path.join(process.env.ProgramData || "C:\\ProgramData", "Tracenium");
  }

  if (process.platform === "darwin") {
    return "/Library/Application Support/Tracenium";
  }

  return "/var/lib/tracenium";
}

function getStatePath() {
  const dir = path.join(resolveBaseDir(), "state");
  ensureDir(dir);
  return path.join(dir, "update-state.json");
}

export function loadUpdateState(): UpdateState {
  const file = getStatePath();

  if (!fs.existsSync(file)) {
    return {};
  }

  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as UpdateState;
  } catch (err) {
    console.error("[update-state] corrupted state file", err);
    return {};
  }
}

export function saveUpdateState(next: UpdateState) {
  const file = getStatePath();
  const tmp = `${file}.tmp`;

  fs.writeFileSync(tmp, JSON.stringify(next, null, 2), "utf8");
  fs.renameSync(tmp, file);
}

export function updateUpdateState(patch: Partial<UpdateState>) {
  const current = loadUpdateState();

  const next: UpdateState = {
    ...current,
    ...patch
  };

  // derive status automatically if not explicitly provided
  if (patch.status) {
    next.status = patch.status;
  } else if (patch.installStartedAtUtc) {
    next.status = "install_started";
  } else if (patch.updateInProgress === true) {
    next.status = "in_progress";
  }

  if (patch.lastError) {
    next.status = "failed";
    next.lastCompletedAtUtc = new Date().toISOString();
    next.updateInProgress = false;
  }

  // ensure failed attempts do not block future updates
  if (patch.lastError) {
    next.installStartedAtUtc = undefined;
  }

  saveUpdateState(next);
  return next;
}

export function markUpdateSucceeded(version: string) {
  const now = new Date().toISOString();

  return updateUpdateState({
    updateInProgress: false,
    status: "success",
    lastCompletedAtUtc: now,
    lastSuccessVersion: version,
    lastError: undefined,
    installStartedAtUtc: undefined
  });
}

export function markUpdateFailed(error: string) {
  return updateUpdateState({
    updateInProgress: false,
    status: "failed",
    lastError: error,
    installStartedAtUtc: undefined
  });
}

export function clearUpdateInProgress() {
  updateUpdateState({
    updateInProgress: false,
    installStartedAtUtc: undefined,
    lastCompletedAtUtc: new Date().toISOString()
  });
}
