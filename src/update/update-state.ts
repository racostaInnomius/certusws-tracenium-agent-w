// src/update/update-state.ts

import fs from "fs";
import path from "path";

export interface UpdateState {
  lastCheckedAtUtc?: string;
  lastAttemptedVersion?: string;
  lastAttemptedAtUtc?: string;
  lastCompletedAtUtc?: string;
  lastSuccessVersion?: string;
  lastDownloadedPath?: string;
  lastDownloadedSha256?: string;
  updateInProgress?: boolean;
  status?: "idle" | "in_progress" | "success" | "failed";
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
  if (patch.updateInProgress === true) {
    next.status = "in_progress";
  }

  if (patch.updateInProgress === false && !patch.lastError) {
    next.status = "success";
    next.lastCompletedAtUtc = new Date().toISOString();
    if (patch.lastAttemptedVersion) {
      next.lastSuccessVersion = patch.lastAttemptedVersion;
    }
  }

  if (patch.lastError) {
    next.status = "failed";
    next.lastCompletedAtUtc = new Date().toISOString();
  }

  saveUpdateState(next);
  return next;
}

export function clearUpdateInProgress() {
  updateUpdateState({
    updateInProgress: false,
    lastCompletedAtUtc: new Date().toISOString()
  });
}