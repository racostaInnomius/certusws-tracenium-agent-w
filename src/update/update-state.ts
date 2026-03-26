// src/update/update-state.ts

import fs from "fs";
import path from "path";

export interface UpdateState {
  lastCheckedAtUtc?: string;
  lastAttemptedVersion?: string;
  lastAttemptedAtUtc?: string;
  lastDownloadedPath?: string;
  lastDownloadedSha256?: string;
  updateInProgress?: boolean;
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
  } catch {
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
  const next = { ...current, ...patch };
  saveUpdateState(next);
  return next;
}

export function clearUpdateInProgress() {
  updateUpdateState({
    updateInProgress: false
  });
}