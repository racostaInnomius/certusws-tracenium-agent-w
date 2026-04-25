import fs from "fs";
import path from "path";
import type { PmpNamespace, PmpRemediationStatus } from "../../domain/pmp-types";

export interface PmpRemediationState {
  status?: PmpRemediationStatus;
  mode?: "download" | "install";
  startedAtUtc?: string;
  finishedAtUtc?: string;
  rebootRequired?: boolean;
  installedCount?: number;
  failedCount?: number;
  selectedCount?: number;
  lastError?: string;
  results?: NonNullable<PmpNamespace["remediation"]>["results"];
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
  return path.join(dir, "pmp-state.json");
}

export function loadPmpState(): PmpRemediationState {
  const file = getStatePath();

  if (!fs.existsSync(file)) {
    return {};
  }

  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as PmpRemediationState;
  } catch (err) {
    console.error("[pmp-state] corrupted state file", err);
    return {};
  }
}

export function savePmpState(next: PmpRemediationState) {
  const file = getStatePath();
  const tmp = `${file}.tmp`;

  fs.writeFileSync(tmp, JSON.stringify(next, null, 2), "utf8");
  fs.renameSync(tmp, file);
}

export function updatePmpState(patch: Partial<PmpRemediationState>) {
  const current = loadPmpState();
  const next: PmpRemediationState = {
    ...current,
    ...patch
  };

  if (patch.status === "in_progress") {
    next.finishedAtUtc = undefined;
    next.lastError = undefined;
  }

  if (patch.lastError) {
    next.status = "failed";
  }

  savePmpState(next);
  return next;
}
