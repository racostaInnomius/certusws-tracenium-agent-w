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
  // Override for tests and ad-hoc runs; production always uses the
  // platform data dir above.
  const dir = process.env.TRACENIUM_STATE_DIR || path.join(resolveBaseDir(), "state");
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

/** Marker in `lastError` for an install the agent could not see finish. */
export const AGENT_RESTARTED_ERROR = "agent_restarted";

/**
 * Called once at boot, before any collector reads the state and before a
 * job can start. An `in_progress` install found here cannot be in
 * progress in THIS process: the promise that was awaiting `patch.install`
 * died with the previous one. Whatever the privsvc did with it is unknown
 * to us — it may still be running, it may have finished into a pipe nobody
 * read — and the next patch scan will report the real on-disk state.
 *
 * Until 2026-09-04 nothing cleared this. Msig13 (tenant 111) lost its
 * AgentCore mid-install three times that day and every FACTS snapshot in
 * between (14:29, 14:36, 16:09) still said `installing`: the portal showed
 * a spinner for a process that had been dead for hours. Same shape as
 * `stale_update_in_progress` in update-task.ts.
 *
 * Returns what was found so the caller can log it, or null when there was
 * nothing to do.
 */
export function reconcileStalePmpState(): Pick<PmpRemediationState, "mode" | "startedAtUtc"> | null {
  const current = loadPmpState();
  if (current.status !== "in_progress") return null;

  updatePmpState({
    status: "failed",
    finishedAtUtc: new Date().toISOString(),
    lastError: AGENT_RESTARTED_ERROR
  });

  return { mode: current.mode, startedAtUtc: current.startedAtUtc };
}

// ── PMv2 — security-config remediation lock (in-memory) ──────────
//
// In Phase 1 the patch_install path uses an ad-hoc flag on `ctx`
// (`_patchInstallInProgress`) for concurrency. v2 adds a second
// system-changing path (patch_remediate) and they MUST be mutually
// exclusive: a registry edit interleaved with a Windows Update
// install is a recipe for half-applied state.
//
// We add the new lock here as a module-level boolean and export
// helpers. The pre-existing `_patchInstallInProgress` flag stays
// untouched in grpc-stream.ts; the patch_remediate path checks
// BOTH (the install flag via `ctx`, plus this remediate flag), and
// the patch_install case is amended in PMv2-F to also reject when
// remediate is in flight.
//
// Why module-level instead of persisted to disk like updatePmpState
// above: idempotency for remediations comes from the pre/post
// state-read pair, not from a sticky lock that survives crashes.
// If the agent restarts mid-remediate, the next attempt's
// pre-read will see the actual on-disk state (already-compliant or
// not) and ack accordingly. An on-disk lock would just risk getting
// stuck.

let remediateInFlight = false;

/**
 * Attempt to acquire the remediation lock. Returns false when
 * either a prior remediation is still running OR the caller's ctx
 * indicates a patch_install is in flight.
 *
 * Pass the ctx so we can check the existing install flag without
 * a circular import of grpc-stream's internal state.
 */
export function tryStartRemediate(ctx: any): boolean {
  if (remediateInFlight) return false;
  if (ctx && (ctx as any)._patchInstallInProgress === true) return false;
  remediateInFlight = true;
  return true;
}

export function finishRemediate(): void {
  remediateInFlight = false;
}

export function isRemediateInFlight(): boolean {
  return remediateInFlight;
}
