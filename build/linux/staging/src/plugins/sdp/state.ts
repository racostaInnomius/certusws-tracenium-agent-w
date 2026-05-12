// src/plugins/sdp/state.ts
//
// SDP — Phase 1. In-memory concurrency lock for software installs.
//
// Why module-level + in-memory (not on-disk like PMP):
//   * Idempotency is guaranteed by the detection rule. If the agent
//     crashes mid-install and the next runJob arrives post-restart,
//     pre-install detection will see "already installed" and short-
//     circuit. No need to persist "I was installing X" across runs.
//   * The orchestrator's timeout/retry engine handles the case where
//     the agent crashed and never ACKed — the job goes timed_out
//     server-side and the retry policy decides whether to refire.
//   * Persisted state would create a worse failure mode: the file
//     would lock the agent into "in_progress" forever if the lock-
//     release write fails post-install.
//
// What IS in scope here:
//   * Single in-flight install per device (the only OS-level
//     constraint — msiexec / installer don't tolerate concurrency).
//   * A small "last install" snapshot for diagnostics, kept only in
//     memory; if you grep agent logs you'll see the same info anyway.

export type LastInstallSnapshot = {
  packageId: number;
  packageName: string;
  packageVersion: string;
  startedAtMs: number;
  finishedAtMs?: number;
  outcome?: string;
  exitCode?: number;
};

let installInProgress = false;
let lastInstall: LastInstallSnapshot | null = null;

/**
 * Try to acquire the install lock. Returns false if another install
 * is already running — the caller should ACK the runJob with status
 * 1 (transient retry) so the orchestrator re-fires later.
 */
export function tryStartInstall(snapshot: Omit<LastInstallSnapshot, "startedAtMs">): boolean {
  if (installInProgress) return false;
  installInProgress = true;
  lastInstall = { ...snapshot, startedAtMs: Date.now() };
  return true;
}

/**
 * Release the lock and stamp the outcome on the in-memory record.
 * Always called from a `finally` block so a thrown exception still
 * unlocks.
 */
export function finishInstall(outcome: string, exitCode?: number): void {
  installInProgress = false;
  if (lastInstall) {
    lastInstall.finishedAtMs = Date.now();
    lastInstall.outcome = outcome;
    if (exitCode !== undefined) lastInstall.exitCode = exitCode;
  }
}

export function isInstallInProgress(): boolean {
  return installInProgress;
}

export function getLastInstall(): LastInstallSnapshot | null {
  return lastInstall;
}
