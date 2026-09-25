// src/update/update-task.ts

import type { AgentContext } from "../core/agent-context";
import {
  loadUpdateState,
  markUpdateFailed,
  markUpdateSucceeded,
  updateUpdateState
} from "./update-state";
import {
  fetchAgentMetadata,
  checkForAvailableUpdate,
  performMacosPkgUpdate,
  performWindowsMsiUpdate,
  performLinuxUpdate
} from "./update-service";
import { compareSemver, looksLikeSemver } from "./semver";
import { describeError } from "./describe-error";
import { resolveOsArch } from "../domain/os-arch";
import { isRemediateInFlight } from "../plugins/pmp/state";
import { isInstallInProgress as isSoftwareInstallInProgress } from "../plugins/sdp/state";
import { aspRunInFlight } from "../plugins/asp/runner";
import {
  batteryBlocksUpdate,
  readBatteryForUpdate,
  UPDATE_BATTERY_DEFERRED_PREFIX
} from "./battery-gate";

/** Prefix of the `skipped` reason when the update yielded to a privileged operation. */
export const UPDATE_DEFERRED_PREFIX = "privileged_operation_in_progress:";

/** Skips that mean "not now, send it again", as opposed to "nothing to do". */
const RETRY_LATER_PREFIXES = [UPDATE_DEFERRED_PREFIX, UPDATE_BATTERY_DEFERRED_PREFIX];

/**
 * Which privileged operation, if any, the privsvc is running for this
 * process right now. Each is a long call whose result would be lost if the
 * installer restarted the privsvc underneath it.
 */
export function privilegedOperationInFlight(
  ctx: Pick<AgentContext, never> & { _patchInstallInProgress?: boolean }
): "patch_install" | "patch_remediate" | "software_install" | "asp_assess" | null {
  if ((ctx as any)?._patchInstallInProgress === true) return "patch_install";
  if (isRemediateInFlight()) return "patch_remediate";
  if (isSoftwareInstallInProgress()) return "software_install";
  // ADR-0022: la corrida vive en el PrivSvc; un MSI que lo reinicia la mata a
  // mitad y el backend la cerraría `incomplete` sin motivo visible.
  if (aspRunInFlight()) return "asp_assess";
  return null;
}

/**
 * The control ACK for an update outcome, shared by the runJob and the push
 * paths so they cannot drift. `status` follows the ack contract: 0 done,
 * 1 retry later (the backend re-dispatches with backoff), 2 failed.
 *
 * A deferred update (privileged operation in flight, battery too low) is the
 * `skipped` that must NOT close the job: the version was never installed, and
 * acking 0 would have the backend record the update as done on a host still
 * running the old build.
 */
export function ackForUpdateOutcome(outcome: UpdateOutcome): { status: 0 | 1 | 2; message: string } {
  if (outcome.status === "failed") {
    return { status: 2, message: `update_failed: ${outcome.error}` };
  }
  if (outcome.status === "skipped") {
    if (RETRY_LATER_PREFIXES.some((p) => outcome.reason.startsWith(p))) {
      return { status: 1, message: `agent_update retry: ${outcome.reason}` };
    }
    return { status: 0, message: `update_skipped: ${outcome.reason}` };
  }
  // `src=` names the tier that served the installer, mirroring what an
  // SDP install already reports. Without it the control plane cannot tell
  // a LAN download from a WAN one, which is the whole KPI of putting
  // distribution points on the update path.
  return { status: 0, message: `update_started;src=${outcome.servedBy || "origin"}` };
}

/**
 * Which tier served the installer for the attempt that just ran.
 *
 * Read from the update state because the per-OS updaters return different
 * shapes, while the state is already the channel that carries the hand-off
 * between download and install. Absent means no distribution point served it —
 * reported as "origin" rather than left blank, so a fleet-wide "how much came
 * over the LAN?" is answerable without treating silence as a third category.
 */
function servedTier(): string {
  try {
    return loadUpdateState().lastServedBy || "origin";
  } catch {
    return "origin";
  }
}

/**
 * The installer was not launched (today: Windows, schtasks refused the task).
 *
 * The per-OS updater already returned `started: false` with the reason, and
 * this used to ack `update_started` anyway — the same silence that kept
 * W11_JPR_LAB on 1.1.77, one layer up. Moving the task to XML makes a
 * rejected definition possible, so the refusal has to reach the job.
 */
function installerNotLaunched(
  run: { started?: boolean; error?: string },
  logger?: { error?: (...args: any[]) => void }
): UpdateOutcome | null {
  if (run?.started !== false) return null;
  const error = run.error || "installer_not_launched";
  markUpdateFailed(error);
  logger?.error?.("[update] installer was not launched", { error });
  return { status: "failed", error };
}

function nowMs() {
  return Date.now();
}

function parseUtcMs(value?: string): number {
  if (!value) return 0;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : 0;
}

function shouldCheckNow(intervalMs: number): boolean {
  const state = loadUpdateState();
  const last = parseUtcMs(state.lastCheckedAtUtc);

  if (!last) return true;
  return nowMs() - last >= intervalMs;
}

function reconcilePendingUpdate(currentVersion: string, logger?: {
  info?: (...args: any[]) => void;
  warn?: (...args: any[]) => void;
}) {
  const state = loadUpdateState();
  const attemptedVersion = String(state.lastAttemptedVersion || "").trim();

  if (!state.updateInProgress || !attemptedVersion || !looksLikeSemver(attemptedVersion)) {
    return loadUpdateState();
  }

  if (compareSemver(currentVersion, attemptedVersion) >= 0) {
    logger?.info?.("[update] reconciling pending update as success", {
      currentVersion,
      attemptedVersion
    });
    markUpdateSucceeded(attemptedVersion);
    return loadUpdateState();
  }

  return state;
}

/**
 * What actually happened during an update attempt.
 *
 * This used to be `void`, and every failure was swallowed by the catch at the
 * bottom of runUpdateTask: the promise resolved normally, so callers that
 * ACK'd on resolution reported `update_completed` to the control plane for
 * updates that never installed anything. Operators then saw a job marked
 * completed against a host still on the old version, with the real cause
 * (e.g. `PrivSvc timeout`) visible only in the endpoint's local err.log.
 *
 * Returning an outcome instead of throwing keeps every existing caller working
 * (the scheduler ignores the value) while letting the two job-ACK paths report
 * the truth.
 *
 * `started` means the installer was LAUNCHED, not that the new version is
 * running — the process is about to be replaced. Confirmation comes later,
 * from reconcilePendingUpdate on the next boot.
 */
export type UpdateOutcome =
  | {
      status: "started";
      version: string;
      /** Source tier that served the installer: "dp" | "cdn" | "origin". */
      servedBy?: string;
    }
  | { status: "skipped"; reason: string }
  | { status: "failed"; error: string };

export async function runUpdateTask(
  ctx: AgentContext,
  opts?: {
    force?: boolean;
    intervalMs?: number;
    logger?: {
      info?: (...args: any[]) => void;
      warn?: (...args: any[]) => void;
      error?: (...args: any[]) => void;
    };
    targetVersion?: string;
    // ── Job-payload override (Phase 11) ────────────────────────────
    // When the backend dispatches an `agent_update` job with an
    // explicit `downloadUrl` + `expectedHash` in the payload, skip the
    // /metadata fetch and the latest-version comparison: trust the
    // operator that this is the version to install, and download from
    // the URL directly. Used for:
    //   - Forced downgrades (`allowDowngrade=true` semantics without
    //     touching the global metadata.allowDowngrade flag)
    //   - Hot-fix MSIs hosted on a side channel (e.g. a one-off pkg
    //     uploaded to a private blob for a single tenant)
    //   - Rescuing devices on a broken version of update-task itself
    //     that wouldn't otherwise pick up the new metadata
    // Both fields must be present together; passing only the URL
    // without a hash is rejected upstream by performXxxUpdate.
    downloadUrl?: string;
    expectedHash?: string;
    /**
     * LAN base URLs of the distribution points serving this device's site.
     * The per-OS updater composes /sdp/blob/<expectedHash> from each and tries
     * them through privsvc before any direct download. Absent → today's
     * behaviour, straight from the internet.
     */
    dpBaseUrls?: string[];
  }
): Promise<UpdateOutcome> {
  const logger = opts?.logger;
  const force = opts?.force === true;
  const targetVersion = opts?.targetVersion ? String(opts.targetVersion).trim() : undefined;
  const downloadUrlOverride = opts?.downloadUrl ? String(opts.downloadUrl).trim() : undefined;
  // DP bases ride along untouched; the per-OS updater composes the blob URLs
  // (it owns the hash) and falls through to the direct download if the LAN
  // copy is unusable.
  const dpBaseUrls = Array.isArray(opts?.dpBaseUrls) ? opts!.dpBaseUrls : undefined;
  const expectedHashOverride = opts?.expectedHash
    ? String(opts.expectedHash).trim().toLowerCase()
    : undefined;
  const intervalMs = opts?.intervalMs ?? 6 * 60 * 60 * 1000;

  const isWindows = ctx.agent?.platform === "windows" || process.platform === "win32";
  const isMacos = ctx.agent?.platform === "macos" || process.platform === "darwin";
  const isLinux = ctx.agent?.platform === "linux" || process.platform === "linux";

  if (!isWindows && !isMacos && !isLinux) {
    logger?.info?.("[update] skipping auto-update: platform not supported currently");
    return { status: "skipped", reason: "platform_not_supported" };
  }

  const currentVersion = String(ctx.agent?.version || "").trim();
  logger?.info?.("[update] current agent version", { currentVersion });
  if (
    !currentVersion ||
    currentVersion === "undefined" ||
    currentVersion === "null" ||
    !looksLikeSemver(currentVersion)
  ) {
    logger?.warn?.("[update] missing current agentVersion");
    return { status: "skipped", reason: "missing_current_version" };
  }

  const state = reconcilePendingUpdate(currentVersion, logger);
  let freshState = state;

  if (freshState.updateInProgress) {
    const lastAttempt = parseUtcMs(freshState.installStartedAtUtc || freshState.lastAttemptedAtUtc);
    if (nowMs() - lastAttempt < 10 * 60 * 1000) {
      logger?.warn?.("[update] update already in progress, skipping");
      return { status: "skipped", reason: "update_already_in_progress" };
    }

    logger?.warn?.("[update] stale updateInProgress detected, marking failed");
    markUpdateFailed("stale_update_in_progress");
    freshState = loadUpdateState();
  }

  // ── Never restart the privsvc under a privileged operation ───────
  //
  // Installing the new agent (MSI / pkg / deb) restarts BOTH services.
  // Whatever the privsvc was doing for us at that moment dies with it: a
  // Windows Update install, an SDP package install, a registry
  // remediation. Msig13 (tenant 111) on 2026-09-04 received the runJob
  // patch_install and the agentUpdate to 1.1.59 in the same reconnect
  // burst; the MSI restarted the privsvc 22 minutes into the WUA install
  // and the job was lost. Nothing here looked before pulling the trigger.
  //
  // Skip with a reason the job handlers map to ACK_RETRY, so the backend
  // re-dispatches the update with backoff once the operation is over. The
  // periodic check simply tries again on its next tick.
  const busy = privilegedOperationInFlight(ctx);
  if (busy) {
    logger?.warn?.("[update] deferring: a privileged operation is in flight", { operation: busy });
    return { status: "skipped", reason: `${UPDATE_DEFERRED_PREFIX}${busy}` };
  }

  if (!force && !shouldCheckNow(intervalMs)) {
    return { status: "skipped", reason: "check_interval_not_elapsed" };
  }

  // ── Battery: only a nearly flat one holds the update back ────────
  //
  // Running on battery is fine — see battery-gate.ts for the laptop that sat
  // on 1.1.77 because the scheduled task refused to start unplugged. Dying
  // halfway through the installer is not: the services are stopped and the
  // binaries half-replaced. Checked before the download so a flat laptop does
  // not spend what it has left on 170 MB, and acked as a retry like the
  // privileged-operation guard, so the job comes back instead of closing as
  // done.
  const lowBattery = batteryBlocksUpdate(await readBatteryForUpdate());
  if (lowBattery !== null) {
    logger?.warn?.("[update] deferring: battery too low to install", { percent: lowBattery });
    return { status: "skipped", reason: `${UPDATE_BATTERY_DEFERRED_PREFIX}${lowBattery}%` };
  }

  // ── Fast-path: job payload override ───────────────────────────────
  //
  // If the backend job carried an explicit downloadUrl + expectedHash,
  // bypass the entire metadata-resolution pipeline and go straight to
  // the installer. We MUST have targetVersion too — the install logic
  // needs to know what version to attempt (logged + persisted into
  // update state so the post-restart HELLO can reconcile).
  if (downloadUrlOverride && expectedHashOverride && targetVersion) {
    logger?.info?.("[update] using job-payload download override", {
      currentVersion,
      targetVersion,
      downloadUrl: downloadUrlOverride
    });

    updateUpdateState({
      updateInProgress: true,
      // Clear the previous run's tier: reporting a stale one would claim the DP
      // served an update it never touched.
      lastServedBy: null,
      lastAttemptedVersion: targetVersion,
      lastAttemptedAtUtc: new Date().toISOString()
    });

    const run = isMacos
      ? await performMacosPkgUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride, dpBaseUrls)
      : isWindows
        ? await performWindowsMsiUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride, dpBaseUrls)
        : await performLinuxUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride, dpBaseUrls);

    const notLaunched = installerNotLaunched(run, logger);
    if (notLaunched) return notLaunched;

    logger?.warn?.("[update] update started (payload override)", {
      targetVersion,
      format: isMacos ? "pkg" : isWindows ? "msi" : "deb-or-rpm",
      command: run.command,
      args: run.args
    });
    return { status: "started", version: targetVersion, servedBy: servedTier() };
  }

  // If only PART of the override pair was supplied, that's a backend
  // bug — we refuse rather than silently degrading into a metadata
  // lookup the operator didn't ask for.
  if ((downloadUrlOverride && !expectedHashOverride) || (!downloadUrlOverride && expectedHashOverride)) {
    logger?.error?.("[update] job-payload override incomplete; need BOTH downloadUrl + expectedHash", {
      hasUrl: !!downloadUrlOverride,
      hasHash: !!expectedHashOverride
    });
    return { status: "failed", error: "job_payload_override_incomplete" };
  }

  try {
    logger?.info?.("[update] starting metadata fetch", {
      currentVersion,
      platform: ctx.agent?.platform || process.platform,
      force
    });
    const metadata = await fetchAgentMetadata(ctx);
    //logger?.info?.("[update] metadata raw", metadata);
    const result = checkForAvailableUpdate(currentVersion, metadata);
    const effectiveVersion = targetVersion || result.latestVersion;

    const latestVersion = result.latestVersion;

    // reload state dynamically before idempotency check to avoid stale decisions
    freshState = loadUpdateState();
    // idempotency guard: skip ONLY if we already attempted AND completed CURRENT LATEST version
    if (
      freshState.lastAttemptedVersion &&
      latestVersion &&
      freshState.lastAttemptedVersion === latestVersion &&
      freshState.lastSuccessVersion === latestVersion
    ) {
      logger?.info?.("[update] already attempted AND completed latest version, skipping", {
        currentVersion,
        latestVersion,
        lastAttemptedVersion: freshState.lastAttemptedVersion,
        lastSuccessVersion: freshState.lastSuccessVersion
      });
      return { status: "skipped", reason: "latest_already_installed" };
    }

    logger?.info?.("[update] metadata evaluated" )
    //{
      //currentVersion,
      //latestVersion: result.latestVersion,
      //available: result.available,
      //reason: result.reason
    //});

    if (!result.available) {
      logger?.info?.("[update] no update available", {
        currentVersion,
        latestVersion: result.latestVersion,
        reason: result.reason
      });
      return { status: "skipped", reason: result.reason || "no_update_available" };
    }

    // Era una copia literal del getArch() de update-service.ts. Las dos —y las
    // otras dos que miraban `os.arch()` y se equivocaban— viven ahora en
    // domain/os-arch.ts.
    const arch = resolveOsArch();
    // Linux: pick deb (debian-family) or rpm (rhel/suse). The
    // detection happens inside update-service's downloadLinuxPkg /
    // performLinuxUpdate via detectFamily(); here we just pick the
    // metadata key. We try `deb` first when a runtime probe of
    // /etc/os-release is too heavy for this hot path — the backend's
    // metadata endpoint is allowed to return a 404 / missing key,
    // which we surface as "no compatible binary" below.
    let fileMeta: any;
    if (isMacos) {
      fileMeta = result.metadata?.files?.pkg?.[arch];
    } else if (isWindows) {
      fileMeta = result.metadata?.files?.msi?.[arch];
    } else {
      // Linux: use the lazy-cached detectFamily() to select format.
      // Imported inline to avoid pulling the platform module into the
      // Windows/Mac compile units (it's a single sync read of
      // /etc/os-release; the cache means subsequent calls are free).
      const { detectFamily } = require("../platform/linux/distro");
      const family = detectFamily().family;
      const linuxKey = family === "debian" ? "deb" : "rpm";
      fileMeta = result.metadata?.files?.[linuxKey]?.[arch];
    }

    if (!fileMeta) {
      logger?.warn?.("[update] no compatible binary for this arch", { arch });
      return { status: "failed", error: `no_compatible_binary_for_${arch}` };
    }

    const expectedHash = fileMeta.hash;

    if (!expectedHash) {
      logger?.warn?.("[update] missing expected hash, skipping update");
      return { status: "failed", error: "missing_expected_hash" };
    }

    updateUpdateState({
      updateInProgress: true,
      // Clear the previous run's tier: reporting a stale one would claim the DP
      // served an update it never touched.
      lastServedBy: null,
      lastAttemptedVersion: effectiveVersion,
      lastAttemptedAtUtc: new Date().toISOString()
    });

    const run = isMacos
      ? await performMacosPkgUpdate(ctx, effectiveVersion, expectedHash, undefined, dpBaseUrls)
      : isWindows
        ? await performWindowsMsiUpdate(ctx, effectiveVersion, expectedHash, undefined, dpBaseUrls)
        : await performLinuxUpdate(ctx, effectiveVersion, expectedHash, undefined, dpBaseUrls);

    const notLaunched = installerNotLaunched(run, logger);
    if (notLaunched) return notLaunched;

    logger?.warn?.("[update] update started", {
      latestVersion: effectiveVersion,
      format: isMacos ? "pkg" : isWindows ? "msi" : "deb-or-rpm",
      command: run.command,
      args: run.args
    });
    return { status: "started", version: effectiveVersion, servedBy: servedTier() };

  } catch (err: any) {
    // ⚠️ NOT `err?.message || String(err)`. This string becomes the ACK the
    // control plane stores in `device_jobs.last_error`, and an AggregateError
    // — what Node throws when every candidate address of a host refuses the
    // connection — has an EMPTY message, so that idiom reported the literal
    // word "AggregateError" and discarded `err.errors[]`. Nine failures in
    // tenant 111 looked like a new fault and were the same TCP timeout to
    // Azure Blob we had already seen eighteen times with a single address.
    const error = describeError(err);
    markUpdateFailed(error);

    logger?.error?.("[update] update task failed", {
      error,
      stack: err?.stack
    });
    // Report the failure instead of resolving silently. Callers that ACK a
    // job decide what to send back; swallowing this is what made the control
    // plane believe failed updates had completed.
    return { status: "failed", error };
  }
}
