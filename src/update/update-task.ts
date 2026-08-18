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
  | { status: "started"; version: string }
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
     * Ordered download sources (dp → cdn → origin) from the job payload, when
     * the control plane knows this device sits behind a distribution point.
     * Passed straight through to the per-OS updater, which tries them via
     * privsvc before any direct download. Absent → today's behaviour.
     */
    sources?: Array<{ tier: string; url: string }>;
  }
): Promise<UpdateOutcome> {
  const logger = opts?.logger;
  const force = opts?.force === true;
  const targetVersion = opts?.targetVersion ? String(opts.targetVersion).trim() : undefined;
  const downloadUrlOverride = opts?.downloadUrl ? String(opts.downloadUrl).trim() : undefined;
  // Ordered sources ride along untouched; the per-OS updater decides whether
  // the DP tier is usable and falls through to the direct download if not.
  const sources = Array.isArray(opts?.sources) ? opts!.sources : undefined;
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

  if (!force && !shouldCheckNow(intervalMs)) {
    return { status: "skipped", reason: "check_interval_not_elapsed" };
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
      lastAttemptedVersion: targetVersion,
      lastAttemptedAtUtc: new Date().toISOString()
    });

    const run = isMacos
      ? await performMacosPkgUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride, sources)
      : isWindows
        ? await performWindowsMsiUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride, sources)
        : await performLinuxUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride, sources);

    logger?.warn?.("[update] update started (payload override)", {
      targetVersion,
      format: isMacos ? "pkg" : isWindows ? "msi" : "deb-or-rpm",
      command: run.command,
      args: run.args
    });
    return { status: "started", version: targetVersion };
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

    function resolveArch(): "x64" | "arm64" {
      const envArch = process.env.TRACENIUM_ARCH;
      if (envArch === "arm64" || envArch === "x64") {
        return envArch;
      }

      if (process.platform === "win32") {
        const arch = process.env.PROCESSOR_ARCHITECTURE;
        const wow64 = process.env.PROCESSOR_ARCHITEW6432;

        if (arch === "ARM64" || wow64 === "ARM64") {
          return "arm64";
        }
      }

      return process.arch === "arm64" ? "arm64" : "x64";
    }

    const arch = resolveArch();
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
      lastAttemptedVersion: effectiveVersion,
      lastAttemptedAtUtc: new Date().toISOString()
    });

    const run = isMacos
      ? await performMacosPkgUpdate(ctx, effectiveVersion, expectedHash, undefined, sources)
      : isWindows
        ? await performWindowsMsiUpdate(ctx, effectiveVersion, expectedHash, undefined, sources)
        : await performLinuxUpdate(ctx, effectiveVersion, expectedHash, undefined, sources);

    logger?.warn?.("[update] update started", {
      latestVersion: effectiveVersion,
      format: isMacos ? "pkg" : isWindows ? "msi" : "deb-or-rpm",
      command: run.command,
      args: run.args
    });
    return { status: "started", version: effectiveVersion };

  } catch (err: any) {
    const error = err?.message || String(err);
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
