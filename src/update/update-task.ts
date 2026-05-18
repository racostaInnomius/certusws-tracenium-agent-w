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
  }
) {
  const logger = opts?.logger;
  const force = opts?.force === true;
  const targetVersion = opts?.targetVersion ? String(opts.targetVersion).trim() : undefined;
  const downloadUrlOverride = opts?.downloadUrl ? String(opts.downloadUrl).trim() : undefined;
  const expectedHashOverride = opts?.expectedHash
    ? String(opts.expectedHash).trim().toLowerCase()
    : undefined;
  const intervalMs = opts?.intervalMs ?? 6 * 60 * 60 * 1000;

  const isWindows = ctx.agent?.platform === "windows" || process.platform === "win32";
  const isMacos = ctx.agent?.platform === "macos" || process.platform === "darwin";
  const isLinux = ctx.agent?.platform === "linux" || process.platform === "linux";

  if (!isWindows && !isMacos && !isLinux) {
    logger?.info?.("[update] skipping auto-update: platform not supported currently");
    return;
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
    return;
  }

  const state = reconcilePendingUpdate(currentVersion, logger);
  let freshState = state;

  if (freshState.updateInProgress) {
    const lastAttempt = parseUtcMs(freshState.installStartedAtUtc || freshState.lastAttemptedAtUtc);
    if (nowMs() - lastAttempt < 10 * 60 * 1000) {
      logger?.warn?.("[update] update already in progress, skipping");
      return;
    }

    logger?.warn?.("[update] stale updateInProgress detected, marking failed");
    markUpdateFailed("stale_update_in_progress");
    freshState = loadUpdateState();
  }

  if (!force && !shouldCheckNow(intervalMs)) {
    return;
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
      ? await performMacosPkgUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride)
      : isWindows
        ? await performWindowsMsiUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride)
        : await performLinuxUpdate(ctx, targetVersion, expectedHashOverride, downloadUrlOverride);

    logger?.warn?.("[update] update started (payload override)", {
      targetVersion,
      format: isMacos ? "pkg" : isWindows ? "msi" : "deb-or-rpm",
      command: run.command,
      args: run.args
    });
    return;
  }

  // If only PART of the override pair was supplied, that's a backend
  // bug — we refuse rather than silently degrading into a metadata
  // lookup the operator didn't ask for.
  if ((downloadUrlOverride && !expectedHashOverride) || (!downloadUrlOverride && expectedHashOverride)) {
    logger?.error?.("[update] job-payload override incomplete; need BOTH downloadUrl + expectedHash", {
      hasUrl: !!downloadUrlOverride,
      hasHash: !!expectedHashOverride
    });
    return;
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
      return;
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
      return;
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
      return;
    }

    const expectedHash = fileMeta.hash;

    if (!expectedHash) {
      logger?.warn?.("[update] missing expected hash, skipping update");
      return;
    }

    updateUpdateState({
      updateInProgress: true,
      lastAttemptedVersion: effectiveVersion,
      lastAttemptedAtUtc: new Date().toISOString()
    });

    const run = isMacos
      ? await performMacosPkgUpdate(ctx, effectiveVersion, expectedHash)
      : isWindows
        ? await performWindowsMsiUpdate(ctx, effectiveVersion, expectedHash)
        : await performLinuxUpdate(ctx, effectiveVersion, expectedHash);

    logger?.warn?.("[update] update started", {
      latestVersion: effectiveVersion,
      format: isMacos ? "pkg" : isWindows ? "msi" : "deb-or-rpm",
      command: run.command,
      args: run.args
    });

  } catch (err: any) {
    markUpdateFailed(err?.message || String(err));

    logger?.error?.("[update] update task failed", {
      error: err?.message || String(err),
      stack: err?.stack
    });
  }
}
