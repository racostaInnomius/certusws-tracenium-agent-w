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
  performWindowsMsiUpdate
} from "./update-service";

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

function compareSemver(a: string, b: string): number {
  const parse = (v: string): number[] =>
    v.split(".").map((x) => {
      const n = Number(x);
      return Number.isFinite(n) ? n : 0;
    });

  const av = parse(a);
  const bv = parse(b);
  const len = Math.max(av.length, bv.length);

  for (let i = 0; i < len; i += 1) {
    const ai = av[i] ?? 0;
    const bi = bv[i] ?? 0;

    if (ai !== bi) {
      return ai > bi ? 1 : -1;
    }
  }

  return 0;
}

function looksLikeSemver(v: string): boolean {
  return /^\d+\.\d+\.\d+([.-][A-Za-z0-9]+)?$/.test(v);
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
  }
) {
  const logger = opts?.logger;
  const force = opts?.force === true;
  const targetVersion = opts?.targetVersion ? String(opts.targetVersion).trim() : undefined;
  const intervalMs = opts?.intervalMs ?? 6 * 60 * 60 * 1000;

  const isWindows = ctx.agent?.platform === "windows" || process.platform === "win32";
  const isMacos = ctx.agent?.platform === "macos" || process.platform === "darwin";

  if (!isWindows && !isMacos) {
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
    const fileMeta = isMacos
      ? result.metadata?.files?.pkg?.[arch]
      : result.metadata?.files?.msi?.[arch];

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
      : await performWindowsMsiUpdate(ctx, effectiveVersion, expectedHash);

    logger?.warn?.("[update] update started", {
      latestVersion: effectiveVersion,
      format: isMacos ? "pkg" : "msi",
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
