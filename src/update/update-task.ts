// src/update/update-task.ts

import type { AgentContext } from "../core/agent-context";
import { loadUpdateState, updateUpdateState } from "./update-state";
import {
  fetchAgentMetadata,
  checkForAvailableUpdate,
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

  if (ctx.agent?.platform !== "windows" && process.platform !== "win32") {
    logger?.info?.("[update] skipping auto-update: only windows supported currently");
    return;
  }

  const state = loadUpdateState();

  if (state.updateInProgress) {
    const lastAttempt = parseUtcMs(state.lastAttemptedAtUtc);
    if (nowMs() - lastAttempt < 10 * 60 * 1000) {
      logger?.warn?.("[update] update already in progress, skipping");
      return;
    }

    logger?.warn?.("[update] stale updateInProgress detected, recovering");
    updateUpdateState({ updateInProgress: false });
  }

  if (!force && !shouldCheckNow(intervalMs)) {
    return;
  }

  const currentVersion = String(ctx.agent?.version || "").trim();
  logger?.info?.("[update] current agent version", { currentVersion });
  if (
    !currentVersion ||
    currentVersion === "undefined" ||
    currentVersion === "null" ||
    !/^\d+\.\d+\.\d+/.test(currentVersion)
  ) {
    logger?.warn?.("[update] missing current agentVersion");
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

    // idempotency guard: skip ONLY if we already attempted the CURRENT LATEST version
    if (
      state.lastAttemptedVersion &&
      latestVersion &&
      state.lastAttemptedVersion === latestVersion
    ) {
      logger?.info?.("[update] already attempted latest version, skipping", {
        currentVersion,
        latestVersion,
        lastAttemptedVersion: state.lastAttemptedVersion
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
    const fileMeta = result.metadata?.files?.msi?.[arch];

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

    const run = await performWindowsMsiUpdate(
      ctx,
      effectiveVersion,
      expectedHash
    );

    logger?.warn?.("[update] msi update started", {
      latestVersion: effectiveVersion,
      command: run.command,
      args: run.args
    });

  } catch (err: any) {
    updateUpdateState({
      updateInProgress: false,
      lastError: err?.message || String(err)
    });

    logger?.error?.("[update] update task failed", {
      error: err?.message || String(err),
      stack: err?.stack
    });
  }
}