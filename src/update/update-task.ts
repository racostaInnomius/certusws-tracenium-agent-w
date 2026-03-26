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
  }
) {
  const logger = opts?.logger;
  const force = opts?.force === true;
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
  }

  if (!force && !shouldCheckNow(intervalMs)) {
    return;
  }

  updateUpdateState({
    lastCheckedAtUtc: new Date().toISOString()
  });

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

    logger?.info?.("[update] metadata evaluated", {
      currentVersion,
      latestVersion: result.latestVersion,
      available: result.available,
      reason: result.reason
    });

    if (!result.available) {
      logger?.info?.("[update] no update available", {
        currentVersion,
        latestVersion: result.latestVersion,
        reason: result.reason
      });
      return;
    }

    const arch = process.arch === "arm64" ? "arm64" : "x64";
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
      updateInProgress: true
    });

    const run = await performWindowsMsiUpdate(
      ctx,
      result.latestVersion,
      expectedHash
    );

    logger?.warn?.("[update] msi update started", {
      latestVersion: result.latestVersion,
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