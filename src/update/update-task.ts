// src/modules/update/update-task.ts

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
    logger?.warn?.("[update] update already in progress, skipping");
    return;
  }

  if (!force && !shouldCheckNow(intervalMs)) {
    return;
  }

  updateUpdateState({
    lastCheckedAtUtc: new Date().toISOString()
  });

  const currentVersion = String(ctx.agent?.version || "").trim();
  if (!currentVersion) {
    logger?.warn?.("[update] missing current agentVersion");
    return;
  }

  try {
    const metadata = await fetchAgentMetadata(ctx);
    const result = checkForAvailableUpdate(currentVersion, metadata);

    logger?.info?.("[update] metadata evaluated", {
      currentVersion,
      latestVersion: result.latestVersion,
      available: result.available,
      reason: result.reason
    });

    if (!result.available || !result.metadata?.files?.msi) {
      return;
    }

    if (!result.available) {
      logger?.info?.("[update] no update available", {
        currentVersion,
        latestVersion: result.latestVersion,
        reason: result.reason
      });
      return;
    }

    const expectedHash = result.metadata.files.msi.hash;

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
      error: err?.message || String(err)
    });
  }
}