// test/plugins/pmp-state-reconcile.test.ts
//
// An `in_progress` install found at boot belongs to a process that is
// gone. Nothing cleared it until 2026-09-04: Msig13 (tenant 111) lost its
// AgentCore mid-install three times that day and every PMP snapshot in
// between kept saying `installing` — the portal showed a spinner for
// hours over a job whose result had already been written to a dead pipe.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

import {
  loadPmpState,
  savePmpState,
  reconcileStalePmpState,
  AGENT_RESTARTED_ERROR
} from "../../src/plugins/pmp/state";

let dir: string;
const prevEnv = process.env.TRACENIUM_STATE_DIR;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-pmp-state-"));
  process.env.TRACENIUM_STATE_DIR = dir;
});

afterEach(() => {
  if (prevEnv === undefined) delete process.env.TRACENIUM_STATE_DIR;
  else process.env.TRACENIUM_STATE_DIR = prevEnv;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("reconcileStalePmpState at boot", () => {
  it("⭐ turns an orphaned in_progress into failed:agent_restarted, keeping what was known", () => {
    // The shape Msig13 left on disk at 16:06 — set by grpc-stream when
    // the runJob arrived, never updated because the process died.
    savePmpState({
      status: "in_progress",
      mode: "install",
      startedAtUtc: "2026-09-04T15:49:31.573Z",
      selectedCount: 2,
      installedCount: 0,
      failedCount: 0,
      results: []
    });

    const found = reconcileStalePmpState();

    expect(found).toEqual({ mode: "install", startedAtUtc: "2026-09-04T15:49:31.573Z" });
    const after = loadPmpState();
    expect(after.status).toBe("failed");
    expect(after.lastError).toBe(AGENT_RESTARTED_ERROR);
    expect(after.finishedAtUtc).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    // The provider derives `installing` from status alone; the rest is
    // evidence of what was attempted and stays.
    expect(after.mode).toBe("install");
    expect(after.startedAtUtc).toBe("2026-09-04T15:49:31.573Z");
    expect(after.selectedCount).toBe(2);
  });

  it.each(["idle", "success", "partial", "failed"] as const)(
    "leaves a %s state exactly as it was",
    (status) => {
      const state = {
        status,
        mode: "install" as const,
        finishedAtUtc: "2026-09-01T00:00:00.000Z",
        installedCount: 1,
        lastError: status === "failed" ? "patch_install failed" : undefined
      };
      savePmpState(state);

      expect(reconcileStalePmpState()).toBeNull();
      expect(loadPmpState()).toEqual(state);
    }
  );

  it("does nothing when there is no state file yet", () => {
    expect(reconcileStalePmpState()).toBeNull();
    expect(fs.existsSync(path.join(dir, "pmp-state.json"))).toBe(false);
  });

  it("is idempotent: a second boot sees failed, not in_progress", () => {
    savePmpState({ status: "in_progress", mode: "download" });
    expect(reconcileStalePmpState()).toEqual({ mode: "download", startedAtUtc: undefined });
    expect(reconcileStalePmpState()).toBeNull();
    expect(loadPmpState().status).toBe("failed");
  });
});
