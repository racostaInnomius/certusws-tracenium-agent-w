// test/status/tray-status-store.test.ts
//
// Regression coverage for TrayStatusStore's markJobStarted/markJobFinished
// — specifically the `jobs.current` tracking added so the tray apps can
// show an "Active Job" tab and a menu-bar badge while a job is running.
// No test existed for this store before.
//
// Uses a real temp directory (mkdtempSync) rather than mocking `fs` —
// TrayStatusStore does real file I/O (write-to-tmp + rename) and that
// behavior (atomic-ish writes, JSON round-trip) is part of what's worth
// verifying, not incidental plumbing to stub out.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

let tmpDir: string;
let statusDir: string;

vi.mock("../../src/bootstrap/paths", () => ({
  ensureAgentStatusDir: () => {
    fs.mkdirSync(statusDir, { recursive: true });
    return statusDir;
  },
  getTrayStatusFilePath: () => path.join(statusDir, "tray-status.json"),
  getLegacyAgentStatusDir: () => null,
}));

vi.mock("../../src/plugins/pmp/state", () => ({
  loadPmpState: () => ({ status: undefined, rebootRequired: undefined, lastError: undefined }),
}));

vi.mock("../../src/update/update-state", () => ({
  loadUpdateState: () => ({ status: undefined, lastCheckedAtUtc: undefined, lastCompletedAtUtc: undefined, lastError: undefined }),
}));

vi.mock("systeminformation", () => ({
  default: {
    osInfo: async () => ({}),
    system: async () => ({}),
    cpu: async () => ({}),
    mem: async () => ({ total: 0 }),
    networkInterfaces: async () => [],
    networkInterfaceDefault: async () => "",
  },
}));

let TrayStatusStore: typeof import("../../src/status/tray-status-store").TrayStatusStore;

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tray-status-test-"));
  statusDir = path.join(tmpDir, "status");
  vi.resetModules();
  ({ TrayStatusStore } = await import("../../src/status/tray-status-store"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("TrayStatusStore — active job tracking", () => {
  it("markJobStarted with a jobId sets jobs.current", () => {
    const store = new TrayStatusStore();
    const snapshot = store.markJobStarted("patch_install", "job-1");

    expect(snapshot.jobs.current).toEqual(
      expect.objectContaining({ jobId: "job-1", jobType: "patch_install" })
    );
    expect(snapshot.jobs.current?.startedAtUtc).toBeTruthy();
    expect(snapshot.jobs.lastJobType).toBe("patch_install");
    expect(snapshot.jobs.lastJobStatus).toBe("in_progress");
  });

  it("markJobStarted without a jobId leaves jobs.current untouched", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("facts_snapshot", "job-1");
    const snapshot = store.markJobStarted("facts_snapshot");

    // No jobId on this call — the previously-tracked active job (if
    // any) is left as-is rather than being silently wiped.
    expect(snapshot.jobs.current?.jobId).toBe("job-1");
  });

  it("markJobFinished clears jobs.current when the jobId matches", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-1");
    const snapshot = store.markJobFinished("patch_install", "success", "job-1");

    expect(snapshot.jobs.current).toBeNull();
    expect(snapshot.jobs.lastJobStatus).toBe("success");
  });

  it("markJobFinished does NOT clear jobs.current for a mismatched (stale) jobId", () => {
    // Guards against an out-of-order finish for an older job stomping
    // a newer job's in-progress state.
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-2");
    const snapshot = store.markJobFinished("patch_install", "failed", "job-1");

    expect(snapshot.jobs.current?.jobId).toBe("job-2");
  });

  it("markJobFinished with no jobId clears jobs.current unconditionally (back-compat)", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-1");
    const snapshot = store.markJobFinished("patch_install", "success");

    expect(snapshot.jobs.current).toBeNull();
  });

  it("persists jobs.current across a save/load round trip", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-1");

    const reloaded = store.load();
    expect(reloaded?.jobs.current).toEqual(
      expect.objectContaining({ jobId: "job-1", jobType: "patch_install" })
    );
  });
});

describe("TrayStatusStore — self-service Software Catalog", () => {
  const item = { packageId: "1", name: "Zoom", version: "6.1.0" };

  it("updateCatalog writes items + catalogVersion", () => {
    const store = new TrayStatusStore();
    const snapshot = store.updateCatalog([item], "abc123");

    expect(snapshot.catalog?.catalogVersion).toBe("abc123");
    expect(snapshot.catalog?.items).toEqual([item]);
    expect(snapshot.catalog?.updatedAtUtc).toBeTruthy();
  });

  it("is a no-op when catalogVersion matches what's already on disk", () => {
    const store = new TrayStatusStore();
    const first = store.updateCatalog([item], "abc123");
    const firstUpdatedAt = first.catalog?.updatedAtUtc;

    const second = store.updateCatalog(
      [{ ...item, name: "Zoom (renamed, but same version hash)" }],
      "abc123"
    );

    // Same version — the store must not have rewritten the block (or
    // the top-level updatedAtUtc), even though the payload differs.
    expect(second.catalog?.updatedAtUtc).toBe(firstUpdatedAt);
    expect(second.catalog?.items).toEqual([item]);
  });

  it("rewrites when catalogVersion changes", () => {
    const store = new TrayStatusStore();
    store.updateCatalog([item], "abc123");
    const second = store.updateCatalog([], "def456");

    expect(second.catalog?.catalogVersion).toBe("def456");
    expect(second.catalog?.items).toEqual([]);
  });

  it("persists across a save/load round trip", () => {
    const store = new TrayStatusStore();
    store.updateCatalog([item], "abc123");

    const reloaded = store.load();
    expect(reloaded?.catalog?.items).toEqual([item]);
    expect(reloaded?.catalog?.catalogVersion).toBe("abc123");
  });
});
