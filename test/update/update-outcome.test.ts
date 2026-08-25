// test/update/update-outcome.test.ts
//
// Regression net for the "job says completed, host never updated" bug.
//
// runUpdateTask catches its own errors and RESOLVES (it does not reject), so
// any caller that ACK'd on promise resolution reported success for updates
// that never installed. A real endpoint hit `PrivSvc timeout` mid-update and
// the control plane still closed the job as completed, leaving the host on the
// old version with no signal anywhere in the UI.
//
// These tests pin the contract that makes that impossible: the task reports a
// discriminated outcome, and a failure is never reported as success.

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

// The task pulls in update-state (disk) and update-service (network/PrivSvc);
// both are mocked so we exercise the outcome contract, not the installers.
const state = {
  updateInProgress: false,
  lastAttemptedVersion: "",
  lastSuccessVersion: "",
  lastAttemptedAtUtc: "",
  installStartedAtUtc: "",
  lastCheckedAtUtc: "",
};

vi.mock("../../src/update/update-state", () => ({
  loadUpdateState: () => state,
  markUpdateFailed: vi.fn(),
  markUpdateSucceeded: vi.fn(),
  updateUpdateState: vi.fn(),
}));

const fetchAgentMetadata = vi.fn();
const checkForAvailableUpdate = vi.fn();
const performWindowsMsiUpdate = vi.fn();

vi.mock("../../src/update/update-service", () => ({
  fetchAgentMetadata: (...a: any[]) => fetchAgentMetadata(...a),
  checkForAvailableUpdate: (...a: any[]) => checkForAvailableUpdate(...a),
  performWindowsMsiUpdate: (...a: any[]) => performWindowsMsiUpdate(...a),
  performMacosPkgUpdate: vi.fn(),
  performLinuxUpdate: vi.fn(),
}));

import { runUpdateTask } from "../../src/update/update-task";

const ctx: any = {
  agent: { platform: "windows", version: "1.1.28" },
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
};

const realPlatform = process.platform;

beforeEach(() => {
  // Pin the arch: resolveArch() otherwise reads the HOST (arm64 on Apple
  // silicon), so the fixture's x64 metadata would look like a missing binary
  // and the suite would pass or fail depending on who ran it.
  process.env.TRACENIUM_ARCH = "x64";
  // Pin the platform too. runUpdateTask derives the OS with
  //   isWindows = ctx.agent.platform === "windows" || process.platform === "win32"
  //   isMacos   = ctx.agent.platform === "macos"   || process.platform === "darwin"
  // so on a macOS dev machine BOTH are true for a Windows ctx, and the
  // if/else picks the macOS branch — it would look for a pkg that this
  // fixture never offers. Stubbing the host platform keeps the test faithful
  // to the reported Windows scenario. (That OR is fragile in production code
  // too, but fixing it is out of scope here.)
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  Object.assign(state, {
    updateInProgress: false,
    lastAttemptedVersion: "",
    lastSuccessVersion: "",
    lastAttemptedAtUtc: "",
    installStartedAtUtc: "",
    lastCheckedAtUtc: "",
  });
  fetchAgentMetadata.mockReset();
  checkForAvailableUpdate.mockReset();
  performWindowsMsiUpdate.mockReset();
});

afterEach(() => {
  delete process.env.TRACENIUM_ARCH;
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
  vi.clearAllMocks();
});

function metadataOffering(version: string) {
  fetchAgentMetadata.mockResolvedValue({});
  checkForAvailableUpdate.mockReturnValue({
    available: true,
    latestVersion: version,
    metadata: { files: { msi: { x64: { hash: "a".repeat(64) } } } },
  });
}

describe("runUpdateTask outcome contract", () => {
  it("reports `failed` when the installer step throws — the exact shape of the PrivSvc timeout", async () => {
    metadataOffering("1.1.30");
    performWindowsMsiUpdate.mockRejectedValue(new Error("PrivSvc timeout"));

    const outcome = await runUpdateTask(ctx, { force: true, targetVersion: "1.1.30" });
    expect(outcome.status).toBe("failed");
    expect((outcome as any).error).toContain("PrivSvc timeout");
  });

  it("reports `started` only when the installer was actually launched", async () => {
    metadataOffering("1.1.30");
    performWindowsMsiUpdate.mockResolvedValue({ command: "msiexec", args: ["/i"] });

    const outcome = await runUpdateTask(ctx, { force: true, targetVersion: "1.1.30" });

    // `servedBy` names the tier that served the installer. It defaults to
    // "origin" rather than being omitted so that "how much of the fleet updated
    // over the LAN?" is answerable by counting, without having to treat a
    // missing field as a third, unknown category.
    expect(outcome).toEqual({
      status: "started",
      version: "1.1.30",
      servedBy: "origin",
    });
  });

  it("distinguishes a legitimate no-op from a failure", async () => {
    fetchAgentMetadata.mockResolvedValue({});
    checkForAvailableUpdate.mockReturnValue({
      available: false,
      latestVersion: "1.1.28",
      reason: "already_latest",
      metadata: {},
    });

    const outcome = await runUpdateTask(ctx, { force: true });

    expect(outcome.status).toBe("skipped");
    expect(performWindowsMsiUpdate).not.toHaveBeenCalled();
  });

  it("reports `failed`, not `skipped`, when metadata offers no binary for this arch", async () => {
    fetchAgentMetadata.mockResolvedValue({});
    checkForAvailableUpdate.mockReturnValue({
      available: true,
      latestVersion: "1.1.30",
      metadata: { files: { msi: {} } }, // no x64 entry
    });

    const outcome = await runUpdateTask(ctx, { force: true, targetVersion: "1.1.30" });

    // An operator asked for an update that cannot be satisfied: that is a
    // failure to surface, not a silent skip.
    expect(outcome.status).toBe("failed");
  });

  it("never resolves to `started` when the update never ran", async () => {
    metadataOffering("1.1.30");
    performWindowsMsiUpdate.mockRejectedValue(new Error("boom"));

    const outcome = await runUpdateTask(ctx, { force: true, targetVersion: "1.1.30" });

    // The whole point of the fix: a failure must never look like a launch.
    expect(outcome.status).not.toBe("started");
  });
});
