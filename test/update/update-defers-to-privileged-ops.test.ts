// test/update/update-defers-to-privileged-ops.test.ts
//
// The self-update restarts the privsvc, and the privsvc is where the long
// privileged operations run. Whatever it was doing for us dies with it.
//
// PRODUCTION FAILURE THIS REPRODUCES (Msig13, tenant 111, 2026-09-04):
// the device came back online with two things queued for it — the first
// real Windows patch_install and the self-update to 1.1.59 — and the
// backend delivered both in the same reconnect burst (14:09:24Z runJob,
// 14:09:25Z agentUpdate). runUpdateTask never looked at what the privsvc
// was doing; the MSI restarted it 22 minutes into the Windows Update
// install and the job was lost.
//
// The update now yields, and it yields with ACK_RETRY: a plain
// `update_skipped` acks 0, which closes the agent_update job as done on a
// host that is still running the old build.

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

const state = {
  updateInProgress: false,
  lastAttemptedVersion: "",
  lastSuccessVersion: "",
  lastAttemptedAtUtc: "",
  installStartedAtUtc: "",
  lastCheckedAtUtc: ""
};

vi.mock("../../src/update/update-state", () => ({
  loadUpdateState: () => state,
  markUpdateFailed: vi.fn(),
  markUpdateSucceeded: vi.fn(),
  updateUpdateState: vi.fn()
}));

// Any call into the network/installer layer means the guard did NOT fire.
const fetchAgentMetadata = vi.fn();
vi.mock("../../src/update/update-service", () => ({
  fetchAgentMetadata: (...a: any[]) => fetchAgentMetadata(...a),
  checkForAvailableUpdate: vi.fn(),
  performWindowsMsiUpdate: vi.fn(),
  performMacosPkgUpdate: vi.fn(),
  performLinuxUpdate: vi.fn()
}));

let remediateInFlight = false;
vi.mock("../../src/plugins/pmp/state", () => ({
  isRemediateInFlight: () => remediateInFlight
}));

let softwareInstallInFlight = false;
vi.mock("../../src/plugins/sdp/state", () => ({
  isInstallInProgress: () => softwareInstallInFlight
}));

import {
  runUpdateTask,
  privilegedOperationInFlight,
  ackForUpdateOutcome,
  UPDATE_DEFERRED_PREFIX
} from "../../src/update/update-task";

const makeCtx = (): any => ({
  agent: { platform: "windows", version: "1.1.58" },
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
});

const realPlatform = process.platform;

beforeEach(() => {
  process.env.TRACENIUM_ARCH = "x64";
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  Object.assign(state, {
    updateInProgress: false,
    lastAttemptedVersion: "",
    lastSuccessVersion: "",
    lastAttemptedAtUtc: "",
    installStartedAtUtc: "",
    lastCheckedAtUtc: ""
  });
  remediateInFlight = false;
  softwareInstallInFlight = false;
  fetchAgentMetadata.mockReset();
});

afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
  delete process.env.TRACENIUM_ARCH;
});

describe("privilegedOperationInFlight", () => {
  it("names the patch_install held on ctx (Msig13)", () => {
    const ctx = makeCtx();
    ctx._patchInstallInProgress = true;
    expect(privilegedOperationInFlight(ctx)).toBe("patch_install");
  });

  it("names a remediation and a software install too", () => {
    remediateInFlight = true;
    expect(privilegedOperationInFlight(makeCtx())).toBe("patch_remediate");
    remediateInFlight = false;
    softwareInstallInFlight = true;
    expect(privilegedOperationInFlight(makeCtx())).toBe("software_install");
  });

  it("is null when the privsvc is idle for us", () => {
    expect(privilegedOperationInFlight(makeCtx())).toBeNull();
  });
});

describe("runUpdateTask yields to a privileged operation", () => {
  it("⭐ skips before touching the network while a patch_install is in flight", async () => {
    const ctx = makeCtx();
    ctx._patchInstallInProgress = true;

    const outcome = await runUpdateTask(ctx, { targetVersion: "1.1.59", force: true, logger: ctx.logger });

    expect(outcome).toEqual({ status: "skipped", reason: `${UPDATE_DEFERRED_PREFIX}patch_install` });
    expect(fetchAgentMetadata).not.toHaveBeenCalled();
    expect(ctx.logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("deferring"),
      { operation: "patch_install" }
    );
  });

  it("yields to an SDP install for the same reason: the installer restarts the privsvc", async () => {
    softwareInstallInFlight = true;

    const outcome = await runUpdateTask(makeCtx(), { targetVersion: "1.1.59", force: true });

    expect(outcome).toEqual({ status: "skipped", reason: `${UPDATE_DEFERRED_PREFIX}software_install` });
    expect(fetchAgentMetadata).not.toHaveBeenCalled();
  });

  it("proceeds to the metadata lookup when nothing privileged is running", async () => {
    fetchAgentMetadata.mockRejectedValue(new Error("network down in this test"));

    const outcome = await runUpdateTask(makeCtx(), { targetVersion: "1.1.59", force: true });

    expect(outcome.status).not.toBe("skipped");
    expect(fetchAgentMetadata).toHaveBeenCalled();
  });
});

describe("ackForUpdateOutcome — one mapping for the job and the push path", () => {
  it("a deferred update is ACK_RETRY, so the backend re-sends it later", () => {
    expect(
      ackForUpdateOutcome({ status: "skipped", reason: `${UPDATE_DEFERRED_PREFIX}patch_install` })
    ).toEqual({ status: 1, message: "agent_update retry: privileged_operation_in_progress:patch_install" });
  });

  it("every other skip still closes the job as done", () => {
    expect(ackForUpdateOutcome({ status: "skipped", reason: "latest_already_installed" })).toEqual({
      status: 0,
      message: "update_skipped: latest_already_installed"
    });
  });

  it("failed and started keep their wire shape", () => {
    expect(ackForUpdateOutcome({ status: "failed", error: "hash_mismatch" })).toEqual({
      status: 2,
      message: "update_failed: hash_mismatch"
    });
    expect(ackForUpdateOutcome({ status: "started", version: "1.1.59", servedBy: "dp" } as any)).toEqual({
      status: 0,
      message: "update_started;src=dp"
    });
    expect(ackForUpdateOutcome({ status: "started", version: "1.1.59" } as any)).toEqual({
      status: 0,
      message: "update_started;src=origin"
    });
  });
});
