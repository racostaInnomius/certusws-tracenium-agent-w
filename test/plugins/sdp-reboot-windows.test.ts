// test/plugins/sdp-reboot-windows.test.ts
//
// The Windows reboot exit codes, driven through the REAL orchestrator.
//
// Why a separate file with a stubbed `os`: the orchestrator derives the local
// platform from os.platform() and rejects a snapshot that doesn't match it, so
// the 3010/1641 paths are unreachable from a macOS or Linux host. Gating them
// on `process.platform === "win32"` would have been worse than no test — CI
// runs on ubuntu-latest, so they would never have executed anywhere while
// looking like coverage. Stubbing the platform is what makes the wiring (not
// just the pure decision function) actually verifiable.
//
// The stub is module-scoped, which is why these tests are not in
// sdp-orchestrator.test.ts: that file's whole harness is built around running
// as the real host.

import os from "os";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { runSoftwareInstall } from "../../src/plugins/sdp/index";

// vi.mock("os", …) does NOT take effect here — the orchestrator's default
// import of the builtin keeps resolving to the real module. Spying on the
// shared module object does, and it reaches detection.ts's applicability check
// too, since both files import the same object. The first test below asserts
// the stub is live so this file can never silently degrade into testing macOS.
beforeAll(() => {
  vi.spyOn(os, "platform").mockReturnValue("win32");
});
afterAll(() => {
  vi.restoreAllMocks();
});

type PrivResponse = { ok: boolean; result?: any; error?: { code: string } };
type Scripts = Partial<Record<string, PrivResponse | PrivResponse[]>>;

function makeCtx(scripts: Scripts = {}) {
  const calls: Array<{ method: string; params: any }> = [];
  const queues: Record<string, PrivResponse[]> = {};
  for (const [method, val] of Object.entries(scripts)) {
    queues[method] = Array.isArray(val) ? [...val] : [val as PrivResponse];
  }
  const priv = {
    call: vi.fn(async (req: any): Promise<PrivResponse> => {
      calls.push({ method: req.method, params: req.params });
      const q = queues[req.method];
      if (q && q.length > 0) return q.shift() as PrivResponse;
      if (q) return q[q.length - 1] ?? { ok: false, error: { code: "no_script" } };
      throw new Error(`unscripted privsvc method: ${req.method}`);
    }),
  };
  const ctx: any = {
    priv,
    enrollment: { tenantId: "t-1", deviceId: "dev-1" },
    policyRuntime: { pluginEnabled: () => true },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { ctx, calls };
}

function parseAck(msg: string): { outcome: string; fields: Record<string, string> } {
  const parts = msg.split(";");
  const outcome = parts[0].split(":")[1];
  const fields: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const i = p.indexOf("=");
    if (i >= 0) fields[p.slice(0, i)] = p.slice(i + 1);
  }
  return { outcome, fields };
}

function winSnap(over: Record<string, unknown> = {}) {
  return {
    id: 10,
    name: "TestApp",
    version: "1.0.0",
    platform: "windows",
    arch: "any",
    format: "msi",
    downloadPath: "https://cdn.example.com/app.msi",
    sha256: "a".repeat(64),
    silentInstallArgs: "/qn",
    silentUninstallArgs: null,
    // registry_uninstall is the applicable rule type on Windows, so pre/post
    // detection actually dispatch to the scripted privsvc.
    detectionRule: { type: "registry_uninstall", displayNameLike: "TestApp%" },
    expectedExitCodes: [0, 3010],
    signingRequired: false,
    ...over,
  };
}

const OK_DOWNLOAD: PrivResponse = {
  ok: true,
  result: { stagingPath: "C:\\staging\\pkg-10.msi", sha256: "a".repeat(64), durationMs: 5 },
};
const DETECT = (matched: boolean): PrivResponse => ({
  ok: true,
  result: { matched, snapshot: { probe: matched } },
});
const INSTALL_EXIT = (exitCode: number): PrivResponse => ({
  ok: true,
  result: { exitCode, stderrExcerpt: "", durationMs: 12 },
});

function methodsCalled(calls: Array<{ method: string }>): string[] {
  return calls.map((c) => c.method);
}

describe("Windows reboot exit codes — through the orchestrator", () => {
  it("sanity: the platform stub is in effect (a windows snapshot is accepted)", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(false), DETECT(true)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": INSTALL_EXIT(0),
    });
    const ack = await runSoftwareInstall(ctx, "job-w0", {
      deploymentId: 7,
      packageSnapshot: winSnap(),
    });
    // Without the stub this would be `rejected` / platform_mismatch.
    expect(ack.outcome).toBe("success");
  });

  it("reports reboot_required on 3010 and still runs post-detect", async () => {
    const { ctx, calls } = makeCtx({
      "sdp.detect": [DETECT(false), DETECT(true)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": INSTALL_EXIT(3010),
    });
    const ack = await runSoftwareInstall(ctx, "job-w1", {
      deploymentId: 7,
      packageSnapshot: winSnap(),
    });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("reboot_required");
    const p = parseAck(ack.ackMessage);
    expect(p.fields.exit).toBe("3010");
    expect(p.fields.reason).toBe("exit_reboot_required");
    // The machine is still up, so the silent-no-op check keeps its value.
    expect(methodsCalled(calls)).toEqual([
      "sdp.detect",
      "sdp.download",
      "sdp.install",
      "sdp.detect",
    ]);
  });

  // The headline regression. 1641 is outside the catalog's [0, 3010], so before
  // the widening this was graded `unexpected_exit_1641` → permanent `failed`,
  // with no retry — a successful install reported as a failure.
  it("reports reboot_required on 1641 even though the catalog never listed it", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(false)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": INSTALL_EXIT(1641),
    });
    const ack = await runSoftwareInstall(ctx, "job-w2", {
      deploymentId: 7,
      packageSnapshot: winSnap({ expectedExitCodes: [0, 3010] }),
    });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("reboot_required");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("exit_reboot_initiated");
  });

  it("skips post-detect when the reboot has already started (1641)", async () => {
    const { ctx, calls } = makeCtx({
      // Only ONE detect scripted: a second call would consume the pre-detect
      // response again and quietly pass. The method list below is the assertion
      // that matters.
      "sdp.detect": [DETECT(false)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": INSTALL_EXIT(1641),
    });
    const ack = await runSoftwareInstall(ctx, "job-w3", {
      deploymentId: 7,
      packageSnapshot: winSnap(),
    });
    expect(ack.outcome).toBe("reboot_required");
    expect(methodsCalled(calls)).toEqual(["sdp.detect", "sdp.download", "sdp.install"]);
  });

  it("still fails on a genuinely unexpected exit code", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(false)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": INSTALL_EXIT(1603),
    });
    const ack = await runSoftwareInstall(ctx, "job-w4", {
      deploymentId: 7,
      packageSnapshot: winSnap(),
    });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("failed");
    expect(parseAck(ack.ackMessage).fields.reason).toMatch(/^unexpected_exit_1603/);
  });

  it("prefers the installer's word over the catalog flag", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(false), DETECT(true)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": INSTALL_EXIT(3010),
    });
    const ack = await runSoftwareInstall(ctx, "job-w5", {
      deploymentId: 7,
      packageSnapshot: winSnap({ requiresReboot: true }),
    });
    expect(parseAck(ack.ackMessage).fields.reason).toBe("exit_reboot_required");
  });
});
