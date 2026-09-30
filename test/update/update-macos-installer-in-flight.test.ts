// test/update/update-macos-installer-in-flight.test.ts
//
// runUpdateTask en macOS mira antes si hay un `installer` nuestro vivo. El
// iMac de T1 (30-sep) llegó a tener tres parados en la cola de PackageKit:
// cada intento lanzaba otro y contestaba `update_started`.

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

const state = {
  updateInProgress: false,
  lastAttemptedVersion: "",
  lastSuccessVersion: "",
  lastAttemptedAtUtc: "",
  installStartedAtUtc: "",
  lastCheckedAtUtc: ""
};
const markUpdateFailed = vi.fn();
vi.mock("../../src/update/update-state", () => ({
  loadUpdateState: () => state,
  markUpdateFailed: (...a: any[]) => markUpdateFailed(...a),
  markUpdateSucceeded: vi.fn(),
  updateUpdateState: vi.fn()
}));

const fetchAgentMetadata = vi.fn();
const performMacosPkgUpdate = vi.fn();
vi.mock("../../src/update/update-service", () => ({
  fetchAgentMetadata: (...a: any[]) => fetchAgentMetadata(...a),
  checkForAvailableUpdate: vi.fn(),
  performWindowsMsiUpdate: vi.fn(),
  performMacosPkgUpdate: (...a: any[]) => performMacosPkgUpdate(...a),
  performLinuxUpdate: vi.fn()
}));

vi.mock("../../src/update/battery-gate", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/update/battery-gate")>()),
  readBatteryForUpdate: async () => undefined
}));

// La decisión es la real; lo que se simula es lo que hay en la máquina.
let running: Array<{ pid: number; elapsedSec: number }> = [];
const killInstaller = vi.fn();
vi.mock("../../src/update/macos-installer-guard", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/update/macos-installer-guard")>()),
  findRunningInstallers: () => running,
  killInstaller: (pid: number) => killInstaller(pid)
}));

import { runUpdateTask, ackForUpdateOutcome } from "../../src/update/update-task";

const makeCtx = (): any => ({
  agent: { platform: "macos", version: "1.1.84" },
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
});

const realPlatform = process.platform;

beforeEach(() => {
  process.env.TRACENIUM_ARCH = "x64";
  Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
  Object.assign(state, { updateInProgress: false, lastCheckedAtUtc: "" });
  running = [];
  killInstaller.mockReset();
  markUpdateFailed.mockReset();
  fetchAgentMetadata.mockReset();
  performMacosPkgUpdate.mockReset();
});

afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
  delete process.env.TRACENIUM_ARCH;
});

describe("runUpdateTask en macOS con un installer nuestro vivo", () => {
  it("⭐ uno reciente: no lanza otro, y el job vuelve (ACK_RETRY con el pid)", async () => {
    running = [{ pid: 68552, elapsedSec: 5 * 60 }];

    const outcome = await runUpdateTask(makeCtx(), { targetVersion: "1.1.87", force: true });

    expect(outcome).toEqual({ status: "skipped", reason: "installer_running:pid=68552,5 min" });
    expect(fetchAgentMetadata).not.toHaveBeenCalled();
    expect(performMacosPkgUpdate).not.toHaveBeenCalled();
    expect(ackForUpdateOutcome(outcome)).toEqual({
      status: 1,
      message: "agent_update retry: installer_running:pid=68552,5 min"
    });
  });

  it("⭐ el caso del iMac: atascados → los mata, FALLA con el motivo y no apila otro", async () => {
    running = [
      { pid: 61276, elapsedSec: 31246 },
      { pid: 66864, elapsedSec: 9740 },
      { pid: 68552, elapsedSec: 2822 }
    ];

    const outcome = await runUpdateTask(makeCtx(), { targetVersion: "1.1.87", force: true });

    expect(killInstaller.mock.calls.map((c) => c[0])).toEqual([61276, 66864, 68552]);
    expect(outcome.status).toBe("failed");
    expect((outcome as any).error).toMatch(/^installer_stalled: 3 installer\(s\) .*PackageKit.* 8 h 40 min; killed/);
    expect(markUpdateFailed).toHaveBeenCalledWith((outcome as any).error);
    expect(performMacosPkgUpdate).not.toHaveBeenCalled();
    expect(ackForUpdateOutcome(outcome).status).toBe(2);
  });

  it("sin installers nuestros sigue su camino normal", async () => {
    fetchAgentMetadata.mockRejectedValue(new Error("network down in this test"));

    await runUpdateTask(makeCtx(), { targetVersion: "1.1.87", force: true });

    expect(fetchAgentMetadata).toHaveBeenCalled();
    expect(killInstaller).not.toHaveBeenCalled();
  });

  it("en Windows no se mira", async () => {
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    running = [{ pid: 1, elapsedSec: 99999 }];
    fetchAgentMetadata.mockRejectedValue(new Error("network down in this test"));

    await runUpdateTask({ ...makeCtx(), agent: { platform: "windows", version: "1.1.84" } }, { targetVersion: "1.1.87", force: true });

    expect(killInstaller).not.toHaveBeenCalled();
    expect(fetchAgentMetadata).toHaveBeenCalled();
  });
});
