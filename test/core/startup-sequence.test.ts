// test/core/startup-sequence.test.ts
//
// Al arrancar el servicio: compliance → CDP → parches EN SERIE, y el de parches
// espera a que la máquina lleve 10 min encendida.
//
// ⚠️ POR QUÉ (prod, 16-sep): los tres salían a la vez por el mismo carril del
// PrivSvc. TNS-OPER-SNOC04 falló «Windows Update scan exceeded 150s» a los 7 min
// de arrancar y escaneó bien 38 s después; MarisolCorona falló a los 16 min
// esperando en el carril «behind security.compliance». Un escaneo fallido llega
// con 0 pendientes y la ingesta borra los que había.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/update/update-task", () => ({ runUpdateTask: vi.fn(async () => ({ status: "skipped" })) }));
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox: { enqueue: vi.fn(), getState: vi.fn(), setState: vi.fn() } }));
vi.mock("../../src/bootstrap/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

import { PolicyRuntime } from "../../src/core/policy-runtime";
import type { PolicyStore } from "../../src/core/policy-store";
import { scheduler } from "../../src/core/scheduler";
import { STARTUP_STEP_CAP_MS, startupPatchDelayMs } from "../../src/core/startup-sequence";

const S = scheduler as any;
const RUNS = ["runInventory", "runUpdate", "runCompliance", "runCdp", "runPatch"] as const;
const MIN = 60_000;

const POLICY = {
  version: "1",
  plugins: { enabled: ["amp", "scp", "pmp", "cdp"] },
  modules: { inventory: true, compliance: true, patch: true },
  features: { selfUpdate: true },
};

function storeWith(doc: any) {
  let current = doc;
  const store = { getPolicy: () => current, getVersion: () => "test" } as unknown as PolicyStore;
  return { store, set: (next: any) => { current = next; } };
}

/** Un run*() que no acaba hasta que el test lo diga. */
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

let spies: Record<string, ReturnType<typeof vi.spyOn>>;
const originalUptime = S.machineUptimeSeconds;

async function start(opts: { uptimeSeconds: number; doc?: any }) {
  const s = storeWith(opts.doc ?? POLICY);
  const rt = new PolicyRuntime(s.store, null);
  await rt.init();
  let uptime = opts.uptimeSeconds;
  const t0 = Date.now();
  // El uptime avanza con el reloj falso, como el de verdad.
  S.machineUptimeSeconds = () => uptime + (Date.now() - t0) / 1000;
  await scheduler.start({ policyRuntime: rt, enrollment: { deviceId: "dev-1", tenantId: "t-1" } } as any);
  return { rt, set: s.set };
}

beforeEach(() => {
  vi.useFakeTimers();
  spies = {};
  for (const r of RUNS) spies[r] = vi.spyOn(S, r).mockResolvedValue(undefined);
});

afterEach(async () => {
  await scheduler.stop();
  S.machineUptimeSeconds = originalUptime;
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("startupPatchDelayMs", () => {
  it("espera lo que falte hasta 10 min de máquina encendida", () => {
    expect(startupPatchDelayMs(60)).toBe(9 * MIN);
    expect(startupPatchDelayMs(0)).toBe(10 * MIN);
  });
  it("⚠️ un reinicio del AGENTE en un servidor encendido hace semanas no espera", () => {
    expect(startupPatchDelayMs(21 * 24 * 3600)).toBe(0);
  });
  it("uptime ilegible → no se espera", () => {
    expect(startupPatchDelayMs(NaN)).toBe(0);
    expect(startupPatchDelayMs(-5)).toBe(0);
  });
});

describe("Scheduler — secuencia de arranque", () => {
  it("🔴 en serie: CDP no sale hasta que acaba compliance, ni parches hasta que acaba CDP", async () => {
    const compliance = deferred();
    const cdp = deferred();
    spies.runCompliance.mockReturnValue(compliance.promise);
    spies.runCdp.mockReturnValue(cdp.promise);

    await start({ uptimeSeconds: 6 * 3600 });
    await vi.advanceTimersByTimeAsync(1);
    expect(spies.runCompliance).toHaveBeenCalledTimes(1);
    expect(spies.runCdp).not.toHaveBeenCalled();
    expect(spies.runPatch).not.toHaveBeenCalled();

    compliance.resolve();
    await vi.advanceTimersByTimeAsync(1);
    expect(spies.runCdp).toHaveBeenCalledTimes(1);
    expect(spies.runPatch).not.toHaveBeenCalled();

    cdp.resolve();
    await vi.advanceTimersByTimeAsync(1);
    expect(spies.runPatch).toHaveBeenCalledTimes(1);
  });

  it("⭐ recién encendida (1 min): el escaneo de parches espera a los 10 min de uptime", async () => {
    await start({ uptimeSeconds: 60 });
    await vi.advanceTimersByTimeAsync(1);
    expect(spies.runCompliance).toHaveBeenCalledTimes(1);
    expect(spies.runCdp).toHaveBeenCalledTimes(1);
    expect(spies.runPatch).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(8 * MIN);
    expect(spies.runPatch).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1 * MIN + 1000);
    expect(spies.runPatch).toHaveBeenCalledTimes(1);
  });

  it("el update es una comprobación de red: corre ya, fuera de la serie", async () => {
    const compliance = deferred();
    spies.runCompliance.mockReturnValue(compliance.promise);
    await start({ uptimeSeconds: 60 });
    expect(spies.runUpdate).toHaveBeenCalledTimes(1);
    compliance.resolve();
  });

  it("⚠️ un paso colgado no bloquea a los demás más allá del techo", async () => {
    spies.runCompliance.mockReturnValue(new Promise(() => {}));
    await start({ uptimeSeconds: 6 * 3600 });
    await vi.advanceTimersByTimeAsync(STARTUP_STEP_CAP_MS - 1000);
    expect(spies.runCdp).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2000);
    expect(spies.runCdp).toHaveBeenCalledTimes(1);
  });

  it("parar el servicio durante la espera anula el escaneo pendiente", async () => {
    await start({ uptimeSeconds: 60 });
    await vi.advanceTimersByTimeAsync(1 * MIN);
    await scheduler.stop();
    await vi.advanceTimersByTimeAsync(20 * MIN);
    expect(spies.runPatch).not.toHaveBeenCalled();
  });

  it("🔴 una policy que llega al conectar NO adelanta el escaneo que espera su turno", async () => {
    // Primera instalación: el runtime arranca sin PMP y la policy real llega
    // por la conexión. Sin la guarda, el reconciliador lo lanzaría al momento.
    const sinPmp = { ...POLICY, plugins: { enabled: ["amp", "scp", "cdp"] } };
    const { rt, set } = await start({ uptimeSeconds: 60, doc: sinPmp });
    await vi.advanceTimersByTimeAsync(1);

    set({ ...POLICY, version: "2" });
    await rt.applyUpdate();
    await vi.advanceTimersByTimeAsync(1);
    expect(spies.runPatch).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(10 * MIN);
    expect(spies.runPatch).toHaveBeenCalledTimes(1);
  });

  it("y si la policy APAGA parches durante la espera, no se escanea", async () => {
    const { rt, set } = await start({ uptimeSeconds: 60 });
    await vi.advanceTimersByTimeAsync(1);
    set({ ...POLICY, version: "2", modules: { inventory: true, compliance: true, patch: false } });
    await rt.applyUpdate();

    await vi.advanceTimersByTimeAsync(10 * MIN);
    expect(spies.runPatch).not.toHaveBeenCalled();
  });
});
