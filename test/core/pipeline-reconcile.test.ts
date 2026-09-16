// test/core/pipeline-reconcile.test.ts
//
// Un evento de policy sólo toca los pipelines que cambió.
//
// ⚠️ EL FALLO (prod, 16-sep): `applyUpdate()` emite todos sus eventos en cada
// aplicación y el backend reenvía la misma policy. Cinco eventos relanzaban los
// pipelines con escaneo inmediato, así que cada reenvío ponía a la flota entera
// a escanear Windows Update a la vez contra el mismo WSUS (T111: ráfagas de 73
// escaneos en una hora, 95 «Windows Update scan exceeded 150s» en 14 días).
//
// Se entra por donde entra la policy de verdad —store → PolicyRuntime.init() /
// applyUpdate()— y con el scheduler real: lo que se mide es qué run*() se llama
// y qué temporizadores cambian.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/update/update-task", () => ({ runUpdateTask: vi.fn(async () => ({ status: "skipped" })) }));
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox: { enqueue: vi.fn(), getState: vi.fn(), setState: vi.fn() } }));
vi.mock("../../src/bootstrap/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

import { PolicyRuntime } from "../../src/core/policy-runtime";
import type { PolicyStore } from "../../src/core/policy-store";
import { scheduler } from "../../src/core/scheduler";

const S = scheduler as any;
const RUNS = ["runInventory", "runUpdate", "runCompliance", "runCdp", "runPatch"] as const;

const POLICY = {
  version: "1",
  plugins: { enabled: ["amp", "scp", "pmp", "cdp"] },
  modules: { inventory: true, compliance: true, patch: true },
  features: { selfUpdate: false },
};

function storeWith(doc: any) {
  let current = doc;
  const store = { getPolicy: () => current, getVersion: () => "test" } as unknown as PolicyStore;
  return { store, set: (next: any) => { current = next; } };
}

let spies: Record<string, ReturnType<typeof vi.spyOn>>;
const calls = () => Object.fromEntries(RUNS.map((r) => [r, spies[r].mock.calls.length]));
const resetCalls = () => RUNS.forEach((r) => spies[r].mockClear());

async function started(doc: any) {
  const s = storeWith(doc);
  const rt = new PolicyRuntime(s.store, null);
  await rt.init();
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
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("Scheduler — un reenvío de la MISMA policy", () => {
  it("🔴 no relanza ningún escaneo ni re-arma ningún temporizador", async () => {
    const { rt, set } = await started(POLICY);
    // El arranque sí corre lo suyo: eso es el paso 2, no esto.
    expect(calls()).toMatchObject({ runUpdate: 0, runCompliance: 1, runCdp: 1, runPatch: 1 });
    const timersBefore = new Map(S.timers);
    resetCalls();

    // El reconciliador del backend reenvía la policy idéntica, tres veces.
    for (let i = 0; i < 3; i++) {
      set({ ...POLICY, version: String(2 + i) });
      await rt.applyUpdate();
    }

    expect(calls()).toEqual({ runInventory: 0, runUpdate: 0, runCompliance: 0, runCdp: 0, runPatch: 0 });
    // Los MISMOS temporizadores: re-armar también reiniciaba el ciclo de 24 h.
    for (const [key, timer] of timersBefore) expect(S.timers.get(key)).toBe(timer);
  });
});

describe("Scheduler — una policy que SÍ cambia algo", () => {
  it("cambiar el intervalo de parches re-arma sólo ese pipeline y NO escanea", async () => {
    const { rt, set } = await started(POLICY);
    const timersBefore = new Map(S.timers);
    resetCalls();

    set({ ...POLICY, version: "2", patch: { intervalSeconds: 43200 } });
    await rt.applyUpdate();

    expect(calls()).toEqual({ runInventory: 0, runUpdate: 0, runCompliance: 0, runCdp: 0, runPatch: 0 });
    expect(S.timers.get("patch")).not.toBe(timersBefore.get("patch"));
    expect(S.timers.get("compliance")).toBe(timersBefore.get("compliance"));
    expect(S.timers.get("cdp")).toBe(timersBefore.get("cdp"));
  });

  it("⭐ activar PMP en el portal escanea YA, una sola vez aunque lleguen ocho eventos", async () => {
    // Módulo patch ya activo y el plugin no: el caso en que olvidar el plugin
    // en el plan dejaría el primer escaneo 24 h esperando.
    const sinPmp = { ...POLICY, plugins: { enabled: ["amp", "scp", "cdp"] } };
    const { rt, set } = await started(sinPmp);
    resetCalls();

    set({ ...POLICY, version: "2" });
    await rt.applyUpdate();

    expect(spies.runPatch).toHaveBeenCalledTimes(1);
    // Cambiaron los plugins: el inventario manda las capabilities nuevas.
    expect(spies.runInventory).toHaveBeenCalledTimes(1);
    expect(calls()).toMatchObject({ runCompliance: 0, runCdp: 0 });
  });

  it("apagar CDP para su temporizador sin correr nada", async () => {
    const { rt, set } = await started(POLICY);
    resetCalls();

    set({ ...POLICY, version: "2", plugins: { enabled: ["amp", "scp", "pmp"] } });
    await rt.applyUpdate();

    expect(S.timers.has("cdp")).toBe(false);
    expect(S.pipelineActive.has("cdp")).toBe(false);
    expect(calls()).toMatchObject({ runPatch: 0, runCompliance: 0, runCdp: 0 });
    expect(spies.runInventory).toHaveBeenCalledTimes(1);
  });

  it("un temporizador re-armado sigue disparando su pipeline", async () => {
    const { rt, set } = await started(POLICY);
    set({ ...POLICY, version: "2", patch: { intervalSeconds: 3600 } });
    await rt.applyUpdate();
    resetCalls();

    await vi.advanceTimersByTimeAsync(3600 * 1000 + 30_000);
    expect(spies.runPatch).toHaveBeenCalledTimes(1);
  });
});
