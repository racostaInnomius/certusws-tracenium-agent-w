// test/core/self-update-gate.test.ts
//
// Apagar «Self-update» en el portal no paraba nada. El gate era
//
//     isUpdateEnabled() = modules.update || features.selfUpdate
//
// y `modules.update` vale `true` en DEFAULT_POLICY; el validador lo rellena
// desde ahí y ni el portal ni el backend escriben nunca `false`. Con el OR, la
// otra rama siempre ganaba: el sondeo de 6 h seguía corriendo e instalando la
// última versión en equipos que el operador creía congelados.
//
// Los tests entran por donde entra la policy de verdad (store → init() /
// applyUpdate()), no asignando `rt.policy` a mano: el validador es justo la
// pieza que rellena el `true` que escondía el fallo.

import { beforeEach, describe, expect, it, vi } from "vitest";

const { runUpdateTask } = vi.hoisted(() => ({
  runUpdateTask: vi.fn(async () => ({ status: "skipped", reason: "test" }))
}));
vi.mock("../../src/update/update-task", () => ({ runUpdateTask }));
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox: { enqueue: vi.fn() } }));
vi.mock("../../src/bootstrap/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

import { PolicyRuntime } from "../../src/core/policy-runtime";
import type { PolicyStore } from "../../src/core/policy-store";
import { scheduler } from "../../src/core/scheduler";

function storeWith(doc: any): { store: PolicyStore; set(next: any): void } {
  let current = doc;
  const store = {
    getPolicy: () => current,
    getVersion: () => "test"
  } as unknown as PolicyStore;
  return { store, set: (next) => { current = next; } };
}

async function runtimeFor(doc: any) {
  const rt = new PolicyRuntime(storeWith(doc).store, null);
  await rt.init();
  return rt;
}

describe("PolicyRuntime.isUpdateEnabled — features.selfUpdate manda", () => {
  it("⚠️ selfUpdate=false apaga el auto-update aunque modules.update venga del default", async () => {
    // La forma que escribe el portal: `modules` sin `update`, el switch apagado.
    const rt = await runtimeFor({ version: "1", modules: {}, features: { selfUpdate: false } });
    expect(rt.isUpdateEnabled()).toBe(false);
  });

  it("selfUpdate=false también por la ruta v2 (agent.features)", async () => {
    const rt = await runtimeFor({ version: "1", agent: { features: { selfUpdate: false } } });
    expect(rt.isUpdateEnabled()).toBe(false);
  });

  it("sin opinión en la policy sigue encendido (default del agente)", async () => {
    expect((await runtimeFor({ version: "1" })).isUpdateEnabled()).toBe(true);
    // Un documento ilegible cae entero al default.
    expect((await runtimeFor(null)).isUpdateEnabled()).toBe(true);
  });

  it("selfUpdate=true enciende", async () => {
    const rt = await runtimeFor({ version: "1", features: { selfUpdate: true } });
    expect(rt.isUpdateEnabled()).toBe(true);
  });

  it("modules.update=false sigue apagando (ninguna policy lo escribe, pero no debe encenderse)", async () => {
    const rt = await runtimeFor({ version: "1", modules: { update: false }, features: { selfUpdate: true } });
    expect(rt.isUpdateEnabled()).toBe(false);
  });

  it("applyUpdate(): apagar el switch en una policy posterior lo apaga en caliente", async () => {
    const s = storeWith({ version: "1", features: { selfUpdate: true } });
    const rt = new PolicyRuntime(s.store, null);
    await rt.init();
    expect(rt.isUpdateEnabled()).toBe(true);

    s.set({ version: "2", features: { selfUpdate: false } });
    await rt.applyUpdate();
    expect(rt.isUpdateEnabled()).toBe(false);
  });
});

describe("Scheduler — el sondeo periódico respeta el switch", () => {
  // Inventario apagado y sólo AMP: así el único pipeline que arranca
  // `startPipelines` es el de update, y lo que se mide es solo eso.
  const BASE = { version: "1", plugins: { enabled: ["amp"] }, modules: { inventory: false } };

  function ctxFor(rt: PolicyRuntime): any {
    return { policyRuntime: rt, enrollment: { deviceId: "dev-1", tenantId: "t-1" } };
  }

  function start(rt: PolicyRuntime) {
    (scheduler as any).startPipelines(ctxFor(rt));
  }

  beforeEach(() => {
    runUpdateTask.mockClear();
    (scheduler as any).stopAll();
  });

  it("⚠️ con selfUpdate=false no corre el chequeo ni arma el tick de 6 h", async () => {
    const rt = await runtimeFor({ ...BASE, features: { selfUpdate: false } });
    start(rt);
    try {
      expect(runUpdateTask).not.toHaveBeenCalled();
      expect((scheduler as any).pipelineActive.has("update")).toBe(false);
      expect((scheduler as any).timers.has("update")).toBe(false);
    } finally {
      (scheduler as any).stopAll();
    }
  });

  it("con selfUpdate=true corre el chequeo inicial y arma el tick", async () => {
    const rt = await runtimeFor({ ...BASE, features: { selfUpdate: true } });
    start(rt);
    try {
      expect(runUpdateTask).toHaveBeenCalledTimes(1);
      expect((scheduler as any).timers.has("update")).toBe(true);
    } finally {
      (scheduler as any).stopAll();
    }
  });

  it("un tick que ya estaba armado no instala si el switch se apagó entretanto", async () => {
    // runUpdate re-comprueba el gate: cubre la carrera entre el tick y la
    // reconfiguración que dispara `featuresChanged`.
    const s = storeWith({ ...BASE, features: { selfUpdate: true } });
    const rt = new PolicyRuntime(s.store, null);
    await rt.init();

    s.set({ ...BASE, version: "2", features: { selfUpdate: false } });
    await rt.applyUpdate();

    await (scheduler as any).runUpdate(ctxFor(rt));
    expect(runUpdateTask).not.toHaveBeenCalled();
  });
});
