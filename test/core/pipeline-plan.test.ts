// test/core/pipeline-plan.test.ts

import { describe, expect, it } from "vitest";
import {
  capabilitySignature,
  diffPipelinePlan,
  readPipelinePlan,
  type PipelinePlan,
  type PlanSource,
} from "../../src/core/pipeline-plan";

function source(over: Partial<Record<string, any>> = {}): PlanSource {
  const plugins: string[] = over.plugins ?? ["amp", "scp", "pmp", "cdp"];
  return {
    isInventoryEnabled: () => over.inventory ?? true,
    isUpdateEnabled: () => over.update ?? true,
    isComplianceEnabled: () => over.compliance ?? true,
    isPatchEnabled: () => over.patch ?? true,
    pluginEnabled: (k) => plugins.includes(k),
    getInventoryInterval: () => 21600,
    getUpdateInterval: () => 21600,
    getComplianceInterval: () => 3600,
    getCdpInterval: () => 43200,
    getPatchInterval: () => over.patchInterval ?? 86400,
  };
}

const plan = (over = {}): PipelinePlan => readPipelinePlan(source(over));

describe("diffPipelinePlan", () => {
  it("🔴 la misma policy otra vez → nada que re-armar ni que correr", () => {
    expect(diffPipelinePlan(plan(), plan())).toEqual({ rearm: [], runNow: [] });
  });

  it("sin plan previo (arranque) → todo lo armado se arma y lo efectivo corre", () => {
    const d = diffPipelinePlan(null, plan({ update: false }));
    expect(d.rearm).toEqual(["inventory", "update", "compliance", "cdp", "patch"]);
    expect(d.runNow).toEqual(["inventory", "compliance", "cdp", "patch"]);
  });

  it("cambiar un intervalo re-arma ESE pipeline y no lo corre", () => {
    expect(diffPipelinePlan(plan(), plan({ patchInterval: 43200 }))).toEqual({ rearm: ["patch"], runNow: [] });
  });

  it("⭐ activar el plugin con el módulo ya activo: corre ya, sin re-armar", () => {
    // El temporizador ya estaba armado por el módulo; lo nuevo es que ahora hará trabajo.
    const d = diffPipelinePlan(plan({ plugins: ["amp", "scp", "cdp"] }), plan());
    expect(d).toEqual({ rearm: [], runNow: ["patch"] });
  });

  it("apagar un pipeline lo re-arma (para pararlo) y no corre nada", () => {
    expect(diffPipelinePlan(plan(), plan({ plugins: ["amp", "scp", "pmp"] }))).toEqual({ rearm: ["cdp"], runNow: [] });
  });

  it("el intervalo de un pipeline desarmado no cuenta", () => {
    const a = plan({ patch: false, patchInterval: 100 });
    const b = plan({ patch: false, patchInterval: 200 });
    expect(diffPipelinePlan(a, b)).toEqual({ rearm: [], runNow: [] });
  });
});

describe("readPipelinePlan", () => {
  it("⚠️ effective exige el plugin igual que el guard de cada run*()", () => {
    const p = plan({ plugins: [] });
    expect(p.inventory).toMatchObject({ armed: true, effective: false });
    expect(p.compliance).toMatchObject({ armed: true, effective: false });
    expect(p.patch).toMatchObject({ armed: true, effective: false });
    expect(p.cdp).toMatchObject({ armed: false, effective: false });
    expect(p.update).toMatchObject({ armed: true, effective: true });
  });
});

describe("capabilitySignature", () => {
  it("no depende del orden", () => {
    expect(capabilitySignature(["pmp", "amp"], ["patch", "inventory"])).toBe(
      capabilitySignature(["amp", "pmp"], ["inventory", "patch"])
    );
    expect(capabilitySignature(["amp"], [])).not.toBe(capabilitySignature(["amp", "pmp"], []));
  });
});
