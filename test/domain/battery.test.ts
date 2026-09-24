import { describe, it, expect } from "vitest";
import { normalizeBattery } from "../../src/domain/battery";

describe("normalizeBattery", () => {
  it("portátil: presencia, carga redondeada y alimentación", () => {
    expect(normalizeBattery({ hasBattery: true, percent: 63.6, isCharging: true, acConnected: true }))
      .toEqual({ present: true, percent: 64, isCharging: true, acConnected: true });
  });

  it("sobremesa: `present: false` es una respuesta, no un hueco", () => {
    expect(normalizeBattery({ hasBattery: false, percent: 0, acConnected: true }))
      .toEqual({ present: false, percent: null, isCharging: null, acConnected: true });
  });

  it("no leído (null, o sin hasBattery) → undefined", () => {
    expect(normalizeBattery(null)).toBeUndefined();
    expect(normalizeBattery({ percent: 50 })).toBeUndefined();
  });

  it("una carga fuera de rango es basura del driver, no una carga", () => {
    expect(normalizeBattery({ hasBattery: true, percent: 255 })?.percent).toBeNull();
    expect(normalizeBattery({ hasBattery: true, percent: "" })?.percent).toBeNull();
    expect(normalizeBattery({ hasBattery: true, percent: 0 })?.percent).toBe(0);
  });
});
