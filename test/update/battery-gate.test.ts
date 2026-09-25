// test/update/battery-gate.test.ts
//
// Ir con batería no impide actualizar; solo una batería casi agotada y sin
// corriente, porque un apagón a mitad del instalador deja el agente parado.

import { describe, it, expect } from "vitest";
import { batteryBlocksUpdate, UPDATE_MIN_BATTERY_PERCENT } from "../../src/update/battery-gate";

const onBattery = (percent: number | null) => ({
  present: true,
  percent,
  isCharging: false,
  acConnected: false
});

describe("batteryBlocksUpdate", () => {
  it("el límite es el 10 %", () => {
    expect(UPDATE_MIN_BATTERY_PERCENT).toBe(10);
  });

  it("⭐ con batería al 41 % actualiza (W11_JPR_LAB el 25-sep)", () => {
    expect(batteryBlocksUpdate(onBattery(41))).toBeNull();
  });

  it("al 10 % justo todavía actualiza; por debajo, aplaza", () => {
    expect(batteryBlocksUpdate(onBattery(10))).toBeNull();
    expect(batteryBlocksUpdate(onBattery(9))).toBe(9);
    expect(batteryBlocksUpdate(onBattery(0))).toBe(0);
  });

  it("enchufado o cargando nunca aplaza, por baja que esté", () => {
    expect(batteryBlocksUpdate({ ...onBattery(3), acConnected: true })).toBeNull();
    expect(batteryBlocksUpdate({ ...onBattery(3), isCharging: true })).toBeNull();
  });

  it("lo que no sabe no lo bloquea: sin batería, sin porcentaje o sin lectura", () => {
    expect(batteryBlocksUpdate({ present: false, percent: null, isCharging: null, acConnected: null })).toBeNull();
    expect(batteryBlocksUpdate(onBattery(null))).toBeNull();
    expect(batteryBlocksUpdate(undefined)).toBeNull();
  });

  it("si no se sabe si hay corriente, decide la carga", () => {
    expect(batteryBlocksUpdate({ present: true, percent: 5, isCharging: null, acConnected: null })).toBe(5);
  });
});
