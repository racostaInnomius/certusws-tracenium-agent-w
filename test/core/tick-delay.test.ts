// Cuándo corre el siguiente tick.
//
// ⚠️ Este cálculo existe porque su ausencia se vio en producción: dos Macs
// actualizadas seguían mostrándose con la versión vieja media hora después. El
// agente correcto ya estaba corriendo — faltaba el snapshot, y ése sólo sale en
// el tick de inventario, que por defecto es cada seis horas.

import { describe, it, expect } from "vitest";
import { computeTickDelay } from "../../src/core/scheduler";

const SEIS_HORAS = 21600 * 1000;

describe("computeTickDelay — régimen normal", () => {
  it("espera el intervalo completo más el jitter estrecho", () => {
    expect(
      computeTickDelay({ baseIntervalMs: SEIS_HORAS, jitterRangeMs: 30000, random: () => 0 })
    ).toBe(SEIS_HORAS);
    expect(
      computeTickDelay({ baseIntervalMs: SEIS_HORAS, jitterRangeMs: 30000, random: () => 0.999 })
    ).toBeLessThan(SEIS_HORAS + 30000);
  });
});

describe("computeTickDelay — primer tick", () => {
  it("⚠️ NO espera seis horas: arranca en menos de un minuto", () => {
    // Éste es el fallo que se corrige. Sin firstDelayMs el portal muestra la
    // versión vieja hasta seis horas después de una actualización.
    const d = computeTickDelay({
      baseIntervalMs: SEIS_HORAS,
      jitterRangeMs: 30000,
      firstDelayMs: 45000,
      random: () => 0,
    });
    expect(d).toBe(45000);
    expect(d).toBeLessThan(60_000);
  });

  it("⚠️ se reparte en una ventana ANCHA, no en la de 30 s", () => {
    // Una actualización de flota reinicia muchos agentes casi a la vez. Si
    // todos mandaran su snapshot dentro de la misma ventana de 30 s, arreglar
    // un dato viejo crearía una tormenta contra el backend.
    const d = computeTickDelay({
      baseIntervalMs: SEIS_HORAS,
      jitterRangeMs: 30000,
      firstDelayMs: 45000,
      random: () => 0.999,
    });
    expect(d).toBeGreaterThan(45000 + 30000);
    expect(d).toBeLessThanOrEqual(45000 + 5 * 60 * 1000);
  });

  it("el reparto real cubre la ventana entera", () => {
    const muestras = Array.from({ length: 200 }, (_, i) =>
      computeTickDelay({
        baseIntervalMs: SEIS_HORAS,
        jitterRangeMs: 30000,
        firstDelayMs: 45000,
        random: () => i / 200,
      })
    );
    expect(Math.min(...muestras)).toBe(45000);
    expect(Math.max(...muestras)).toBeGreaterThan(45000 + 4 * 60 * 1000);
  });

  it("firstDelayMs de 0 sigue contando como primer tick", () => {
    // 0 es un valor legítimo y NO debe confundirse con 'no hay primer tick':
    // `firstDelayMs ?? base` con 0 funcionaría, pero un `||` lo habría roto.
    const d = computeTickDelay({
      baseIntervalMs: SEIS_HORAS,
      jitterRangeMs: 30000,
      firstDelayMs: 0,
      random: () => 0,
    });
    expect(d).toBe(0);
  });
});
