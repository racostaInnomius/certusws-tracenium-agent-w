// test/update/schtasks-start-time.test.ts
//
// La hora que se le pasa a `schtasks /st` decide si el update ocurre o si se
// programa para MAÑANA.
//
// schtasks solo acepta HH:mm, así que truncar pierde hasta 59 segundos. Con
// un margen de 60s la espera real quedaba entre 1 y 60 segundos, y en el
// extremo bajo el minuto objetivo ya había pasado cuando la tarea se
// registraba: `/sc ONCE` con hora pasada la manda a mañana. El agente daba el
// update por lanzado, la marca caducaba, reintentaba, y así en bucle — que es
// lo que se vio en un equipo atascado en 1.1.56.

import { describe, it, expect } from "vitest";

/** La misma cuenta que hace updater-runner.ts. */
function startTimeFor(nowMs: number, marginMs: number): Date {
  const at = new Date(nowMs + marginMs);
  const truncated = new Date(at);
  truncated.setSeconds(0, 0);
  return truncated;
}

/** Segundos entre `now` y la hora que realmente arrancaría la tarea. */
function delaySeconds(nowMs: number, marginMs: number): number {
  return (startTimeFor(nowMs, marginMs).getTime() - nowMs) / 1000;
}

describe("margen de arranque de schtasks", () => {
  // Se recorre el minuto entero, segundo a segundo: el fallo dependía de en
  // qué segundo del minuto caía la llamada, así que un solo caso no lo habría
  // encontrado.
  const base = Date.parse("2026-09-01T11:00:00Z");
  const seconds = Array.from({ length: 60 }, (_, i) => base + i * 1000);

  it("con 60s de margen, en algún segundo la tarea queda casi en el pasado", () => {
    // El bug. No se comprueba para conservarlo, sino para dejar constancia de
    // por qué el margen ya no es 60.
    const worst = Math.min(...seconds.map((n) => delaySeconds(n, 60_000)));
    expect(worst).toBeLessThanOrEqual(1);
  });

  it("con 90s de margen NUNCA queda por debajo de 30 segundos", () => {
    for (const n of seconds) {
      const d = delaySeconds(n, 90_000);
      expect(d, `en ${new Date(n).toISOString()}`).toBeGreaterThanOrEqual(30);
      expect(d).toBeLessThanOrEqual(90);
    }
  });

  it("y nunca en el pasado, que es lo único imperdonable", () => {
    for (const n of seconds) {
      expect(delaySeconds(n, 90_000)).toBeGreaterThan(0);
    }
  });
});
