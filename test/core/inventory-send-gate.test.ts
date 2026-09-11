import { describe, it, expect } from "vitest";
import { decideFactsSend, MAX_INVENTORY_SILENCE_MS } from "../../src/core/inventory-send-gate";

// ADR-0020 F2 — el tercer disparador del envío de inventario.
//
// Sin él, un equipo con el software quieto no mandaba NADA durante días (hueco
// mediano de 3,6 días en T111) y el servidor no podía distinguir «estable» de
// «apagado». Estos casos fijan que el latido sale cuando toca y NO antes: si
// saliera en cada tick, cada equipo mandaría un mensaje cada ciclo para nada.

const NOW = Date.parse("2026-09-11T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const quiet = { hasAnyChanges: false, forceInitialSnapshot: false, versionChanged: false };

describe("sin cambios", () => {
  it("se calla si el último envío es reciente", () => {
    const g = decideFactsSend({ ...quiet, lastSentAtMs: NOW - 2 * HOUR, nowMs: NOW });
    expect(g.send).toBe(false);
  });

  it("⚠️ pero manda un latido pasadas 24 h de silencio", () => {
    // ESTE es el cambio. Sin él, el portátil estable callaba indefinidamente.
    const g = decideFactsSend({ ...quiet, lastSentAtMs: NOW - 25 * HOUR, nowMs: NOW });
    expect(g.send).toBe(true);
    expect(g.reasons).toEqual(["silence"]);
  });

  it("y no antes: a las 23 h sigue callado", () => {
    // El latido es un mensaje al día, no uno por tick.
    const g = decideFactsSend({ ...quiet, lastSentAtMs: NOW - 23 * HOUR, nowMs: NOW });
    expect(g.send).toBe(false);
  });

  it("la frontera es exactamente 24 h", () => {
    expect(MAX_INVENTORY_SILENCE_MS).toBe(24 * HOUR);
    expect(decideFactsSend({ ...quiet, lastSentAtMs: NOW - MAX_INVENTORY_SILENCE_MS, nowMs: NOW }).send).toBe(false);
    expect(decideFactsSend({ ...quiet, lastSentAtMs: NOW - MAX_INVENTORY_SILENCE_MS - 1, nowMs: NOW }).send).toBe(true);
  });
});

describe("marcas raras cuentan como vencidas", () => {
  it("sin marca previa (agente recién actualizado) → manda", () => {
    for (const last of [null, undefined, NaN, 0]) {
      expect(decideFactsSend({ ...quiet, lastSentAtMs: last as any, nowMs: NOW }).send, String(last)).toBe(true);
    }
  });

  it("⚠️ una marca en el FUTURO (el reloj saltó hacia atrás) → manda", () => {
    // Esperar a que el reloj alcance la marca podría ser días de silencio, que
    // es exactamente lo que esto viene a evitar.
    const g = decideFactsSend({ ...quiet, lastSentAtMs: NOW + 5 * HOUR, nowMs: NOW });
    expect(g.send).toBe(true);
  });
});

describe("los disparadores de siempre siguen igual", () => {
  it("con cambios manda, aunque el último envío sea de hace un minuto", () => {
    const g = decideFactsSend({ ...quiet, hasAnyChanges: true, lastSentAtMs: NOW - 60_000, nowMs: NOW });
    expect(g.send).toBe(true);
    expect(g.reasons).toEqual(["changes"]);
  });

  it("arranque y cambio de versión mandan igual que antes", () => {
    expect(decideFactsSend({ ...quiet, forceInitialSnapshot: true, lastSentAtMs: NOW, nowMs: NOW }).reasons).toEqual(["initial"]);
    expect(decideFactsSend({ ...quiet, versionChanged: true, lastSentAtMs: NOW, nowMs: NOW }).reasons).toEqual(["version"]);
  });
});
