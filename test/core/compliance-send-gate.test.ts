import { describe, it, expect } from "vitest";
import { decideComplianceSend, MAX_COMPLIANCE_SILENCE_MS } from "../../src/core/compliance-send-gate";

// P3-11 — el latido diario de cumplimiento. Sin él, un equipo estable no dejaba
// snapshot durante días. Estos casos fijan que sale cuando toca y NO en cada
// ciclo: cada 8 h un mensaje igual al anterior sería ruido.

const NOW = Date.parse("2026-09-17T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;

describe("decideComplianceSend", () => {
  it("con cambios, siempre", () => {
    expect(decideComplianceSend({ hasChanges: true, lastSentAtMs: NOW - HOUR, nowMs: NOW })).toEqual({ send: true, reasons: ["changes"] });
  });

  it("sin cambios y envío reciente, se calla", () => {
    expect(decideComplianceSend({ hasChanges: false, lastSentAtMs: NOW - 8 * HOUR, nowMs: NOW }).send).toBe(false);
    expect(decideComplianceSend({ hasChanges: false, lastSentAtMs: NOW - MAX_COMPLIANCE_SILENCE_MS, nowMs: NOW }).send).toBe(false);
  });

  it("sin cambios y más de 24 h de silencio, latido", () => {
    expect(decideComplianceSend({ hasChanges: false, lastSentAtMs: NOW - MAX_COMPLIANCE_SILENCE_MS - 1, nowMs: NOW })).toEqual({ send: true, reasons: ["silence"] });
  });

  it("sin marca previa o con una marca en el futuro, cuenta como vencido", () => {
    for (const lastSentAtMs of [null, undefined, NaN, 0, NOW + HOUR]) {
      expect(decideComplianceSend({ hasChanges: false, lastSentAtMs, nowMs: NOW }).send).toBe(true);
    }
  });
});
