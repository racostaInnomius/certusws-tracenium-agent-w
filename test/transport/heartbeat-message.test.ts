// test/transport/heartbeat-message.test.ts

import { describe, it, expect } from "vitest";
import os from "os";
import { buildHeartbeat } from "../../src/transport/heartbeat-message";

const base = { deviceId: "827ccdb4", tenantId: "111", agentVersion: "1.1.71", nowMs: 1_789_000_000_000 };

describe("buildHeartbeat", () => {
  it("⭐ lleva el uptime de la MÁQUINA para que el backend derive el arranque", () => {
    // Sin este campo, «¿volvió del reinicio?» sólo podía responderse con
    // «visto después del parche», que el 12-sep se cumplió con MSIG-TSPDC
    // todavía sin reiniciar.
    const hb = buildHeartbeat({ ...base, readUptime: () => 56.7 });
    expect(hb.uptimeSeconds).toBe(56);
    expect(hb).toMatchObject({ deviceId: "827ccdb4", tenantId: "111", agentVersion: "1.1.71", ts: base.nowMs });
  });

  it("⚠️ por defecto lee os.uptime(), no process.uptime()", () => {
    // Con el del proceso, cada reciclaje del AgentCore parecería un reinicio.
    const hb = buildHeartbeat(base);
    const machine = Math.floor(os.uptime());
    expect(hb.uptimeSeconds).toBeGreaterThanOrEqual(machine - 1);
    expect(hb.uptimeSeconds).toBeLessThanOrEqual(machine + 1);
  });

  it("sin un valor positivo omite el campo: en proto3 un 0 no dice nada", () => {
    for (const raw of [0, -3, null, undefined, "", "abc", Number.NaN]) {
      expect(buildHeartbeat({ ...base, readUptime: () => raw })).not.toHaveProperty("uptimeSeconds");
    }
  });

  it("un fallo leyendo el contador no tumba el heartbeat", () => {
    const hb = buildHeartbeat({
      ...base,
      readUptime: () => {
        throw new Error("EPERM");
      },
    });
    expect(hb.deviceId).toBe("827ccdb4");
    expect(hb).not.toHaveProperty("uptimeSeconds");
  });
});
