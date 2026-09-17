// test/plugins/pmp-windows-reboot-pending.test.ts
//
// Reinicio pendiente en Windows: leído en vivo, no heredado de la instalación.
//
// ⚠️ EL FALLO (T111, 17-sep): el agente reenviaba la marca `rebootRequired`
// que dejó la última instalación en pmp-state.json, y nada la borraba al
// reiniciar. Contrastado a mano en los 6 servidores marcados con WUA
// SystemInfo.RebootRequired + CBS RebootPending + WU Auto Update RebootRequired:
// MSIG-DOMAIN01, MSIG-FILESHARE, MSIG-TSPDC y MSIG-WSUS ya habían reiniciado y
// el portal decía «reboot pending»; MSIG-VEEAM-SRV y MSIG-DOMAIN sí lo estaban.

import { beforeEach, describe, expect, it, vi } from "vitest";

const pmpStateRef: { value: any } = { value: {} };
vi.mock("../../src/plugins/pmp/state", () => ({
  loadPmpState: vi.fn(() => pmpStateRef.value),
  savePmpState: vi.fn(),
  updatePmpState: vi.fn(),
  tryStartRemediate: vi.fn(() => true),
  finishRemediate: vi.fn(),
  isRemediateInFlight: vi.fn(() => false)
}));

import { collectWindowsPmp, resolveWindowsRebootPending } from "../../src/plugins/pmp/providers/windows";

function ctxWith(result: any) {
  return {
    config: { agentVersion: "test" },
    enrollment: { tenantId: "t", deviceId: "d" },
    priv: { call: vi.fn(async () => ({ ok: true, result })) },
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  } as any;
}

/** Uptime que sitúa el arranque en `bootIso`. */
const uptimeSince = (bootIso: string) => () => (Date.now() - Date.parse(bootIso)) / 1000;

// La marca que dejó la instalación de MSIG-DOMAIN01 (17-sep).
const DOMAIN01_STATE = { status: "success", rebootRequired: true, finishedAtUtc: "2026-09-17T03:26:25.629Z", installedCount: 2 };

beforeEach(() => {
  pmpStateRef.value = {};
});

describe("collectWindowsPmp — reinicio pendiente", () => {
  it("🔴 MSIG-DOMAIN01: el PrivSvc lee Windows (no pendiente) → healthy, aunque la marca diga true", async () => {
    pmpStateRef.value = DOMAIN01_STATE;
    const ns = await collectWindowsPmp(
      ctxWith({ status: "healthy", items: [], rebootPending: false, rebootSignals: { wua: false, cbs: false, wu: false } }),
      uptimeSince("2026-09-17T03:30:45Z")
    );
    expect(ns.overall.status).toBe("healthy");
    expect(ns.scan?.rebootPending).toBe(false);
    // El histórico de la instalación se sigue mandando tal cual.
    expect(ns.remediation?.rebootRequired).toBe(true);
  });

  it("✅ MSIG-DOMAIN: Windows dice pendiente → reboot_required", async () => {
    pmpStateRef.value = { status: "success", rebootRequired: true, finishedAtUtc: "2026-09-15T15:42:41.727Z" };
    const ns = await collectWindowsPmp(
      ctxWith({ status: "updates_available", items: [], rebootPending: true }),
      uptimeSince("2026-08-16T04:57:08Z")
    );
    expect(ns.overall.status).toBe("reboot_required");
    expect(ns.scan?.rebootPending).toBe(true);
  });

  it("⭐ un reinicio pendiente que NO dejó Tracenium (WSUS, el usuario) también se ve", async () => {
    // Sin marca de instalación: antes esto era siempre «no pendiente».
    const ns = await collectWindowsPmp(ctxWith({ status: "healthy", items: [], rebootPending: true }), uptimeSince("2026-09-01T00:00:00Z"));
    expect(ns.overall.status).toBe("reboot_required");
  });

  it("PrivSvc anterior (sin rebootPending): la máquina arrancó después de instalar → no pendiente, y no se inventa el campo", async () => {
    pmpStateRef.value = DOMAIN01_STATE;
    const ns = await collectWindowsPmp(ctxWith({ status: "healthy", items: [] }), uptimeSince("2026-09-17T03:30:45Z"));
    expect(ns.overall.status).toBe("healthy");
    expect(ns.scan).not.toHaveProperty("rebootPending");
  });

  it("PrivSvc anterior y sin arranque posterior → se respeta la marca", async () => {
    pmpStateRef.value = { status: "success", rebootRequired: true, finishedAtUtc: "2026-09-13T18:00:48.992Z" };
    const ns = await collectWindowsPmp(ctxWith({ status: "healthy", items: [] }), uptimeSince("2026-09-12T18:50:35Z"));
    expect(ns.overall.status).toBe("reboot_required");
  });
});

describe("resolveWindowsRebootPending", () => {
  const boot = Date.parse("2026-09-17T04:00:00Z");
  it("la lectura en vivo manda, en los dos sentidos", () => {
    expect(resolveWindowsRebootPending({ live: false, remediation: { rebootRequired: true }, bootAtMs: 0 })).toBe(false);
    expect(resolveWindowsRebootPending({ live: true, remediation: null, bootAtMs: boot })).toBe(true);
  });
  it("⚠️ un valor en vivo que no es booleano no cuenta como respuesta", () => {
    expect(resolveWindowsRebootPending({ live: "false", remediation: { rebootRequired: true }, bootAtMs: NaN })).toBe(true);
  });
  it("sin fecha de fin de la instalación se respeta la marca", () => {
    expect(resolveWindowsRebootPending({ live: undefined, remediation: { rebootRequired: true }, bootAtMs: boot })).toBe(true);
  });
});
