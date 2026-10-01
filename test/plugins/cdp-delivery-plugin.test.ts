// test/plugins/cdp-delivery-plugin.test.ts
//
// El plugin de CDP no escribe «lo que el control plane ya tiene» al
// recoger: lo deja en un paquete pegado al namespace, que se aplica con el
// ACK_OK del envío. Y un agente que nunca ha visto una entrega confirmada
// manda la lista completa — la que tienen los equipos cuya base afirmaba
// certificados que no llegaron (2026-10-01: 5 equipos, 500–2000 cada uno).

import os from "os";
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from "vitest";

const computeCdpDelta = vi.fn();
const commitCdpBaseline = vi.fn();
let acked = true;

vi.mock("../../src/domain/cdp-baseline-repo", () => ({
  computeCdpDelta: (...a: any[]) => computeCdpDelta(...a),
  commitCdpBaseline: (...a: any[]) => commitCdpBaseline(...a),
  isCdpDeliveryAcked: () => acked
}));

const collectMacosCdp = vi.fn();
vi.mock("../../src/plugins/cdp/providers/macos", () => ({ collectMacosCdp: () => collectMacosCdp() }));
vi.mock("../../src/plugins/cdp/providers/windows", () => ({ collectWindowsCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/linux", () => ({ collectLinuxCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/java-stores", () => ({
  collectJavaStores: async () => ({ items: [], stores: [], parseFailures: 0 })
}));

// Mismo motivo que en cdp-truncated-removals.test.ts: el spy sobre el
// objeto compartido prende; vi.mock("os") no de forma fiable.
beforeAll(() => {
  vi.spyOn(os, "platform").mockReturnValue("darwin");
});
afterAll(() => {
  vi.restoreAllMocks();
});

import { collectCDP } from "../../src/plugins/cdp";
import { peekCdpDelivery } from "../../src/domain/cdp-delivery";

const store = { id: "mac/system", name: "System", scope: "machine" as const };
const items = (n: number) =>
  Array.from({ length: n }, (_, i) => ({
    id: `cert-${i}`,
    fingerprint256: String(i).padStart(64, "0"),
    store,
    source: "store" as const,
    hasPrivateKey: false,
    isCA: false,
    notBefore: "2026-01-01T00:00:00.000Z",
    notAfter: "2027-01-01T00:00:00.000Z"
  }));

const ctx = {
  config: { agentVersion: "test" },
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn() },
  policyRuntime: {
    getCdpScanTlsListeners: () => false,
    getCdpJavaKeystorePaths: () => [],
    getCdpCertFilePaths: () => []
  }
} as any;

beforeEach(() => {
  vi.clearAllMocks();
  acked = true;
});

describe("CDP: la línea base se mueve con el ACK, no al recoger", () => {
  it("⭐ recoger NO escribe la base; el paquete viaja pegado al namespace", async () => {
    collectMacosCdp.mockResolvedValue({ items: items(3), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue({ added: [items(3)[2]], removed: [], updated: [] });

    const ns: any = await collectCDP(ctx);

    expect(commitCdpBaseline).not.toHaveBeenCalled();
    expect(ns.hasChanges).toBe(true);
    expect(peekCdpDelivery(ns)?.baseline.map((i) => i.id)).toEqual(["cert-0", "cert-1", "cert-2"]);
    // …y no viaja en el payload.
    expect(JSON.stringify(ns)).not.toContain('"baseline"');
  });

  it("sin cambios no hay envío, y no hay nada que aplicar", async () => {
    collectMacosCdp.mockResolvedValue({ items: items(3), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue({ added: [], removed: [], updated: [] });

    const ns: any = await collectCDP(ctx);

    expect(ns.hasChanges).toBe(false);
    expect(peekCdpDelivery(ns)).toBeUndefined();
  });

  it("⭐ un agente sin ninguna entrega confirmada manda la lista COMPLETA, aunque su base diga que no hay cambios", async () => {
    // TNS-OPER-JMARV: la base local decía 2000, el servidor tenía 2.
    acked = false;
    collectMacosCdp.mockResolvedValue({ items: items(5), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue({ added: [], removed: [], updated: [] });

    const ns: any = await collectCDP(ctx);

    expect(computeCdpDelta).not.toHaveBeenCalled();
    expect(ns.hasChanges).toBe(true);
    expect(ns.certificates.items).toHaveLength(5);
    expect(peekCdpDelivery(ns)?.baseline).toHaveLength(5);
  });

  it("con entregas ya confirmadas, el tick vuelve a ser incremental", async () => {
    collectMacosCdp.mockResolvedValue({ items: items(5), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue({ added: [items(5)[4]], removed: [], updated: [] });

    const ns: any = await collectCDP(ctx);

    expect(ns.certificates.items).toBeUndefined();
    expect(ns.certificates.delta.added).toHaveLength(1);
  });
});
