// test/plugins/cdp-on-demand.test.ts
//
// Recolección CDP bajo demanda: el escaneo forzado y su carril.
//
// Hasta ahora el único que llamaba a `collectCDP` era el scheduler, cada
// 12h, y sostenía su propio mutex `cdpRunning`. La ruta bajo demanda
// añade una SEGUNDA entrada, y eso cambia dos cosas que estos tests
// fijan:
//
//   1. El escaneo forzado manda el inventario COMPLETO, no un delta. Un
//      delta vacío respondería "no ha cambiado nada" a quien preguntó
//      "qué hay en este equipo", y un snapshot que no dice nada no se
//      distingue de uno que falló.
//   2. `collectOnce` COMMITEA la baseline, así que dos escaneos
//      solapados se corrompen mutuamente: el segundo diffea contra una
//      baseline que el primero ya reemplazó. El carril vive ahora en el
//      plugin —dueño de la baseline— y no en el llamante.
//
// ⚠️ Como en cdp-truncated-removals.test.ts, esto conduce `collectCDP`
// DE VERDAD con los colectores y la baseline mockeados. Comprobar una
// copia local de la regla pasaría con el código borrado.

import os from "os";
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from "vitest";

const computeCdpDelta = vi.fn();
const commitCdpBaseline = vi.fn();

vi.mock("../../src/domain/cdp-baseline-repo", () => ({
  computeCdpDelta: (...a: any[]) => computeCdpDelta(...a),
  commitCdpBaseline: (...a: any[]) => commitCdpBaseline(...a)
}));

const collectMacosCdp = vi.fn();
vi.mock("../../src/plugins/cdp/providers/macos", () => ({
  collectMacosCdp: () => collectMacosCdp()
}));
vi.mock("../../src/plugins/cdp/providers/windows", () => ({ collectWindowsCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/linux", () => ({ collectLinuxCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/java-stores", () => ({
  collectJavaStores: async () => ({ items: [], stores: [], parseFailures: 0 })
}));

// Mismo motivo que en cdp-truncated-removals.test.ts: vi.mock("os") no
// prende de forma fiable aquí; el spy sobre el objeto compartido sí.
beforeAll(() => {
  vi.spyOn(os, "platform").mockReturnValue("darwin");
});
afterAll(() => {
  vi.restoreAllMocks();
});

import { collectCDP } from "../../src/plugins/cdp";

const store = { id: "mac/system", name: "System", scope: "machine" as const };

const items = (n: number, offset = 0) =>
  Array.from({ length: n }, (_, i) => ({
    id: `cert-${i + offset}`,
    fingerprint256: String(i + offset).padStart(64, "0"),
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
  commitCdpBaseline.mockReturnValue(undefined);
});

describe("collectCDP — escaneo forzado (full)", () => {
  it("manda el inventario completo aunque no haya cambiado nada", async () => {
    collectMacosCdp.mockResolvedValue({ items: items(30), stores: [store], parseFailures: 0 });
    // Un delta vacío es justo el caso que rompía la ruta bajo demanda:
    // el operador pide un escaneo y no recibe ni un certificado.
    computeCdpDelta.mockReturnValue({ added: [], removed: [], updated: [] });

    const ns: any = await collectCDP(ctx, { full: true });

    expect(ns.hasChanges).toBe(true);
    expect(ns.certificates.items).toHaveLength(30);
    expect(ns.certificates.delta).toBeUndefined();
  });

  it("ni siquiera calcula el delta — lo salta, no lo descarta", async () => {
    // La diferencia importa: descartarlo dejaría el coste del diff y, más
    // grave, una segunda lectura de la baseline cuyo resultado se ignora.
    collectMacosCdp.mockResolvedValue({ items: items(5), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue({ added: [], removed: [], updated: [] });

    await collectCDP(ctx, { full: true });

    expect(computeCdpDelta).not.toHaveBeenCalled();
  });

  it("COMMITEA la baseline, para que el siguiente tick programado diffee bien", async () => {
    // Si un escaneo forzado no commiteara, el tick de las 12h volvería a
    // reportar como altas todo lo que el forzado ya mandó.
    collectMacosCdp.mockResolvedValue({ items: items(7), stores: [store], parseFailures: 0 });

    await collectCDP(ctx, { full: true });

    expect(commitCdpBaseline).toHaveBeenCalledTimes(1);
    expect(commitCdpBaseline.mock.calls[0][0]).toHaveLength(7);
  });

  it("sin `full` sigue siendo incremental — el tick programado no cambia", async () => {
    collectMacosCdp.mockResolvedValue({ items: items(30), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue({ added: [{ id: "nuevo" }], removed: [], updated: [] });

    const ns: any = await collectCDP(ctx);

    expect(computeCdpDelta).toHaveBeenCalledTimes(1);
    expect(ns.certificates.items).toBeUndefined();
    expect(ns.certificates.delta.added).toHaveLength(1);
  });
});

describe("collectCDP — carril de serialización", () => {
  it("no solapa dos escaneos: el segundo espera a que el primero termine", async () => {
    // El daño de solapar es silencioso: el segundo diffea contra una
    // baseline ya reemplazada, así que un certificado NUEVO se lee como
    // sin cambios y desaparece del cable hasta que algo más lo mueva.
    let liberaPrimero: (v: any) => void = () => {};
    const primero = new Promise((resolve) => { liberaPrimero = resolve; });

    collectMacosCdp
      .mockImplementationOnce(() => primero)
      .mockImplementationOnce(async () => ({ items: items(2), stores: [store], parseFailures: 0 }));
    computeCdpDelta.mockReturnValue(null);

    const a = collectCDP(ctx, { full: true });
    const b = collectCDP(ctx, { full: true });

    // Con el primero aún en vuelo, el colector NO puede haber corrido dos veces.
    await Promise.resolve();
    await Promise.resolve();
    expect(collectMacosCdp).toHaveBeenCalledTimes(1);

    liberaPrimero({ items: items(1), stores: [store], parseFailures: 0 });
    const [nsA, nsB] = await Promise.all([a, b]);

    expect(collectMacosCdp).toHaveBeenCalledTimes(2);
    // Cada llamante recibe SU propio resultado. Compartir el del primero
    // sería más barato y rompería el contrato de `full`.
    expect((nsA as any).certificates.count).toBe(1);
    expect((nsB as any).certificates.count).toBe(2);
  });

  it("un escaneo que falla no envenena el carril", async () => {
    // Si el carril arrastrara el rechazo, un único fallo dejaría CDP
    // muerto hasta reiniciar el agente.
    collectMacosCdp
      .mockImplementationOnce(async () => { throw new Error("colector caído"); })
      .mockImplementationOnce(async () => ({ items: items(3), stores: [store], parseFailures: 0 }));
    computeCdpDelta.mockReturnValue(null);

    const primero: any = await collectCDP(ctx, { full: true });
    // El colector captura su propio fallo y lo reporta como collectorError,
    // no como rechazo — pero el carril debe aguantar ambas formas.
    expect(primero.collectorError).toBeTruthy();

    const segundo: any = await collectCDP(ctx, { full: true });
    expect(segundo.certificates.count).toBe(3);
  });
});
