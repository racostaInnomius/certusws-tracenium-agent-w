// test/plugins/cdp-partial-store.test.ts
//
// Baja fantasma por fallo parcial de almacen (2026-09-04).
//
// Un keystore Java bloqueado, una base NSS abierta o un login keychain
// de otro usuario hacian que sus certificados faltaran de `items` y el
// diff los mandara como BAJAS, aunque siguieran en disco. El escaneo
// truncado y el fallo total ya estaban protegidos; el fallo PARCIAL no.
//
// Propiedades:
//   1. Almacen ilegible nombrado → solo SUS bajas se retiran del delta y
//      sus certificados se arrastran en la baseline; las bajas de otros
//      almacenes siguen viajando.
//   2. Colector caido sin poder nombrar almacenes (`unscoped`) → NINGUNA
//      baja viaja, como con el recorte.
//   3. El bloque `partial` va al cable, tambien en un baseline completo.
//
// Conduce `collectCDP` DE VERDAD con los colectores y la baseline
// mockeados (misma razon que cdp-truncated-removals.test.ts).

import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from "vitest";
import os from "os";

const computeCdpDelta = vi.fn();
const commitCdpBaseline = vi.fn();
const loadCdpBaselineItemsByStore = vi.fn();
vi.mock("../../src/domain/cdp-baseline-repo", () => ({
  computeCdpDelta: (...a: any[]) => computeCdpDelta(...a),
  commitCdpBaseline: (...a: any[]) => commitCdpBaseline(...a),
  loadCdpBaselineItemsByStore: (...a: any[]) => loadCdpBaselineItemsByStore(...a)
}));

const collectMacosCdp = vi.fn();
vi.mock("../../src/plugins/cdp/providers/macos", () => ({ collectMacosCdp: () => collectMacosCdp() }));
vi.mock("../../src/plugins/cdp/providers/windows", () => ({ collectWindowsCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/linux", () => ({ collectLinuxCdp: vi.fn() }));
const collectJavaStores = vi.fn();
vi.mock("../../src/plugins/cdp/providers/java-stores", () => ({ collectJavaStores: () => collectJavaStores() }));
const collectNssStores = vi.fn();
vi.mock("../../src/plugins/cdp/providers/nss", () => ({ collectNssStores: () => collectNssStores() }));

beforeAll(() => {
  vi.spyOn(os, "platform").mockReturnValue("darwin");
});
afterAll(() => {
  vi.restoreAllMocks();
});

import { collectCDP } from "../../src/plugins/cdp";

const sysStore = { id: "mac/system", name: "System", scope: "machine" as const };
const jksStore = { id: "java:keystore:abc", name: "/opt/app/keystore.jks", scope: "machine" as const };
const item = (id: string, store = sysStore) => ({
  id,
  fingerprint256: id.padStart(64, "0"),
  store,
  source: "store" as const,
  hasPrivateKey: false,
  isCA: false
});

const ctx = {
  config: { agentVersion: "test" },
  logger: { warn: vi.fn(), info: vi.fn() },
  policyRuntime: {
    getCdpJavaKeystorePaths: () => [],
    getCdpCertFilePaths: () => [],
    getCdpScanTlsListeners: () => false,
    getCdpProbeTargets: () => []
  }
} as any;

beforeEach(() => {
  vi.clearAllMocks();
  collectMacosCdp.mockResolvedValue({ items: [item("sys-1")], stores: [sysStore], parseFailures: 0, loginKeychains: { discovered: 0, read: 0 }, unreadable: [] });
  collectNssStores.mockResolvedValue({ items: [], stores: [], parseFailures: 0, unreadable: [], unreadableStores: [] });
});

describe("collectCDP — fallo parcial de almacen", () => {
  it("⭐ almacen ilegible nombrado: sus bajas no viajan, las de otros si, y se arrastra", async () => {
    collectJavaStores.mockResolvedValue({
      items: [],
      stores: [],
      parseFailures: 0,
      storeErrors: [{ store: jksStore.name, message: "unreadable or oversized" }],
      unreadable: [{ id: jksStore.id, name: jksStore.name, reason: "unreadable or oversized" }]
    });
    // La baseline tenia dos del keystore y uno del sistema que si se fue.
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [{ id: "jks-1" }, { id: "jks-2" }, { id: "sys-gone" }] });
    loadCdpBaselineItemsByStore.mockImplementation((match: (s: string) => boolean, present: Set<string>) => {
      expect(match(jksStore.id)).toBe(true);
      expect(match(sysStore.id)).toBe(false);
      expect(present.has("sys-1")).toBe(true);
      return [item("jks-1", jksStore), item("jks-2", jksStore)];
    });

    const ns = await collectCDP(ctx);
    expect(ns.certificates.delta?.removed).toEqual([{ id: "sys-gone" }]);
    expect(ns.partial).toEqual({ unreadableStores: [{ id: jksStore.id, name: jksStore.name, reason: "unreadable or oversized" }], unscoped: [] });
    expect(ns.truncated).toBe(false);
    // La baseline conserva los arrastrados junto a lo visto.
    const committed = commitCdpBaseline.mock.calls[0][0].map((i: any) => i.id).sort();
    expect(committed).toEqual(["jks-1", "jks-2", "sys-1"]);
    expect(ctx.logger.warn).toHaveBeenCalledWith(expect.stringMatching(/escaneo parcial/), expect.objectContaining({ carried: 2 }));
  });

  it("⭐ colector caido sin nombrar almacenes: NINGUNA baja viaja", async () => {
    collectJavaStores.mockRejectedValue(new Error("keytool exploded"));
    computeCdpDelta.mockReturnValue({ added: [item("new")], updated: [], removed: [{ id: "sys-gone" }] });

    const ns = await collectCDP(ctx);
    expect(ns.certificates.delta?.removed).toEqual([]);
    expect(ns.certificates.delta?.added.map((i) => i.id)).toEqual(["new"]);
    expect(ns.partial?.unscoped).toEqual(["java-store: keytool exploded"]);
    expect(loadCdpBaselineItemsByStore).not.toHaveBeenCalled();
  });

  it("almacenes de usuario de Windows no leidos → prefijo `user/`", async () => {
    // Se comprueba la regla de prefijo con el emparejador real: el
    // colector de macOS hace de Windows devolviendo la misma señal.
    collectJavaStores.mockResolvedValue({ items: [], stores: [], parseFailures: 0, storeErrors: [], unreadable: [] });
    collectMacosCdp.mockResolvedValue({ items: [item("sys-1")], stores: [sysStore], parseFailures: 0, loginKeychains: { discovered: 0, read: 0 },
      unreadable: [{ id: "user/", name: "CurrentUser\\\\", reason: "not_supported", prefix: true }] });
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [{ id: "u1" }] });
    loadCdpBaselineItemsByStore.mockImplementation((match: (s: string) => boolean) => {
      expect(match("user/S-1-5-21-1/my")).toBe(true);
      expect(match("lm/my")).toBe(false);
      return [item("u1", { id: "user/S-1-5-21-1/my", name: "CurrentUser\\My (S-1-5-21-1)", scope: "user" })];
    });
    const ns = await collectCDP(ctx);
    // La unica baja era de un almacen no leido: sin bajas ni altas no hay
    // cambios, y un tick sin cambios no lleva delta (la baja no viaja).
    expect(ns.hasChanges).toBe(false);
    expect(ns.certificates.delta).toBeUndefined();
  });

  it("baseline completo con almacen ilegible: `partial` viaja para que el control plane no afirme la ausencia", async () => {
    collectJavaStores.mockResolvedValue({ items: [], stores: [], parseFailures: 0, storeErrors: [], unreadable: [{ id: jksStore.id, name: jksStore.name, reason: "locked" }] });
    computeCdpDelta.mockReturnValue(null);
    loadCdpBaselineItemsByStore.mockReturnValue([]);
    const ns = await collectCDP(ctx);
    expect(ns.certificates.items?.map((i) => i.id)).toEqual(["sys-1"]);
    expect(ns.partial?.unreadableStores[0]).toEqual({ id: jksStore.id, name: jksStore.name, reason: "locked" });
  });

  it("escaneo limpio: sin `partial` y las bajas viajan", async () => {
    collectJavaStores.mockResolvedValue({ items: [], stores: [], parseFailures: 0, storeErrors: [], unreadable: [] });
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [{ id: "sys-gone" }] });
    const ns = await collectCDP(ctx);
    expect(ns.partial).toBeUndefined();
    expect(ns.certificates.delta?.removed).toEqual([{ id: "sys-gone" }]);
    expect(loadCdpBaselineItemsByStore).not.toHaveBeenCalled();
  });

  it("«path not found» de un keystore configurado NO es ilegible: sus bajas son reales", async () => {
    // El provider no lo pone en `unreadable`; aqui se fija el contrato
    // desde el lado del colector: solo `unreadable` suprime.
    collectJavaStores.mockResolvedValue({ items: [], stores: [], parseFailures: 0, storeErrors: [{ store: "/gone.jks", message: "path not found" }], unreadable: [] });
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [{ id: "jks-1" }] });
    const ns = await collectCDP(ctx);
    expect(ns.certificates.delta?.removed).toEqual([{ id: "jks-1" }]);
    expect(ns.partial).toBeUndefined();
  });
});
