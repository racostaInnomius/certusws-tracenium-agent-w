// test/plugins/cdp-truncated-removals.test.ts
//
// Un escaneo recortado no puede afirmar que algo se eliminó.
//
// `applyCap` descarta los certificados de menor prioridad cuando un
// equipo supera MAX_ITEMS y marca `truncated`. Lo descartado falta de
// `items` estando perfectamente presente en el disco, así que el diff
// contra la baseline lo ve como una baja — y lo volvería a reportar como
// baja en CADA escaneo, precisamente en los hosts con más certificados.
//
// El control plane también se niega a actuar sobre bajas de un payload
// truncado, pero el agente es donde la incompletitud se CONOCE: una
// afirmación que nadie aguas abajo puede creer no tiene por qué viajar.
//
// ⚠️ Estos tests conducen `collectCDP` DE VERDAD, con los colectores y la
// baseline mockeados. Una versión anterior comprobaba una copia local de
// la regla y habría pasado con la línea borrada del código — el mismo
// error de fake-que-reimplementa-la-lógica que ya se cometió tres veces
// en este repo.

import { describe, it, expect, vi, beforeEach } from "vitest";

const computeCdpDelta = vi.fn();
const commitCdpBaseline = vi.fn();

vi.mock("../../src/domain/cdp-baseline-repo", () => ({
  computeCdpDelta: (...a: any[]) => computeCdpDelta(...a),
  commitCdpBaseline: (...a: any[]) => commitCdpBaseline(...a)
}));

// El host de CI es macOS; se fija el colector de esa plataforma.
const collectMacosCdp = vi.fn();
vi.mock("../../src/plugins/cdp/providers/macos", () => ({
  collectMacosCdp: () => collectMacosCdp()
}));
vi.mock("../../src/plugins/cdp/providers/windows", () => ({ collectWindowsCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/linux", () => ({ collectLinuxCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/java-stores", () => ({
  collectJavaStores: async () => ({ items: [], stores: [], parseFailures: 0 })
}));

vi.mock("os", async (orig) => {
  const actual = (await orig()) as any;
  return { ...actual, default: { ...actual.default, platform: () => "darwin", hostname: () => "test" } };
});

import { collectCDP } from "../../src/plugins/cdp";

const store = { id: "mac/system", name: "System", scope: "machine" as const };

/** Certificados sintéticos, suficientes para cruzar el tope de 2000. */
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
  logger: { warn: vi.fn(), info: vi.fn() },
  policyRuntime: {
    getCdpScanTlsListeners: () => false,
    getCdpJavaKeystorePaths: () => [],
    getCdpCertFilePaths: () => []
  }
} as any;

const deltaWithRemovals = () => ({
  added: [{ id: "nuevo" }],
  updated: [{ id: "cambiado" }],
  removed: [{ id: "recortado-1" }, { id: "recortado-2" }]
});

beforeEach(() => {
  vi.clearAllMocks();
  commitCdpBaseline.mockReturnValue(undefined);
});

describe("collectCDP — bajas en un escaneo truncado", () => {
  it("marca truncated y DESCARTA las bajas cuando se cruza el tope", async () => {
    collectMacosCdp.mockResolvedValue({ items: items(2100), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue(deltaWithRemovals());

    const ns: any = await collectCDP(ctx);

    expect(ns.truncated).toBe(true);
    expect(ns.certificates.delta.removed).toEqual([]);
  });

  it("conserva altas y cambios — el recorte no invalida lo que SÍ se vio", async () => {
    // Un certificado presente en el payload está presente de verdad; solo
    // la ausencia deja de ser evidencia.
    collectMacosCdp.mockResolvedValue({ items: items(2100), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue(deltaWithRemovals());

    const ns: any = await collectCDP(ctx);

    expect(ns.certificates.delta.added).toHaveLength(1);
    expect(ns.certificates.delta.updated).toHaveLength(1);
  });

  it("NO toca las bajas en un escaneo completo", async () => {
    // Sin esto cambiaríamos un fallo por otro: dejar de detectar bajas
    // reales en el caso normal, que es el 100% de la flota hoy (máximo
    // medido: 528 certificados en un equipo, contra un tope de 2000).
    collectMacosCdp.mockResolvedValue({ items: items(50), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue(deltaWithRemovals());

    const ns: any = await collectCDP(ctx);

    expect(ns.truncated).toBe(false);
    expect(ns.certificates.delta.removed).toHaveLength(2);
  });

  it("sobrevive al primer escaneo, donde no hay delta que recortar", async () => {
    // delta === null significa "primera vez, va baseline completa".
    collectMacosCdp.mockResolvedValue({ items: items(2100), stores: [store], parseFailures: 0 });
    computeCdpDelta.mockReturnValue(null);

    const ns: any = await collectCDP(ctx);

    expect(ns.truncated).toBe(true);
    expect(Array.isArray(ns.certificates.items)).toBe(true);
    expect(ns.certificates.delta).toBeUndefined();
  });
});
