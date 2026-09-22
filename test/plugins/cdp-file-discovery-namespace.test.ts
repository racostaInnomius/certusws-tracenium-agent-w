// test/plugins/cdp-file-discovery-namespace.test.ts
//
// Ola 1.1 — cómo llega el descubrimiento de ficheros al namespace.
//
//   1. `cdp.fileDiscovery`: "default" añade las raíces por SO; "off" no
//      recorre nada; un runtime SIN el getter equivale a "configured"
//      (sin rutas → no se recorre).
//   2. Lo que el recorrido no vio se acota por PREFIJO (raíz cortada,
//      directorio ilegible), no con `unscoped`: las bajas de los demás
//      almacenes siguen viajando.
//   3. Lo denegado bajo una raíz por defecto solo se protege si tenía
//      algo inventariado (baseline).
//   4. Las claves sueltas viajan cuando cambian, y las de rutas no vistas
//      se ARRASTRAN de la última lista.
//
// Conduce collectCDP de verdad con el recorrido mockeado.

import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from "vitest";
import os from "os";

const computeCdpDelta = vi.fn();
const commitCdpBaseline = vi.fn();
const loadCdpBaselineItemsByStore = vi.fn();
vi.mock("../../src/domain/cdp-baseline-repo", () => ({
  computeCdpDelta: (...a: any[]) => computeCdpDelta(...a),
  commitCdpBaseline: (...a: any[]) => commitCdpBaseline(...a),
  loadCdpBaselineItemsByStore: (...a: any[]) => loadCdpBaselineItemsByStore(...a),
  cdpAnchorDigestChanged: vi.fn(() => false),
  commitCdpAnchorDigest: vi.fn(),
  hashCdpAnchorState: vi.fn(() => "h")
}));
const meta = new Map<string, string>();
vi.mock("../../src/domain/cdp-adcs-repo", () => ({
  readCdpMeta: (k: string) => meta.get(k) ?? null,
  writeCdpMeta: (k: string, v: string) => meta.set(k, v),
  readAdcsCursor: () => 0,
  writeAdcsCursor: vi.fn()
}));
vi.mock("../../src/domain/cdp-file-cache-repo", () => ({ openCdpFileScanCache: () => undefined }));
const collectMacosCdp = vi.fn();
vi.mock("../../src/plugins/cdp/providers/macos", () => ({ collectMacosCdp: () => collectMacosCdp() }));
vi.mock("../../src/plugins/cdp/providers/windows", () => ({ collectWindowsCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/linux", () => ({ collectLinuxCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/java-stores", () => ({ collectJavaStores: async () => ({ items: [], stores: [], parseFailures: 0, storeErrors: [], unreadable: [] }) }));
vi.mock("../../src/plugins/cdp/providers/nss", () => ({ collectNssStores: async () => ({ items: [], stores: [], parseFailures: 0, unreadable: [], unreadableStores: [] }) }));
vi.mock("../../src/plugins/cdp/providers/os-tls-capability", () => ({ measureOsTlsCapability: async () => ({ platform: "macos", group: "X", supported: null, method: "not_measured", measuredAt: "t" }) }));
const collectCertFiles = vi.fn();
vi.mock("../../src/plugins/cdp/providers/cert-files", async (orig) => {
  const real: any = await orig();
  return { ...real, collectCertFiles: (...a: any[]) => collectCertFiles(...a) };
});

beforeAll(() => {
  vi.spyOn(os, "platform").mockReturnValue("darwin");
});
afterAll(() => vi.restoreAllMocks());

import { collectCDP } from "../../src/plugins/cdp";

const sysStore = { id: "mac/system", name: "System", scope: "machine" as const };
const fileStore = (p: string) => ({ id: `file:${p}`, name: p, scope: "machine" as const });
const item = (id: string, store: any = sysStore) => ({ id, fingerprint256: id.padStart(64, "0"), store, source: "store" as const, hasPrivateKey: false, isCA: false });

const ctx = (mode: string | undefined, paths: string[] = []) =>
  ({
    config: { agentVersion: "test" },
    logger: { warn: vi.fn(), info: vi.fn() },
    policyRuntime: {
      getCdpJavaKeystorePaths: () => [],
      getCdpCertFilePaths: () => paths,
      ...(mode === undefined ? {} : { getCdpFileDiscovery: () => mode }),
      getCdpScanTlsListeners: () => false,
      getCdpProbeTargets: () => []
    }
  }) as any;

const walk = (over: Record<string, unknown> = {}) => ({
  items: [], stores: [], parseFailures: 0, filesScanned: 3, unreadable: 0, unreadableFiles: [], unreadableReasons: {},
  unreadableDirs: [], deniedPaths: [], truncated: null, capped: false, incompleteRoots: [], keys: [], keystores: 0,
  trustBundlesSkipped: 0, cacheHits: 0, elapsedMs: 5, ...over
});

beforeEach(() => {
  vi.clearAllMocks();
  meta.clear();
  collectMacosCdp.mockResolvedValue({ items: [item("sys-1")], stores: [sysStore], parseFailures: 0, loginKeychains: { discovered: 0, read: 0 }, unreadable: [] });
  loadCdpBaselineItemsByStore.mockReturnValue([]);
  collectCertFiles.mockResolvedValue(walk());
});

describe("cdp.fileDiscovery", () => {
  it("⭐ default: raíces por SO + las del operador (primero las del operador)", async () => {
    computeCdpDelta.mockReturnValue(null);
    const ns = await collectCDP(ctx("default", ["/srv/certs"]));
    const roots = collectCertFiles.mock.calls[0][0];
    expect(roots[0]).toEqual({ path: "/srv/certs", origin: "configured" });
    expect(roots.slice(1).every((r: any) => r.origin === "default")).toBe(true);
    expect(roots.map((r: any) => r.path)).toContain("/Library");
    expect(ns.fileDiscovery).toMatchObject({ mode: "default", filesScanned: 3, truncated: null });
  });

  it("off: no se recorre nada, ni con rutas configuradas", async () => {
    computeCdpDelta.mockReturnValue(null);
    const ns = await collectCDP(ctx("off", ["/srv/certs"]));
    expect(collectCertFiles).not.toHaveBeenCalled();
    expect(ns.fileDiscovery).toBeUndefined();
  });

  it("un runtime sin el getter es «configured»: sin rutas, no se recorre", async () => {
    computeCdpDelta.mockReturnValue(null);
    await collectCDP(ctx(undefined));
    expect(collectCertFiles).not.toHaveBeenCalled();
  });
});

describe("lo que no se vio se acota por prefijo", () => {
  it("⭐ raíz cortada por tiempo: su prefijo protege lo suyo; las bajas de otros almacenes viajan", async () => {
    collectCertFiles.mockResolvedValue(walk({ truncated: "time", incompleteRoots: ["/opt"] }));
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [{ id: "gone-sys" }, { id: "opt-file" }] });
    loadCdpBaselineItemsByStore.mockImplementation((match: (id: string) => boolean) =>
      [item("opt-file", fileStore("/opt/app/x.crt"))].filter((i) => match(i.store.id))
    );
    const ns = await collectCDP(ctx("default"));
    expect(ns.partial?.unscoped).toEqual([]);
    expect(ns.partial?.unreadableStores).toContainEqual({ id: "file:/opt/", name: "/opt/", reason: "file discovery truncated (time)", prefix: true });
    expect(ns.certificates.delta?.removed).toEqual([{ id: "gone-sys" }]);
    expect(ns.fileDiscovery).toMatchObject({ truncated: "time", incompleteRoots: ["/opt"] });
  });

  it("directorio ilegible bajo una raíz del operador: prefijo, no unscoped", async () => {
    collectCertFiles.mockResolvedValue(walk({ unreadableDirs: ["/srv/certs/private"] }));
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    const ns = await collectCDP(ctx("configured", ["/srv/certs"]));
    expect(ns.partial?.unscoped ?? []).toEqual([]);
    expect(ns.partial?.unreadableStores).toContainEqual({ id: "file:/srv/certs/private/", name: "/srv/certs/private/", reason: "directory unreadable", prefix: true });
  });

  it("⭐ denegado bajo raíz por defecto: solo se nombra si tenía historia", async () => {
    collectCertFiles.mockResolvedValue(walk({ deniedPaths: ["/etc/ssl/private", "/var/lib/postgresql"] }));
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    loadCdpBaselineItemsByStore.mockImplementation((match: (id: string) => boolean) =>
      [item("pg", fileStore("/var/lib/postgresql/16/main/server.crt"))].filter((i) => match(i.store.id))
    );
    const ns = await collectCDP(ctx("default"));
    const ids = (ns.partial?.unreadableStores ?? []).map((u) => u.id);
    expect(ids).toEqual(["file:/var/lib/postgresql/"]);
  });

  it("sin nada denegado con historia, el escaneo NO es parcial", async () => {
    collectCertFiles.mockResolvedValue(walk({ deniedPaths: ["/etc/ssl/private"] }));
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    const ns = await collectCDP(ctx("default"));
    expect(ns.partial).toBeUndefined();
  });
});

describe("claves sueltas", () => {
  const key = (p: string) => ({ path: p, format: "pkcs8" as const, encrypted: false, readable: true, keyAlgorithm: "RSA", keySizeBits: 2048 });

  it("⭐ viajan en un baseline y, después, solo cuando cambian (y cuentan como cambio)", async () => {
    collectCertFiles.mockResolvedValue(walk({ keys: [key("/etc/nginx/ssl/a.key")] }));
    computeCdpDelta.mockReturnValue(null);
    const first = await collectCDP(ctx("default"));
    // Sin hash público en el doble: no se puede casar → «unknown», no «none».
    expect(first.looseKeys?.keys).toEqual([{ ...key("/etc/nginx/ssl/a.key"), certMatch: "unknown" }]);

    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    const same = await collectCDP(ctx("default"));
    expect(same.looseKeys).toBeUndefined();
    expect(same.hasChanges).toBe(false);

    collectCertFiles.mockResolvedValue(walk({ keys: [] }));
    const gone = await collectCDP(ctx("default"));
    expect(gone.looseKeys).toEqual({ keys: [] });
    expect(gone.hasChanges).toBe(true);
  });

  it("⭐ la de una ruta no vista se arrastra de la última lista", async () => {
    collectCertFiles.mockResolvedValue(walk({ keys: [key("/etc/a.key"), key("/opt/b.key")] }));
    computeCdpDelta.mockReturnValue(null);
    await collectCDP(ctx("default"));

    collectCertFiles.mockResolvedValue(walk({ keys: [key("/etc/a.key")], truncated: "time", incompleteRoots: ["/opt"] }));
    computeCdpDelta.mockReturnValue(null);
    const ns = await collectCDP(ctx("default", []), { full: true });
    expect(ns.looseKeys?.keys.map((k) => k.path)).toEqual(["/etc/a.key", "/opt/b.key"]);
  });

  it("si el recorrido falla, el bloque de claves no viaja (no se afirma que no haya)", async () => {
    collectCertFiles.mockRejectedValue(new Error("boom"));
    computeCdpDelta.mockReturnValue(null);
    const ns = await collectCDP(ctx("default"));
    expect(ns.looseKeys).toBeUndefined();
    expect(ns.partial?.unscoped).toEqual(["file: boom"]);
  });
});
