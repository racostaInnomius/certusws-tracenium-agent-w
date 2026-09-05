// test/plugins/cdp-side-blocks.test.ts
//
// §5.2: las claves de host SSH y los candidatos de sonda viajan en el
// namespace FUERA de `certificates`, solo cuando cambian (digest en
// cdp_meta) o en un baseline completo, y solo con la sonda de listeners
// activada. Y cuando cambian, cuentan como cambio para el planificador.
// Conduce collectCDP de verdad con colectores y baseline mockeados.

import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from "vitest";
import os from "os";

const computeCdpDelta = vi.fn();
const commitCdpBaseline = vi.fn();
vi.mock("../../src/domain/cdp-baseline-repo", () => ({
  computeCdpDelta: (...a: any[]) => computeCdpDelta(...a),
  commitCdpBaseline: (...a: any[]) => commitCdpBaseline(...a),
  loadCdpBaselineItemsByStore: vi.fn(() => []),
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
const collectMacosCdp = vi.fn();
vi.mock("../../src/plugins/cdp/providers/macos", () => ({ collectMacosCdp: () => collectMacosCdp() }));
vi.mock("../../src/plugins/cdp/providers/windows", () => ({ collectWindowsCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/linux", () => ({ collectLinuxCdp: vi.fn() }));
vi.mock("../../src/plugins/cdp/providers/java-stores", () => ({ collectJavaStores: async () => ({ items: [], stores: [], parseFailures: 0, storeErrors: [], unreadable: [] }) }));
vi.mock("../../src/plugins/cdp/providers/nss", () => ({ collectNssStores: async () => ({ items: [], stores: [], parseFailures: 0, unreadable: [], unreadableStores: [] }) }));
vi.mock("../../src/plugins/cdp/providers/tls-listeners", () => ({ collectTlsListeners: async () => ({ items: [], stores: [], parseFailures: 0, portsScanned: 0, portsWithTls: 0 }) }));
vi.mock("../../src/plugins/cdp/listening-ports", () => ({ listListeningPorts: async () => [22, 443] }));
const sshKeys = vi.fn();
vi.mock("../../src/plugins/cdp/providers/ssh-host-keys", () => ({ collectSshHostKeys: (...a: any[]) => sshKeys(...a) }));
const outbound = vi.fn();
vi.mock("../../src/plugins/cdp/providers/outbound-tls", () => ({ collectOutboundTlsCandidates: (...a: any[]) => outbound(...a) }));

beforeAll(() => {
  vi.spyOn(os, "platform").mockReturnValue("darwin");
});
afterAll(() => vi.restoreAllMocks());

import { collectCDP } from "../../src/plugins/cdp";

const sysStore = { id: "mac/system", name: "System", scope: "machine" as const };
const item = (id: string) => ({ id, fingerprint256: id.padStart(64, "0"), store: sysStore, source: "store" as const, hasPrivateKey: false, isCA: false });
const ctx = (scan: boolean) =>
  ({
    config: { agentVersion: "test" },
    logger: { warn: vi.fn(), info: vi.fn() },
    policyRuntime: {
      getCdpJavaKeystorePaths: () => [],
      getCdpCertFilePaths: () => [],
      getCdpScanTlsListeners: () => scan,
      getCdpTlsListenerPorts: () => [],
      getCdpProbeTargets: () => []
    }
  }) as any;

const SSH = { host: "srv-01", listening: true, keys: [{ keyType: "ssh-ed25519", algorithm: "Ed25519", bits: 256, curve: "Ed25519", fingerprintSha256: "SHA256:abc", path: "/etc/ssh/ssh_host_ed25519_key.pub" }], unreadable: 0 };
const CANDS = [{ host: "10.0.0.5", port: 443, connections: 3, process: "chrome" }];

beforeEach(() => {
  vi.clearAllMocks();
  meta.clear();
  collectMacosCdp.mockResolvedValue({ items: [item("sys-1")], stores: [sysStore], parseFailures: 0, loginKeychains: { discovered: 0, read: 0 }, unreadable: [] });
  sshKeys.mockResolvedValue(SSH);
  outbound.mockResolvedValue(CANDS);
});

describe("claves SSH y candidatos de sonda en el namespace", () => {
  it("⭐ con la sonda de listeners apagada no se recogen: son funciones de red opt-in", async () => {
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    const ns = await collectCDP(ctx(false));
    expect(sshKeys).not.toHaveBeenCalled();
    expect(outbound).not.toHaveBeenCalled();
    expect(ns.sshHostKeys).toBeUndefined();
    expect(ns.probeCandidates).toBeUndefined();
    expect(ns.hasChanges).toBe(false);
  });

  it("⭐ la primera vez viajan y cuentan como cambio aunque los certificados no se muevan", async () => {
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    const ns = await collectCDP(ctx(true));
    expect(ns.sshHostKeys).toEqual({ host: "srv-01", listening: true, keys: SSH.keys });
    expect(ns.probeCandidates).toEqual(CANDS);
    expect(ns.hasChanges).toBe(true);
    // Los puertos que escuchan se pasan a los dos colectores.
    expect(sshKeys).toHaveBeenCalledWith({ listeningPorts: [22, 443] });
    expect(outbound).toHaveBeenCalledWith({ localListening: [22, 443] });
  });

  it("⭐ sin cambios no vuelven a viajar ni disparan hasChanges", async () => {
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    await collectCDP(ctx(true));
    const ns2 = await collectCDP(ctx(true));
    expect(ns2.sshHostKeys).toBeUndefined();
    expect(ns2.probeCandidates).toBeUndefined();
    expect(ns2.hasChanges).toBe(false);
    // Cambia un candidato → solo ese bloque vuelve, y hay cambio.
    outbound.mockResolvedValue([...CANDS, { host: "10.0.0.6", port: 636, connections: 1 }]);
    const ns3 = await collectCDP(ctx(true));
    expect(ns3.sshHostKeys).toBeUndefined();
    expect(ns3.probeCandidates).toHaveLength(2);
    expect(ns3.hasChanges).toBe(true);
  });

  it("un escaneo forzado (full) los manda siempre, sin marcar cambio por ellos", async () => {
    computeCdpDelta.mockReturnValue(null);
    await collectCDP(ctx(true));
    const ns = await collectCDP(ctx(true), { full: true });
    expect(ns.sshHostKeys).toBeDefined();
    expect(ns.probeCandidates).toEqual(CANDS);
    expect(ns.hasChanges).toBe(true); // por ser baseline, no por ellos
  });

  it("un fallo de los colectores no tumba el escaneo", async () => {
    computeCdpDelta.mockReturnValue({ added: [], updated: [], removed: [] });
    sshKeys.mockRejectedValue(new Error("EACCES"));
    const c = ctx(true);
    const ns = await collectCDP(c);
    expect(ns.certificates.count).toBe(1);
    expect(ns.sshHostKeys).toBeUndefined();
    expect(c.logger.warn).toHaveBeenCalledWith(expect.stringMatching(/claves SSH/), expect.anything());
  });
});
