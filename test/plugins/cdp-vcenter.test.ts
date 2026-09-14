// test/plugins/cdp-vcenter.test.ts
//
// vCenter por el gateway (2026-09-14): el proveedor de CDP lee el
// certificado maquina de vCenter y el de cada ESXi (lo que cada uno sirve
// en 443) con la credencial sellada del gateway, y lo reporta como un
// bloque aparte. Sin `readCertificates` no toca vCenter; sin credencial
// tampoco; un host que no contesta deja la lectura incompleta.

import { describe, it, expect, vi } from "vitest";
import crypto from "crypto";
import { collectVcenter, derToVcenterCert } from "../../src/plugins/cdp/providers/vcenter";
import { FIXTURE_CERT } from "./tls-fixture";

const DER = Buffer.from(FIXTURE_CERT.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""), "base64");
const FP = crypto.createHash("sha256").update(DER).digest("hex");

const CFG = {
  vcenter: { url: "https://10.130.130.3", host: "10.130.130.3", port: 443, tlsThumbprintSha256: FP, credentialRef: "vcenter/default" },
  scope: { folders: [] },
  snapshot: { memory: false, quiesce: true, retentionHours: 24, maxConcurrent: 5, perVmTimeoutSec: 900, minFreePercent: 10, minFreeGiB: 10 },
  readCertificates: true,
};

function fakeClient(hosts = [{ moref: "host-12", name: "esx01.lab", connectionState: "connected" }, { moref: "host-13", name: "esx02.lab", connectionState: "connected" }]) {
  return {
    assertPinnedCertificate: vi.fn(async () => undefined),
    fetchServerCertificateDer: vi.fn(async () => DER),
    retrieveServiceContent: vi.fn(async () => ({})),
    login: vi.fn(async () => ({ sessionKey: "s", userName: "u" })),
    listHosts: vi.fn(async () => hosts),
    logout: vi.fn(async () => undefined),
  };
}

function deps(over: Record<string, unknown> = {}, client = fakeClient()) {
  const cred = { username: "svc@vsphere.local", password: "s3cret" };
  return {
    deps: {
      gatewayConfig: () => CFG,
      getCredential: vi.fn(async () => cred),
      makeClient: () => client,
      now: () => new Date("2026-09-14T10:00:00.000Z"),
      ...over,
    } as any,
    client,
    cred,
  };
}

const ctx = { logger: { info: vi.fn(), warn: vi.fn() } } as any;

describe("collectVcenter", () => {
  it("⭐ lee el certificado maquina y el de cada host, y el bloque lleva rol, host y huella", async () => {
    const d = deps();
    const fetchPeer = vi.fn(async () => DER);
    const r = await collectVcenter(ctx, { deps: d.deps, fetchPeerCertificate: fetchPeer, now: d.deps.now });
    expect(r).toBeDefined();
    expect(r!.host).toBe("10.130.130.3");
    expect(r!.readAt).toBe("2026-09-14T10:00:00.000Z");
    expect(r!.machine?.fingerprint256).toBe(FP);
    expect(r!.hosts.map((h) => [h.name, h.moref, h.certificate?.fingerprint256])).toEqual([["esx01.lab", "host-12", FP], ["esx02.lab", "host-13", FP]]);
    expect(r!.complete).toBe(true);
    expect(fetchPeer).toHaveBeenCalledWith("esx01.lab", 443);
    // El pin va antes que la credencial; la sesion se cierra; el secreto se borra.
    expect(d.client.assertPinnedCertificate).toHaveBeenCalled();
    expect(d.client.logout).toHaveBeenCalled();
    expect(d.cred.password).toBe("");
    // Nada de lo que solo tiene sentido EN un equipo viaja.
    expect((r!.machine as any).store).toBeUndefined();
    expect((r!.machine as any).id).toBeUndefined();
  });

  it("⭐ sin `readCertificates` no toca vCenter ni pide la credencial", async () => {
    const d = deps({ gatewayConfig: () => ({ ...CFG, readCertificates: false }) });
    expect(await collectVcenter(ctx, { deps: d.deps, fetchPeerCertificate: vi.fn() })).toBeUndefined();
    expect(d.deps.getCredential).not.toHaveBeenCalled();
    expect(d.client.login).not.toHaveBeenCalled();
    const notGateway = deps({ gatewayConfig: () => null });
    expect(await collectVcenter(ctx, { deps: notGateway.deps, fetchPeerCertificate: vi.fn() })).toBeUndefined();
  });

  it("sin credencial en el gateway no hay bloque, y no se contacta a vCenter", async () => {
    const d = deps({ getCredential: vi.fn(async () => { const e: any = new Error("none"); e.code = "not_found"; throw e; }) });
    expect(await collectVcenter(ctx, { deps: d.deps, fetchPeerCertificate: vi.fn() })).toBeUndefined();
    expect(d.client.assertPinnedCertificate).not.toHaveBeenCalled();
  });

  it("⭐ un host que no contesta se reporta con su motivo y deja la lectura INCOMPLETA (nada se retira por ausencia)", async () => {
    const d = deps();
    const fetchPeer = vi.fn(async (host: string) => {
      if (host === "esx02.lab") throw new Error("ETIMEDOUT");
      return DER;
    });
    const r = await collectVcenter(ctx, { deps: d.deps, fetchPeerCertificate: fetchPeer });
    expect(r!.hosts[1]).toEqual({ name: "esx02.lab", moref: "host-13", connectionState: "connected", error: "ETIMEDOUT" });
    expect(r!.complete).toBe(false);
  });

  it("un pin que no coincide no entrega la credencial a vCenter y lo dice", async () => {
    const client = fakeClient();
    client.assertPinnedCertificate.mockRejectedValue(new Error("vCenter certificate does not match the pinned thumbprint"));
    const d = deps({}, client);
    const r = await collectVcenter(ctx, { deps: d.deps, fetchPeerCertificate: vi.fn(async () => DER) });
    expect(client.login).not.toHaveBeenCalled();
    expect(r!.hosts).toEqual([]);
    expect(r!.complete).toBe(false);
    expect(r!.errors?.[0]).toMatch(/pinned thumbprint/);
    expect(d.cred.password).toBe("");
  });

  it("respeta el tope de hosts por lectura y lo anota", async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ moref: `host-${i}`, name: `esx${i}.lab`, connectionState: "connected" }));
    const d = deps({}, fakeClient(many));
    const r = await collectVcenter(ctx, { deps: d.deps, fetchPeerCertificate: vi.fn(async () => DER), maxHosts: 3 });
    expect(r!.hosts).toHaveLength(3);
    expect(r!.complete).toBe(false);
    expect(r!.errors?.[0]).toMatch(/2 host\(s\) beyond/);
  });
});

describe("derToVcenterCert", () => {
  it("parsea el DER a los campos del cable y descarta lo que no parsea", () => {
    const c = derToVcenterCert(DER, "esx01.lab")!;
    expect(c.fingerprint256).toBe(FP);
    expect(c.keyAlgorithm).toBeDefined();
    expect(derToVcenterCert(Buffer.from("nope"), "x")).toBeNull();
  });
});
