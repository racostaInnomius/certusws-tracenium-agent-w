// test/plugins/cdp-tls-probes.test.ts
//
// Rol Probe (fase 2): el agente sondea SOLO lo que la policy dice, con
// forma estricta, y lo que reporta no contamina el embudo de propiedad.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import { parseProbeTarget, probeTargetKey } from "../../src/domain/probe-target";
import { sanitizeProbeTargets } from "../../src/core/policy-runtime";
import { collectTlsProbes } from "../../src/plugins/cdp/providers/tls-probes";
import { FIXTURE_CERT } from "./tls-fixture";

describe("parseProbeTarget", () => {
  it("acepta hostname, IPv4 y [IPv6]", () => {
    expect(parseProbeTarget("lb.corp.example:443")).toEqual({ host: "lb.corp.example", port: 443 });
    expect(parseProbeTarget("10.0.0.5:8443")).toEqual({ host: "10.0.0.5", port: 8443 });
    expect(parseProbeTarget("[fd00::1]:636")).toEqual({ host: "fd00::1", port: 636 });
    expect(probeTargetKey({ host: "fd00::1", port: 636 })).toBe("[fd00::1]:636");
  });

  it("⭐ rechaza loopback: el propio equipo lo cubre el colector de listeners", () => {
    for (const t of ["127.0.0.1:443", "localhost:8443", "[::1]:443", "0.0.0.0:443"]) {
      expect(parseProbeTarget(t)).toBeNull();
    }
  });

  it("rechaza puertos y hosts imposibles", () => {
    for (const t of ["host:0", "host:70000", "host:abc", "host", ":443", "10.0.0.999:443", "ho st:443", "a".repeat(300) + ":443"]) {
      expect(parseProbeTarget(t)).toBeNull();
    }
  });
});

describe("sanitizeProbeTargets", () => {
  it("dedupe, minusculas, tope", () => {
    const out = sanitizeProbeTargets(["LB.Corp:443", "lb.corp:443", "bad", 42, "10.0.0.1:636"]);
    expect(out).toEqual(["lb.corp:443", "10.0.0.1:636"]);
    const many = Array.from({ length: 500 }, (_, i) => `h${i}.corp:443`);
    expect(sanitizeProbeTargets(many).length).toBe(200);
  });

  it("no-array → vacio", () => {
    expect(sanitizeProbeTargets("lb.corp:443")).toEqual([]);
    expect(sanitizeProbeTargets(undefined)).toEqual([]);
  });
});

describe("collectTlsProbes", () => {
  const der = new crypto.X509Certificate(FIXTURE_CERT).raw;
  const ctx = (targets: string[]) =>
    ({
      logger: { info() {}, warn() {} },
      policyRuntime: {
        getCdpProbeTargets: () => targets.map((t) => parseProbeTarget(t)!).filter(Boolean)
      }
    }) as any;

  it("sin objetivos no sondea nada", async () => {
    let calls = 0;
    const r = await collectTlsProbes(ctx([]), { probe: async () => (calls++, null) });
    expect(calls).toBe(0);
    expect(r.items).toEqual([]);
  });

  it("⭐ lo sondeado es source=probe, scope=network y NUNCA «tuyo»", async () => {
    // El embudo de propiedad se construye sobre has_private_key. Un
    // objetivo remoto no es de este equipo por definicion; marcarlo como
    // propio inflaria la unica cifra que importa.
    const r = await collectTlsProbes(ctx(["lb.corp:443"]), {
      probe: async () => ({
        der,
        chainDepth: 1,
        chainAuthorized: false,
        chainError: "SELF_SIGNED_CERT_IN_CHAIN",
        protocol: "TLSv1.3",
        cipher: "TLS_AES_256_GCM_SHA384",
        kexGroup: "X25519",
        kemHybrid: false
      })
    });
    expect(r.answered).toBe(1);
    const item = r.items[0];
    expect(item.source).toBe("probe");
    expect(item.store).toEqual({ id: "probe/tcp/lb.corp:443", name: "lb.corp:443", scope: "network" });
    expect(item.hasPrivateKey).toBe(false);
    expect(item.tls).toMatchObject({ port: 443, target: "lb.corp", protocol: "TLSv1.3", kexGroup: "X25519", kemHybrid: false });
  });

  it("el SNI es el hostname, y vacio para una IP", async () => {
    const seen: string[] = [];
    await collectTlsProbes(ctx(["lb.corp:443", "10.0.0.5:443"]), {
      probe: async (_h, _p, sni) => (seen.push(sni), null)
    });
    expect(seen.sort()).toEqual(["", "lb.corp"]);
  });

  it("⭐ kemHybrid null viaja como null: «no se supo» no es «no»", async () => {
    const r = await collectTlsProbes(ctx(["lb.corp:443"]), {
      probe: async () => ({ der, chainDepth: 1, chainAuthorized: true, kemHybrid: null, kemProbeError: "timeout" })
    });
    expect(r.items[0].tls).toMatchObject({ kemHybrid: null, kemProbeError: "timeout" });
  });

  it("un objetivo que no contesta no rompe a los demas", async () => {
    const r = await collectTlsProbes(ctx(["a.corp:443", "b.corp:443"]), {
      probe: async (host) => (host === "a.corp" ? null : { der, chainDepth: 1, chainAuthorized: true })
    });
    expect(r.targets).toBe(2);
    expect(r.answered).toBe(1);
  });
});
