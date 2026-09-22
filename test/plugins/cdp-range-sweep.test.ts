// test/plugins/cdp-range-sweep.test.ts
//
// Ola 1.2 — barrido por rangos. Lo que se prueba aqui es sobre todo lo
// que el barrido NO hace: no pasarse de los topes, no barrer lo que ya
// se sondea, no afirmar que vio la red cuando se corto, y no mandar
// jamas un byte de mas.

import { describe, it, expect, beforeAll } from "vitest";
import crypto from "crypto";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { OPENSSL } from "../privsvc/openssl-compat";
import {
  intToIpv4,
  ipv4ToInt,
  parseProbeRange,
  parseRangeBounds,
  probeRangeKey,
  rangeAddresses,
  PROBE_RANGE_MAX_ADDRESSES
} from "../../src/domain/probe-range";
import { sanitizeProbeRanges } from "../../src/core/policy-runtime";
import { collectRangeSweep, planSweep, SWEEP_MAX_ATTEMPTS } from "../../src/plugins/cdp/providers/tls-range-sweep";
import { FIXTURE_CERT } from "./tls-fixture";

describe("probe-range: forma y topes", () => {
  it("ipv4 ida y vuelta", () => {
    expect(ipv4ToInt("10.0.0.1")).toBe(167772161);
    expect(intToIpv4(167772161)).toBe("10.0.0.1");
    expect(ipv4ToInt("10.0.0.256")).toBeNull();
    expect(ipv4ToInt("no")).toBeNull();
  });

  it("CIDR se alinea a la red y calcula el final", () => {
    expect(parseRangeBounds("10.0.0.37/24")).toEqual({ start: ipv4ToInt("10.0.0.0"), end: ipv4ToInt("10.0.0.255") });
    expect(parseRangeBounds("10.0.0.5/32")).toEqual({ start: ipv4ToInt("10.0.0.5"), end: ipv4ToInt("10.0.0.5") });
  });

  it("⭐ nada mas ancho que un /22: un /16 son 65.536 handshakes", () => {
    expect(parseRangeBounds("10.0.0.0/22")).not.toBeNull();
    expect(parseRangeBounds("10.0.0.0/21")).toBeNull();
    expect(parseRangeBounds("10.0.0.0/16")).toBeNull();
    expect(parseRangeBounds("10.0.0.0/8")).toBeNull();
  });

  it("⭐ un inicio-fin tampoco pasa de 1024 direcciones", () => {
    expect(parseRangeBounds("10.0.0.1-10.0.3.232")).not.toBeNull(); // 1000
    expect(parseRangeBounds("10.0.0.1-10.0.10.1")).toBeNull();
    expect(parseRangeBounds("10.0.0.10-10.0.0.1")).toBeNull(); // al reves
  });

  it("entrada completa: rango, puertos y SNI", () => {
    expect(parseProbeRange({ range: "10.0.0.0/30", ports: [443, 8443], sni: "WWW.Corp.Example" })).toEqual({
      raw: "10.0.0.0/30",
      start: ipv4ToInt("10.0.0.0"),
      end: ipv4ToInt("10.0.0.3"),
      ports: [443, 8443],
      sni: "www.corp.example"
    });
  });

  it("sin puertos, con puertos imposibles o con mas de 8 no hay entrada", () => {
    expect(parseProbeRange({ range: "10.0.0.0/30" })).toBeNull();
    expect(parseProbeRange({ range: "10.0.0.0/30", ports: [] })).toBeNull();
    expect(parseProbeRange({ range: "10.0.0.0/30", ports: [0] })).toBeNull();
    expect(parseProbeRange({ range: "10.0.0.0/30", ports: [1, 2, 3, 4, 5, 6, 7, 8, 9] })).toBeNull();
  });

  it("⭐ IPv6 no se barre: un /64 no se puede recorrer", () => {
    expect(parseProbeRange({ range: "fd00::/120", ports: [443] })).toBeNull();
  });

  it("un SNI que no es un nombre DNS se ignora, pero la entrada vale", () => {
    const r = parseProbeRange({ range: "10.0.0.0/30", ports: [443], sni: "no un nombre" });
    expect(r).not.toBeNull();
    expect(r!.sni).toBeUndefined();
  });

  it("⭐ loopback, enlace local y multicast nunca se enumeran", () => {
    expect([...rangeAddresses(parseProbeRange({ range: "127.0.0.0/30", ports: [443] })!)]).toEqual([]);
    expect([...rangeAddresses(parseProbeRange({ range: "169.254.0.0/30", ports: [443] })!)]).toEqual([]);
    expect([...rangeAddresses(parseProbeRange({ range: "239.0.0.0/30", ports: [443] })!)]).toEqual([]);
    expect([...rangeAddresses(parseProbeRange({ range: "10.0.0.0/30", ports: [443] })!)].length).toBe(4);
  });

  it("un /22 entero cabe exactamente en el tope", () => {
    const r = parseProbeRange({ range: "10.0.0.0/22", ports: [443] })!;
    expect(r.end - r.start + 1).toBe(PROBE_RANGE_MAX_ADDRESSES);
  });
});

describe("sanitizeProbeRanges", () => {
  it("⭐ una entrada invalida se TIRA, no se recorta a lo que quepa", () => {
    // Recortar un /16 a un /22 seria barrer algo que nadie pidio.
    expect(sanitizeProbeRanges([{ range: "10.0.0.0/16", ports: [443] }])).toEqual([]);
  });

  it("canoniza, deduplica y tope de 16 entradas", () => {
    const out = sanitizeProbeRanges([
      { range: "10.0.0.0/24", ports: [443, 443] },
      { range: "10.0.0.0/24", ports: [443] },
      "10.0.0.0/24",
      null
    ]);
    expect(out).toEqual([{ range: "10.0.0.0/24", ports: [443] }]);
    const many = Array.from({ length: 40 }, (_, i) => ({ range: `10.0.${i}.0/24`, ports: [443] }));
    expect(sanitizeProbeRanges(many).length).toBe(16);
  });

  it("no-array → vacio (y por tanto no se barre nada)", () => {
    expect(sanitizeProbeRanges(undefined)).toEqual([]);
    expect(sanitizeProbeRanges("10.0.0.0/24")).toEqual([]);
  });

  it("la clave de dedupe distingue puertos y SNI", () => {
    const a = parseProbeRange({ range: "10.0.0.0/30", ports: [443] })!;
    const b = parseProbeRange({ range: "10.0.0.0/30", ports: [8443] })!;
    const c = parseProbeRange({ range: "10.0.0.0/30", ports: [443], sni: "a.corp" })!;
    expect(new Set([probeRangeKey(a), probeRangeKey(b), probeRangeKey(c)]).size).toBe(3);
  });
});

describe("planSweep", () => {
  const range = (r: string, ports: number[]) => parseProbeRange({ range: r, ports })!;

  it("direcciones x puertos", () => {
    const plan = planSweep([range("10.0.0.0/30", [443, 8443])], new Set());
    expect(plan.addresses).toBe(4);
    expect(plan.units.length).toBe(8);
    expect(plan.truncated).toBeNull();
  });

  it("⭐ lo que ya cubre probeTargets no se barre", () => {
    const plan = planSweep([range("10.0.0.0/30", [443])], new Set(["10.0.0.1:443", "10.0.0.2:443"]));
    expect(plan.skipped).toBe(2);
    expect(plan.units.map((u) => u.address)).toEqual(["10.0.0.0", "10.0.0.3"]);
  });

  it("⭐ el presupuesto total corta y lo dice", () => {
    // 16 entradas x /22 = 16.384 direcciones: muy por encima del techo.
    const many = Array.from({ length: 16 }, (_, i) => range(`10.${i}.0.0/22`, [443]));
    const plan = planSweep(many, new Set());
    expect(plan.truncated).toBe("addresses");
    expect(plan.units.length).toBeLessThanOrEqual(SWEEP_MAX_ATTEMPTS);
  });
});

describe("collectRangeSweep", () => {
  const der = new crypto.X509Certificate(FIXTURE_CERT).raw;
  // Un SEGUNDO certificado de verdad: el caso del vhost por nombre solo
  // se prueba si los dos intentos devuelven DER distintos.
  let vhostDer: Buffer;
  beforeAll(() => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-sweep-"));
    const o = (...a: string[]) => execFileSync(OPENSSL, a, { cwd: dir, stdio: "pipe" });
    o("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "vhost.key");
    o("req", "-x509", "-key", "vhost.key", "-out", "vhost.pem", "-subj", "/CN=vhost.corp.example", "-days", "5");
    vhostDer = new crypto.X509Certificate(fs.readFileSync(path.join(dir, "vhost.pem"))).raw;
  });
  const ctx = () => ({ logger: { info() {}, warn() {} }, policyRuntime: {} }) as any;
  const hit = (extra: any = {}) => ({ der, chainDepth: 1, chainAuthorized: true, ...extra });
  const base = { gapMs: 0, skip: new Set<string>(), reverse: async () => null };

  it("sin rangos no abre un solo socket", async () => {
    let tcp = 0;
    const r = await collectRangeSweep(ctx(), { ...base, ranges: [], tcpCheck: async () => (tcp++, true) });
    expect(tcp).toBe(0);
    expect(r.items).toEqual([]);
    expect(r.stats.ranges).toBe(0);
  });

  it("⭐ solo lo que acepta TCP llega al handshake", async () => {
    const probed: string[] = [];
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.0/30", ports: [443] })!],
      tcpCheck: async (h) => h === "10.0.0.2",
      probe: async (h) => (probed.push(h), hit())
    });
    expect(r.stats.attempts).toBe(4);
    expect(r.stats.accepted).toBe(1);
    expect(probed).toEqual(["10.0.0.2"]);
    expect(r.stats.answered).toBe(1);
  });

  it("⭐ un endpoint barrido produce las MISMAS filas que uno escrito a mano", async () => {
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.1/32", ports: [8443] })!],
      tcpCheck: async () => true,
      probe: async () => hit({ protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", kexGroup: "X25519MLKEM768", kemHybrid: true })
    });
    const item = r.items[0];
    expect(item.source).toBe("probe");
    expect(item.hasPrivateKey).toBe(false);
    expect(item.store).toEqual({ id: "probe/tcp/10.0.0.1:8443", name: "10.0.0.1:8443", scope: "network" });
    expect(item.tls).toMatchObject({
      port: 8443,
      target: "10.0.0.1",
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      kexGroup: "X25519MLKEM768",
      kemHybrid: true,
      sweep: "10.0.0.1/32"
    });
    expect(item.tls!.sni).toBeUndefined();
  });

  it("⭐ doble intento: sin SNI y con el nombre de la resolucion inversa", async () => {
    const sniSeen: string[] = [];
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.1/32", ports: [443] })!],
      tcpCheck: async () => true,
      reverse: async () => "vhost.corp.example",
      probe: async (_h, _p, sni) => (sniSeen.push(sni), hit())
    });
    expect(sniSeen).toEqual(["", "vhost.corp.example"]);
    expect(r.stats.sniAttempts).toBe(1);
    // Mismo certificado en los dos: un solo endpoint, no dos.
    expect(r.stats.sniDistinct).toBe(0);
    expect(r.items.length).toBe(1);
  });

  it("⭐ si el SNI da OTRO certificado, es otro endpoint y se identifica por el nombre", async () => {
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.1/32", ports: [443], sni: "vhost.corp.example" })!],
      tcpCheck: async () => true,
      probe: async (_h, _p, sni) => (sni ? hit({ der: vhostDer }) : hit())
    });
    expect(r.stats.sniDistinct).toBe(1);
    expect(r.items.length).toBe(2);
    expect(r.items.map((i) => i.tls!.target).sort()).toEqual(["10.0.0.1", "vhost.corp.example"]);
    const named = r.items.find((i) => i.tls!.target === "vhost.corp.example")!;
    expect(named.tls!.sni).toBe("vhost.corp.example");
    expect(named.store.id).toBe("probe/tcp/vhost.corp.example:443");
  });

  it("⭐ con SNI de la entrada no se pregunta al DNS por nada", async () => {
    let reverses = 0;
    await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.1/32", ports: [443], sni: "www.corp" })!],
      tcpCheck: async () => true,
      reverse: async () => (reverses++, "otro.corp"),
      probe: async () => hit()
    });
    expect(reverses).toBe(0);
  });

  it("⭐ el presupuesto de pared corta el barrido y lo DICE", async () => {
    let t = 0;
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.0/24", ports: [443] })!],
      // Cada consulta del reloj avanza 10 s: el presupuesto (120 s) se
      // agota a los pocos intentos.
      now: () => (t += 10_000),
      tcpCheck: async () => true,
      probe: async () => hit()
    });
    expect(r.stats.truncated).toBe("time");
    expect(r.stats.attempts).toBeLessThan(254);
  });

  it("un objetivo que no contesta al handshake no rompe a los demas", async () => {
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.0/30", ports: [443] })!],
      tcpCheck: async () => true,
      probe: async (h) => (h === "10.0.0.1" ? null : hit())
    });
    expect(r.stats.accepted).toBe(4);
    expect(r.stats.answered).toBe(3);
  });

  it("un DER ilegible cuenta como fallo de parseo, no como certificado", async () => {
    const r = await collectRangeSweep(ctx(), {
      ...base,
      ranges: [parseProbeRange({ range: "10.0.0.1/32", ports: [443] })!],
      tcpCheck: async () => true,
      probe: async () => hit({ der: Buffer.from("no soy un certificado") })
    });
    expect(r.items).toEqual([]);
    expect(r.parseFailures).toBe(1);
  });
});
