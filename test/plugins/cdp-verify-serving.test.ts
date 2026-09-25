// test/plugins/cdp-verify-serving.test.ts
//
// ADR-0033 F1, decisión D4 — «la verificación es una sonda, no la
// palabra del agente».
//
// ⚠️ Lo que este fichero vigila, por encima de todo lo demás, es UNA
// distinción: `matches: null` (no se pudo saber) frente a
// `matches: false` (contestó con otro certificado). Fundirlas rompe el
// producto en las dos direcciones — un servicio caído se reportaría como
// «sirve otro certificado» y un desajuste real podría esconderse detrás
// de un «no se pudo conectar»— y el ADR existe precisamente para no
// volver a dar por bueno lo que nadie comprobó (`runUpdateTask`
// reportando éxitos que no lo eran).
//
// El último bloque sondea un servidor TLS REAL levantado aquí. Un falso
// de la sonda demuestra la lógica, pero no que la huella que se calcula
// sea la que la CA y el control plane van a comparar.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import fs from "fs";
import net from "net";
import path from "path";
import tls from "tls";
import {
  CDP_VERIFY_SERVING_FACTS_NAMESPACE,
  CDP_VERIFY_SERVING_JOB_TYPE,
  MAX_TARGETS,
  normalizeFingerprint,
  parseVerifyServingPayload,
  probeTargets,
  runVerifyServingJob,
  type VerifyTarget
} from "../../src/plugins/cdp/verify-serving";
import type { KemProbeOutcome } from "../../src/plugins/cdp/providers/tls-listeners";
import { FIXTURE_CERT, FIXTURE_KEY } from "./tls-fixture";

const DER_A = new crypto.X509Certificate(FIXTURE_CERT).raw;
const HUELLA_A = crypto.createHash("sha256").update(DER_A).digest("hex");
const DER_B = Buffer.from("otro certificado cualquiera");
const HUELLA_B = crypto.createHash("sha256").update(DER_B).digest("hex");

function sirviendo(der: Buffer): KemProbeOutcome {
  return {
    ok: true,
    probe: {
      der,
      chainDepth: 2,
      chainAuthorized: true,
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      kexGroup: "X25519",
      kemHybrid: false
    }
  };
}

const enqueueFalso = () => {
  const enviados: any[] = [];
  return { enviados, enqueue: (p: unknown) => (enviados.push(p), enviados.length) };
};

// ── El payload ──────────────────────────────────────────────────────

describe("parseVerifyServingPayload", () => {
  it("el host por defecto es loopback, y el SNI sale de él", () => {
    const p = parseVerifyServingPayload({ targets: [{ port: 443 }] });
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    expect(p.targets[0]).toEqual({ host: "127.0.0.1", port: 443, sni: "localhost" });
  });

  it("un nombre se manda como SNI; una IP que no es loopback, sin SNI", () => {
    const p = parseVerifyServingPayload({
      targets: [{ host: "Web01.Corp", port: 443 }, { host: "10.0.0.5", port: 8443 }]
    });
    if (!p.ok) throw new Error(p.error);
    expect(p.targets[0].sni).toBe("web01.corp");
    // Mandar un SNI que no es un nombre es mentirle al servidor; muchos
    // devuelven igual su certificado por defecto.
    expect(p.targets[1].sni).toBe("");
  });

  it("el SNI explícito gana (vhost detrás de un puerto)", () => {
    const p = parseVerifyServingPayload({ targets: [{ port: 443, sni: "tienda.corp" }] });
    if (!p.ok) throw new Error(p.error);
    expect(p.targets[0].sni).toBe("tienda.corp");
  });

  it("el preámbulo StartTLS se deduce del puerto y se puede forzar", () => {
    const porPuerto = parseVerifyServingPayload({ targets: [{ port: 587 }] });
    if (!porPuerto.ok) throw new Error(porPuerto.error);
    expect(porPuerto.targets[0].startTls).toBe("smtp");

    // Un SMTP mudado al 2525 quedaría como «no contesta» sin esto.
    const forzado = parseVerifyServingPayload({ targets: [{ port: 2525, startTls: "SMTP" }] });
    if (!forzado.ok) throw new Error(forzado.error);
    expect(forzado.targets[0].startTls).toBe("smtp");
  });

  it("normaliza la huella esperada (mayúsculas y dos puntos)", () => {
    const conDosPuntos = HUELLA_A.toUpperCase().replace(/(.{2})(?=.)/g, "$1:");
    expect(normalizeFingerprint(conDosPuntos)).toBe(HUELLA_A);
    const p = parseVerifyServingPayload({ targets: [{ port: 443 }], expectFingerprint256: conDosPuntos });
    if (!p.ok) throw new Error(p.error);
    expect(p.expect).toBe(HUELLA_A);
  });

  it("rechaza el payload ENTERO ante cualquier objetivo imposible", () => {
    // A medias sería peor: sondear los buenos y callar los malos
    // reportaría éxito habiendo verificado menos de lo pedido.
    const malos: any[] = [
      {},
      { targets: [] },
      { targets: "127.0.0.1:443" },
      { targets: [{ port: 0 }] },
      { targets: [{ port: 70000 }] },
      { targets: [{ port: "no" }] },
      { targets: [{ host: "a b", port: 443 }] },
      { targets: [{ port: 443, startTls: "gopher" }] },
      { targets: [{ port: 443 }], expectFingerprint256: "abc" },
      { targets: Array.from({ length: MAX_TARGETS + 1 }, (_, i) => ({ port: 400 + i })) }
    ];
    for (const m of malos) {
      expect(parseVerifyServingPayload(m).ok, JSON.stringify(m)).toBe(false);
    }
  });

  it("acepta exactamente el tope de objetivos", () => {
    const p = parseVerifyServingPayload({
      targets: Array.from({ length: MAX_TARGETS }, (_, i) => ({ port: 400 + i }))
    });
    expect(p.ok).toBe(true);
  });
});

// ── La distinción que justifica el job ──────────────────────────────

describe("⭐ null no es false", () => {
  const objetivo: VerifyTarget = { host: "127.0.0.1", port: 8443, sni: "localhost" };

  it("el puerto no contesta → matches null y un motivo, NUNCA false", async () => {
    const [r] = await probeTargets([objetivo], HUELLA_A, {
      probe: async () => ({ ok: false, code: "ECONNREFUSED" })
    });
    expect(r.answered).toBe(false);
    expect(r.matches).toBeNull();
    // «Nunca un éxito vacío»: si no contestó, hay razón.
    expect(r.error).toBe("ECONNREFUSED");
    expect(r.fingerprint256).toBeUndefined();
  });

  it("contesta con OTRO certificado → matches false", async () => {
    const [r] = await probeTargets([objetivo], HUELLA_A, { probe: async () => sirviendo(DER_B) });
    expect(r.answered).toBe(true);
    expect(r.matches).toBe(false);
    expect(r.fingerprint256).toBe(HUELLA_B);
    // Y se dice QUÉ sirve, no solo que no coincide: sin la huella
    // servida, nadie puede averiguar qué certificado quedó puesto.
    expect(r.error).toBeUndefined();
  });

  it("contesta con el esperado → matches true, con lo negociado", async () => {
    const [r] = await probeTargets([objetivo], HUELLA_A, { probe: async () => sirviendo(DER_A) });
    expect(r.matches).toBe(true);
    expect(r.protocol).toBe("TLSv1.3");
    expect(r.cipher).toBe("TLS_AES_256_GCM_SHA384");
    expect(r.kexGroup).toBe("X25519");
    expect(r.chainAuthorized).toBe(true);
    expect(r.chainDepth).toBe(2);
  });

  it("sin expectativa, matches es null aunque conteste", async () => {
    const [r] = await probeTargets([objetivo], null, { probe: async () => sirviendo(DER_A) });
    expect(r.answered).toBe(true);
    expect(r.fingerprint256).toBe(HUELLA_A);
    expect(r.matches).toBeNull();
  });

  it("una sonda que REVIENTA es un motivo, no un job caído", async () => {
    const [r] = await probeTargets([objetivo], HUELLA_A, {
      probe: async () => {
        throw new Error("boom");
      }
    });
    expect(r.answered).toBe(false);
    expect(r.matches).toBeNull();
    expect(r.error).toContain("boom");
  });
});

// ── Topes ───────────────────────────────────────────────────────────

describe("presupuesto", () => {
  it("un objetivo que se cuelga se corta con su motivo", async () => {
    const [r] = await probeTargets([{ host: "127.0.0.1", port: 9443, sni: "localhost" }], HUELLA_A, {
      probe: () => new Promise<KemProbeOutcome>(() => {}),
      targetBudgetMs: 30
    });
    expect(r.answered).toBe(false);
    expect(r.matches).toBeNull();
    expect(r.error).toBe("target_budget_exhausted");
  });

  it("⭐ agotado el reloj total, lo que no se intentó SE DICE", async () => {
    // Callarlo dejaría objetivos sin verificar dentro de una respuesta
    // que parece completa.
    let t = 0;
    const objetivos: VerifyTarget[] = Array.from({ length: 6 }, (_, i) => ({
      host: "127.0.0.1",
      port: 1000 + i,
      sni: "localhost"
    }));
    const r = await probeTargets(objetivos, HUELLA_A, {
      probe: async () => {
        t += 100; // cada sonda consume reloj
        return sirviendo(DER_A);
      },
      now: () => t,
      totalBudgetMs: 250
    });
    const agotados = r.filter((x) => x.error === "total_budget_exhausted");
    expect(agotados.length).toBeGreaterThan(0);
    for (const a of agotados) {
      expect(a.answered).toBe(false);
      expect(a.matches).toBeNull();
    }
  });
});

// ── El job ──────────────────────────────────────────────────────────

describe("runVerifyServingJob", () => {
  it("manda el informe en su namespace y resume en el ACK", async () => {
    const { enviados, enqueue } = enqueueFalso();
    const ack = await runVerifyServingJob(
      { enqueue, probe: async (t) => (t.port === 443 ? sirviendo(DER_A) : { ok: false, code: "ECONNREFUSED" }) },
      { jobId: "job-1", payload: { targets: [{ port: 443 }, { port: 8443 }], expectFingerprint256: HUELLA_A } }
    );

    expect(ack.status).toBe(0);
    expect(ack.message).toContain("probed=2");
    expect(ack.message).toContain("matched=1");
    expect(ack.message).toContain("unknown=1");

    expect(enviados).toHaveLength(1);
    const payload = enviados[0];
    // Viaja SOLA en su namespace, como live_query y dex.
    expect(Object.keys(payload.namespaces)).toEqual([CDP_VERIFY_SERVING_FACTS_NAMESPACE]);
    expect(payload.schemaVersion).toBeTruthy();
    const informe = payload.namespaces[CDP_VERIFY_SERVING_FACTS_NAMESPACE];
    expect(informe.jobId).toBe("job-1");
    expect(informe.expectFingerprint256).toBe(HUELLA_A);
    expect(informe.targets).toHaveLength(2);
    expect(informe.summary).toEqual({ probed: 2, answered: 1, matched: 1, mismatched: 0, unknown: 1 });
  });

  it("un desajuste se reporta como desajuste, no como fallo del job", async () => {
    // El job hizo su trabajo: el veredicto `installed_not_serving` lo
    // pone el control plane. Un status != 0 haría que el job apareciera
    // como fallido y el operador buscaría el problema donde no está.
    const { enviados, enqueue } = enqueueFalso();
    const ack = await runVerifyServingJob(
      { enqueue, probe: async () => sirviendo(DER_B) },
      { jobId: "job-2", payload: { targets: [{ port: 443 }], expectFingerprint256: HUELLA_A } }
    );
    expect(ack.status).toBe(0);
    expect(ack.message).toContain("mismatched=1");
    expect(enviados[0].namespaces[CDP_VERIFY_SERVING_FACTS_NAMESPACE].targets[0].matches).toBe(false);
  });

  it("un payload imposible no manda nada y se acusa como rechazado", async () => {
    const { enviados, enqueue } = enqueueFalso();
    const ack = await runVerifyServingJob({ enqueue }, { jobId: "job-3", payload: { targets: [] } });
    expect(ack.status).toBe(2);
    expect(ack.message).toContain("bad_payload");
    expect(enviados).toHaveLength(0);
  });
});

// ── Enrutado ────────────────────────────────────────────────────────

describe("el job está enrutado y gateado como los demás de CDP", () => {
  const fuente = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
  const despachador = fuente.slice(fuente.indexOf("switch (jobType)"));

  it("hay un case, y pide el plugin cdp", () => {
    // El precedente está escrito en cdp-job-routing.test.ts: las fases 2
    // y 3 de ADR-0011 viajaron MUERTAS en dos versiones por no tener
    // `case` aquí.
    expect(despachador).toContain("case CDP_VERIFY_SERVING_JOB_TYPE");
    const bloque = despachador.slice(despachador.indexOf("case CDP_VERIFY_SERVING_JOB_TYPE"));
    const cuerpo = bloque.slice(0, bloque.indexOf("\n    case ", 10));
    expect(cuerpo).toContain('pluginEnabled("cdp")');
    expect(cuerpo).toContain("runVerifyServingJob");
    // ⚠️ NO por `collectFactsSnapshot`: su enfriamiento descarta una
    // segunda recogida de CDP seguida, que es exactamente lo que es una
    // verificación hecha segundos después de instalar.
    expect(cuerpo).not.toContain("collectFactsSnapshot");
  });

  it("el nombre del job es el que el backend despacha", () => {
    expect(CDP_VERIFY_SERVING_JOB_TYPE).toBe("cdp_verify_serving");
  });
});

// ── Contra un servidor TLS de verdad ────────────────────────────────

describe("sonda real (servidor TLS levantado aquí)", () => {
  it("⭐ la huella es la del certificado servido, y un puerto cerrado no es un desajuste", async () => {
    const server = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT }, (s) => s.end());
    const puerto: number = await new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
    });

    // Un puerto que nadie escucha: se abre y se cierra para tener uno
    // libre de verdad.
    const cerrado: number = await new Promise((resolve) => {
      const s = net.createServer();
      s.listen(0, "127.0.0.1", () => {
        const p = (s.address() as net.AddressInfo).port;
        s.close(() => resolve(p));
      });
    });

    try {
      const { enviados, enqueue } = enqueueFalso();
      const ack = await runVerifyServingJob(
        { enqueue },
        {
          jobId: "job-real",
          payload: {
            targets: [{ port: puerto }, { port: cerrado }],
            // La huella que el control plane guardará viene de X509:
            // comprobamos que la que calcula el agente es LA MISMA.
            expectFingerprint256: new crypto.X509Certificate(FIXTURE_CERT).fingerprint256
          }
        }
      );
      expect(ack.status).toBe(0);

      const informe = enviados[0].namespaces[CDP_VERIFY_SERVING_FACTS_NAMESPACE];
      const servido = informe.targets.find((t: any) => t.port === puerto);
      const muerto = informe.targets.find((t: any) => t.port === cerrado);

      expect(servido.matches).toBe(true);
      expect(servido.fingerprint256).toBe(HUELLA_A);
      expect(servido.protocol).toMatch(/^TLSv1/);
      expect(servido.cipher).toBeTruthy();

      // Y el que no contesta: null, con su motivo. Nada de false.
      expect(muerto.answered).toBe(false);
      expect(muerto.matches).toBeNull();
      expect(muerto.error).toMatch(/ECONNREFUSED|closed|timeout/i);

      expect(informe.summary).toEqual({ probed: 2, answered: 1, matched: 1, mismatched: 0, unknown: 1 });
    } finally {
      await new Promise((r) => server.close(r));
    }
  }, 30_000);
});
