// test/bootstrap/install-cert-fallback.test.ts
//
// El enrolamiento con un privsvc que NO conoce `crypto.cert.stage`.
//
// ⚠️ NINGÚN WINDOWS INSTALADO DESDE LA 1.1.61 PUDO ENROLARSE.
//
// El bundle de CA viaja en su propio mensaje (`stage`, ADR-0015 pto. 10)
// porque el pipe de Windows corta a 64 KB por línea. El PrivSvc de Windows
// nunca implementó ese método: respondía `not_supported`, y el agente
// trataba cualquier fallo del `stage` como fallo del enrolamiento —
// reintentaba cada 30 s para siempre. Visto en campo el 2026-09-11.
//
// ── Por qué un socket de verdad y no un transporte doblado ───────────────
//
// La decisión depende de que el error conserve su CÓDIGO. Un transporte
// falso que lance `{ code: "not_supported" }` haría pasar el test aunque el
// `sendToPrivSvc` real tirara el código y dejara sólo el mensaje — que es
// exactamente lo que hacía antes de este arreglo. Aquí la respuesta tiene
// la forma que manda el privsvc por el pipe, y la lee el código real.

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import net from "net";
import fs from "fs";

const h = vi.hoisted(() => ({
  // Ruta corta a propósito: macOS limita la de un socket unix a ~104 B.
  sock: `/tmp/tr-stage-${process.pid}-${Math.random().toString(36).slice(2, 8)}.sock`
}));

vi.mock("../../src/bootstrap/config", () => ({
  config: { serverBaseUrl: "https://api.test.local", agentVersion: "9.9.9-test" }
}));
vi.mock("../../src/bootstrap/enrollment-store", () => ({
  EnrollmentStore: class {
    load() { return null; }
    save() {}
    clear() {}
    getPaths() { return { dir: "/tmp/x", enrollmentJson: "", clientCert: "", clientKey: "", caBundle: "" }; }
  }
}));
vi.mock("../../src/bootstrap/token-source", () => ({
  resolveEnrollmentToken: () => ({ token: "t", attempts: [] }),
  readEnrollmentToken: () => "t",
  describeTokenLookup: () => "",
  clearEnrollmentTokenFile: () => {}
}));
vi.mock("../../src/bootstrap/token-wait", () => ({
  waitForEnrollmentToken: async () => "t",
  clearBlockedMarker: () => {}
}));
vi.mock("../../src/platform/device-id", () => ({ getDeviceId: () => "device-under-test" }));
vi.mock("../../src/platform/privsvc-path", () => ({ getPrivSvcPipePath: () => h.sock }));
vi.mock("../../src/platform/enrollment-meta", () => ({ writeEnrollmentMetadata: async () => {} }));

import { installCertViaPrivSvc } from "../../src/bootstrap/enroll";

const HOJA = "-----BEGIN CERTIFICATE-----\nHOJA\n-----END CERTIFICATE-----\n";
const CADENA = "-----BEGIN CERTIFICATE-----\nCADENA\n-----END CERTIFICATE-----\n";

type Escenario = "privsvc_sin_stage" | "privsvc_con_stage" | "stage_averiado";
let escenario: Escenario;
let recibidos: any[];
let servidor: net.Server;

beforeAll(async () => {
  try { fs.unlinkSync(h.sock); } catch {}
  servidor = net.createServer((conn) => {
    let buf = "";
    conn.on("data", (d) => {
      buf += d.toString();
      const i = buf.indexOf("\n");
      if (i === -1) return;
      const req = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      recibidos.push(req);

      // La forma EXACTA del privsvc de Windows: el `_` de su router.
      let resp: any;
      if (req.method === "crypto.cert.stage") {
        if (escenario === "privsvc_sin_stage") {
          resp = { v: 1, id: req.id, ok: false, error: { code: "not_supported", message: "Unsupported method: crypto.cert.stage" } };
        } else if (escenario === "stage_averiado") {
          resp = { v: 1, id: req.id, ok: false, error: { code: "cert_stage_failed", message: "disco lleno" } };
        } else {
          resp = { v: 1, id: req.id, ok: true, result: { staged: true } };
        }
      } else if (req.method === "crypto.cert.install") {
        resp = {
          v: 1, id: req.id, ok: true,
          result: { clientCertThumbprint: "ABC123", issuingCaThumbprint: "I1", issuingCaThumbprints: ["I1", "I2"] }
        };
      } else {
        resp = { v: 1, id: req.id, ok: false, error: { code: "not_supported", message: "?" } };
      }
      conn.write(JSON.stringify(resp) + "\n");
    });
  });
  await new Promise<void>((r) => servidor.listen(h.sock, r));
});

afterAll(async () => {
  await new Promise<void>((r) => servidor.close(() => r()));
  try { fs.unlinkSync(h.sock); } catch {}
});

beforeEach(() => {
  recibidos = [];
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("installCertViaPrivSvc — stage opcional", () => {
  it("⚠️ con un privsvc que no conoce stage, el bundle viaja con la hoja y el enrolamiento termina", async () => {
    escenario = "privsvc_sin_stage";

    const r = await installCertViaPrivSvc(HOJA, CADENA);

    expect(r.clientCertThumbprint).toBe("ABC123");
    expect(recibidos.map((m) => m.method)).toEqual(["crypto.cert.stage", "crypto.cert.install"]);
    expect(recibidos[1].params.caBundlePem).toBe(CADENA);
    expect(recibidos[1].params.clientCertPem).toBe(HOJA);
  });

  it("con stage disponible, el bundle NO se repite en el install", async () => {
    // Mandarlo otra vez gastaría el margen del pipe que el stage existe
    // para conservar.
    escenario = "privsvc_con_stage";

    await installCertViaPrivSvc(HOJA, CADENA);

    expect(recibidos[0].params.caBundlePem).toBe(CADENA);
    expect(recibidos[1].params).not.toHaveProperty("caBundlePem");
  });

  it("un stage que falla por OTRA causa aborta y no instala", async () => {
    // `not_supported` es un privsvc viejo; cualquier otro código es una
    // avería, y seguir adelante instalaría una hoja sin su cadena.
    escenario = "stage_averiado";

    await expect(installCertViaPrivSvc(HOJA, CADENA)).rejects.toThrow(/disco lleno/);
    expect(recibidos.map((m) => m.method)).toEqual(["crypto.cert.stage"]);
  });

  it("devuelve todas las huellas de CA que informa el privsvc", async () => {
    escenario = "privsvc_con_stage";

    const r = await installCertViaPrivSvc(HOJA, CADENA);

    expect(r.issuingCaThumbprint).toBe("I1");
    expect(r.issuingCaThumbprints).toEqual(["I1", "I2"]);
  });
});
