// test/bootstrap/enroll-install-retry.test.ts
//
// El certificado se pide UNA vez; si falla la instalación local, se
// reintenta SÓLO la instalación.
//
// ⚠️ UN EQUIPO AGOTÓ UN TOKEN DE FLOTA ENTERO EN 18 MINUTOS (2026-09-11).
//
// El bucle de `ensureEnrolled` envolvía a la vez el `POST /enroll` y la
// instalación local. Un fallo DESPUÉS de obtener el certificado —el
// privsvc de Windows no conocía `crypto.cert.stage`— repetía el
// enrolamiento completo cada 30 s: cada vuelta emitía un certificado nuevo
// y gastaba un uso del token de bootstrap. 37 certificados y un token de 38
// usos agotado, que dejó a todos los demás equipos sin poder enrolarse.
//
// Lo que se sostiene aquí es la cuenta: N fallos de instalación = 1 solo
// POST.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "events";

const h = vi.hoisted(() => ({
  instalaciones: [] as Array<"ok" | "fail">,
  metodos: [] as string[],
  estado: { current: null as any }
}));

vi.mock("../../src/bootstrap/config", () => ({
  config: { serverBaseUrl: "https://api.test.local", agentVersion: "9.9.9-test" }
}));
vi.mock("../../src/bootstrap/enrollment-store", () => ({
  EnrollmentStore: class {
    load() { return h.estado.current; }
    save(s: any) { h.estado.current = s; }
    clear() { h.estado.current = null; }
    getPaths() {
      return {
        dir: "/tmp/x", enrollmentJson: "/tmp/x/enrollment.json",
        clientCert: "/tmp/x/mtls-client.crt.pem", clientKey: "/tmp/x/mtls-client.key.pem",
        caBundle: "/tmp/x/mtls-ca.pem"
      };
    }
  }
}));
vi.mock("../../src/bootstrap/token-source", () => ({
  resolveEnrollmentToken: () => ({ token: "bootstrap-token-xyz", attempts: [] }),
  readEnrollmentToken: () => "bootstrap-token-xyz",
  describeTokenLookup: () => "",
  clearEnrollmentTokenFile: () => {}
}));
vi.mock("../../src/bootstrap/token-wait", () => ({
  waitForEnrollmentToken: async () => "bootstrap-token-xyz",
  clearBlockedMarker: () => {}
}));
vi.mock("../../src/platform/device-id", () => ({ getDeviceId: () => "device-under-test" }));
vi.mock("../../src/platform/privsvc-path", () => ({ getPrivSvcPipePath: () => "/tmp/fake-privsvc.sock" }));
vi.mock("../../src/platform/enrollment-meta", () => ({ writeEnrollmentMetadata: async () => {} }));
vi.mock("fs", () => {
  const m = { existsSync: () => false, openSync: () => 3, closeSync: () => {}, unlinkSync: () => {}, writeFileSync: () => {} };
  return { default: m, ...m };
});

// El privsvc, por método. Cada conexión es una petición; la sonda del
// pipe (waitForPrivSvcPipe) conecta y no escribe.
vi.mock("net", () => {
  function createConnection() {
    const sock: any = new EventEmitter();
    sock.write = vi.fn();
    sock.destroy = vi.fn();
    queueMicrotask(() => {
      sock.emit("connect");
      queueMicrotask(() => {
        const llamada = sock.write.mock.calls[0];
        if (!llamada) return;
        const req = JSON.parse(String(llamada[0]).trim());
        h.metodos.push(req.method);
        let resp: any;
        if (req.method === "crypto.csr.generate") {
          resp = { ok: true, result: { csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMII\n-----END CERTIFICATE REQUEST-----" } };
        } else if (req.method === "crypto.cert.stage") {
          resp = { ok: true, result: { staged: true } };
        } else if (req.method === "crypto.cert.install") {
          const r = h.instalaciones.shift() ?? "ok";
          resp = r === "ok"
            ? { ok: true, result: { clientCertThumbprint: "ABC123", issuingCaThumbprint: "I1" } }
            : { ok: false, error: { code: "cert_install_error", message: "almacén bloqueado" } };
        } else {
          resp = { ok: false, error: { code: "not_supported", message: `Unsupported method: ${req.method}` } };
        }
        sock.emit("data", Buffer.from(JSON.stringify(resp) + "\n"));
      });
    });
    return sock;
  }
  const api = { createConnection };
  return { default: api, ...api };
});

const fetchMock = vi.fn(async () => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify({
    tenantId: "1",
    deviceId: "device-under-test",
    mTls: {
      clientCertPem: "-----BEGIN CERTIFICATE-----\nHOJA\n-----END CERTIFICATE-----\n",
      caBundlePem: "-----BEGIN CERTIFICATE-----\nCADENA\n-----END CERTIFICATE-----\n"
    }
  })
}) as any);
vi.stubGlobal("fetch", fetchMock);

import { ensureEnrolled } from "../../src/bootstrap/enroll";

beforeEach(() => {
  vi.useFakeTimers();
  h.instalaciones = [];
  h.metodos = [];
  h.estado.current = null;
  fetchMock.mockClear();
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function hastaAsentar<T>(p: Promise<T>): Promise<T> {
  let hecho = false;
  p.finally(() => { hecho = true; }).catch(() => {});
  for (let i = 0; i < 60 && !hecho; i++) {
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(16_000);
  }
  return p;
}

const instalaciones = () => h.metodos.filter((m) => m === "crypto.cert.install").length;

describe("enrolamiento — el certificado se pide una sola vez", () => {
  it("sin fallos: un POST, una instalación", async () => {
    const estado = await hastaAsentar(ensureEnrolled());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(instalaciones()).toBe(1);
    expect(estado.mtls.clientCertThumbprint).toBe("ABC123");
  });

  it("⚠️ una instalación que falla NO vuelve a pedir el certificado", async () => {
    h.instalaciones = ["fail", "ok"];

    const estado = await hastaAsentar(ensureEnrolled());

    expect(instalaciones()).toBe(2);
    // La cuenta que importa: un fallo local no gasta otro uso del token
    // ni emite otro certificado en el backend.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(estado.mtls.clientCertThumbprint).toBe("ABC123");
  });

  it("⚠️ varios fallos seguidos siguen siendo UN solo POST", async () => {
    // El caso de campo: 37 vueltas. Aquí cinco.
    h.instalaciones = ["fail", "fail", "fail", "fail", "fail", "ok"];

    await hastaAsentar(ensureEnrolled());

    expect(instalaciones()).toBe(6);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
