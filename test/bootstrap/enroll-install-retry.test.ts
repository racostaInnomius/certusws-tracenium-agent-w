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
  estado: { current: null as any },
  // Respuestas del backend al POST /enroll, en orden. "ok" = certificado.
  respuestas: [] as Array<"ok" | "exhausted">,
  // Tokens que va devolviendo la espera de reemplazo, y cuántas veces se pidió.
  reemplazos: [] as string[],
  esperas: { n: 0 },
  reemplazo: async (_rechazado: string, _motivo: string) => {
    h.esperas.n += 1;
    return h.reemplazos.shift() ?? "token-de-reemplazo";
  },
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
  resolveEnrollmentToken: () => ({
    token: "bootstrap-token-xyz",
    source: "registry:64",
    location: "HKLM\\...\\ENROLLMENT_TOKEN (64-bit view)",
    attempts: [],
  }),
  readEnrollmentToken: () => "bootstrap-token-xyz",
  describeTokenLookup: () => "",
  clearEnrollmentTokenFile: () => {}
}));
vi.mock("../../src/bootstrap/token-wait", () => ({
  waitForEnrollmentToken: async () => "bootstrap-token-xyz",
  // ⚠️ Toda ruta NUEVA de enroll.ts necesita su doble aquí: el mock sustituye
  // al módulo ENTERO, así que una función que falte llega como `undefined` y
  // revienta al llamarla, no al importar.
  waitForReplacementToken: h.reemplazo,
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

const fetchMock = vi.fn(async () => {
  if (h.respuestas.length && h.respuestas[0] === "exhausted") {
    h.respuestas.shift();
    return {
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ error: "Token exhausted" }),
    } as any;
  }
  h.respuestas.shift();
  return ({
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
}) as any;
});
vi.stubGlobal("fetch", fetchMock);

import { ensureEnrolled } from "../../src/bootstrap/enroll";

beforeEach(() => {
  vi.useFakeTimers();
  h.instalaciones = [];
  h.metodos = [];
  h.respuestas = [];
  h.reemplazos = [];
  h.esperas.n = 0;
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

describe("token rechazado — no se reintenta, se espera otro", () => {
  it("un 403 'Token exhausted' NO repite el POST: pide un token de reemplazo", async () => {
    // ⚠️ El caso de campo (2026-09-22, T111): el MSI no reescribió el token al
    // reinstalar y el equipo mandaba el de agosto, con sus 42 usos gastados.
    // El 403 sólo era terminal si decía `Token expired`, así que "agotado"
    // caía en el reintento genérico: 5 vueltas con espera creciente y otra
    // ronda cada 30 s, para siempre, contra un token que no iba a mejorar.
    h.respuestas = ["exhausted", "ok"];
    h.reemplazos = ["token-nuevo-del-portal"];

    const estado = await hastaAsentar(ensureEnrolled());

    // DOS peticiones: la que fue rechazada y la que se hizo con el token
    // nuevo. Sin el arreglo, el primer 403 costaba cinco.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(h.esperas.n).toBe(1);

    // Y la segunda va con el token de reemplazo, no con el rechazado.
    const cuerpo = JSON.parse(String((fetchMock.mock.calls[1] as any)[1].body));
    expect(cuerpo.bootstrapToken).toBe("token-nuevo-del-portal");

    // El CSR no se regenera: la clave ya estaba, y el certificado se emite
    // para el mismo deviceId.
    expect(h.metodos.filter((m) => m === "crypto.csr.generate")).toHaveLength(1);
    expect(estado.deviceId).toBe("device-under-test");
  });

  it("y el equipo termina enrolado, sin morir por el camino", async () => {
    // Morir sería lo otro que no debe pasar: `ENROLL_FATAL` mata el arranque
    // y el gestor de servicios relanza el proceso — el bucle de 3722
    // arranques que token-wait.ts existe para evitar.
    h.respuestas = ["exhausted", "exhausted", "ok"];
    h.reemplazos = ["token-1", "token-2"];

    const estado = await hastaAsentar(ensureEnrolled());

    expect(h.esperas.n).toBe(2);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(estado.mtls.clientCertThumbprint).toBe("ABC123");
  });
});
