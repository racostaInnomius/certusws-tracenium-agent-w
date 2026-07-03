// test/bootstrap/enroll-retry.test.ts
//
// Sprint 2 (aditivo) — bootstrap/enroll: el retry loop (5 intentos,
// backoff exponencial base ~1s: 1s, 2s, 4s, 8s) que envuelve la
// generación de CSR vía PrivSvc.
//
// ── Por qué se ejercita a través de la generación de CSR ────────────────
// `retry<T>()` en enroll.ts es un helper PRIVADO (no exportado). Testearlo
// directamente exigiría exportarlo = editar producción, fuera de alcance
// (aditivo, sin tocar el módulo). En su lugar conducimos la función
// EXPORTADA `ensureEnrolled()`, cuyo PRIMER uso del retry es:
//     const csr = await retry(() => generateCsrViaPrivSvc(), 5, 1000);
// Ese retry está ANTES del `while(true)` de enrollment con el backend, así
// que:
//   - éxito al 1er intento        → 1 conexión al pipe, sin sleeps
//   - éxito tardío (N fallos + OK) → N+1 conexiones, con backoff entre medias
//   - agotamiento (5 fallos)      → el error propaga y ensureEnrolled rechaza
//                                    ANTES de entrar al loop del backend
// La frontera de red/privsvc/gRPC se mockea en `net` (createConnection):
// cada intento de CSR abre un socket al named pipe; controlamos si ese
// socket "responde OK" o "falla".
//
// NOTA DE ALCANCE (informe): el retry del POST /enroll al backend vive
// dentro de un `while(true)` que en fallo hace `await sleep(30000)` y vuelve
// a iterar en vez de propagar — no es aislable como "agotamiento" sin
// exportar internals ni reescribir el loop. Se documenta y NO se testea el
// agotamiento de ESE segundo retry aquí. El comportamiento de 5-intentos +
// backoff exponencial queda cubierto por el retry del CSR, que es el mismo
// helper `retry()`.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "events";

// ── Mocks de frontera ───────────────────────────────────────────────────
const hoisted = vi.hoisted(() => ({
  // Cola de comportamientos por intento de CSR: "ok" | "fail".
  csrOutcomes: [] as Array<"ok" | "fail">,
  connectCount: { csr: 0, pipeWait: 0 }
}));

// config — el módulo real lee env/registry y puede lanzar al importar.
vi.mock("../../src/bootstrap/config", () => ({
  config: {
    serverBaseUrl: "https://api.test.local",
    agentVersion: "9.9.9-test"
  }
}));

// EnrollmentStore — fake en memoria; ninguna ruta de estas pruebas llega a
// save() (todas resuelven o rechazan durante la fase de CSR), pero load()/
// getPaths()/clear() se invocan.
const storeState: { current: any } = { current: null };
vi.mock("../../src/bootstrap/enrollment-store", () => ({
  EnrollmentStore: class {
    load() {
      return storeState.current;
    }
    save(s: any) {
      storeState.current = s;
    }
    clear() {
      storeState.current = null;
    }
    getPaths() {
      return {
        dir: "/tmp/x",
        enrollmentJson: "/tmp/x/enrollment.json",
        clientCert: "/tmp/x/mtls-client.crt.pem",
        clientKey: "/tmp/x/mtls-client.key.pem",
        caBundle: "/tmp/x/mtls-ca.pem"
      };
    }
  }
}));

// token-source — siempre hay token (no es modo local).
vi.mock("../../src/bootstrap/token-source", () => ({
  readEnrollmentToken: () => "bootstrap-token-xyz",
  clearEnrollmentTokenFile: () => {}
}));

vi.mock("../../src/platform/device-id", () => ({
  getDeviceId: () => "device-under-test"
}));
vi.mock("../../src/platform/privsvc-path", () => ({
  getPrivSvcPipePath: () => "/tmp/fake-privsvc.sock"
}));
vi.mock("../../src/platform/enrollment-meta", () => ({
  writeEnrollmentMetadata: async () => {}
}));

// fs — evita tocar disco (lock file, escritura de certs). No es modo local,
// así que buildLocalEnrollmentState no corre; sólo el lock usa fs.
vi.mock("fs", () => {
  const m = {
    existsSync: () => false,
    openSync: () => 3,
    closeSync: () => {},
    unlinkSync: () => {},
    writeFileSync: () => {}
  };
  return { default: m, ...m };
});

// net — cada createConnection representa un intento de conexión al pipe.
// waitForPrivSvcPipe hace una conexión "connect→destroy" (siempre OK aquí);
// generateCsrViaPrivSvc hace una conexión que responde JSON o falla según
// la cola de outcomes.
vi.mock("net", () => {
  function createConnection(_opts: any) {
    const sock: any = new EventEmitter();
    sock.write = vi.fn();
    sock.destroy = vi.fn();

    // Distinguimos la sonda de pipe (waitForPrivSvcPipe) de la petición CSR
    // por si el test consume la cola: la sonda NO escribe request, la CSR sí.
    // Como no podemos saberlo en createConnection, usamos un truco: la sonda
    // sólo espera "connect"; la CSR escribe tras "connect". Emitimos connect
    // en el próximo tick y, si el consumidor escribió, respondemos según cola.
    queueMicrotask(() => {
      sock.emit("connect");
      // Tras connect, si hubo write(), es la petición CSR.
      queueMicrotask(() => {
        if ((sock.write as any).mock.calls.length === 0) {
          // sonda de pipe: no responde nada; el caller ya hizo destroy en connect.
          hoisted.connectCount.pipeWait++;
          return;
        }
        hoisted.connectCount.csr++;
        const outcome = hoisted.csrOutcomes.shift() ?? "ok";
        if (outcome === "fail") {
          sock.emit("error", new Error("pipe connection refused"));
          return;
        }
        const resp = JSON.stringify({
          ok: true,
          result: { csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----" }
        });
        sock.emit("data", Buffer.from(resp + "\n"));
      });
    });
    return sock;
  }
  const api = { createConnection };
  return { default: api, ...api };
});

// fetch — el POST /enroll. En el agotamiento del CSR nunca se alcanza (el
// CSR falla antes). En los casos de éxito del CSR, el flujo entra al
// `while(true)` del backend; para que `ensureEnrolled` TERMINE de forma
// determinista (en vez de quedar en `await sleep(30000)` para siempre)
// devolvemos 401, que enroll.ts trata como ENROLL_FATAL: el retry interno
// NO lo reintenta y el catch del loop lo relanza ⇒ la promesa rechaza justo
// tras la fase de CSR. Así el conteo de conexiones CSR queda estable y el
// test no cuelga.
const fetchMock = vi.fn(async () => {
  return {
    ok: false,
    status: 401,
    text: async () => "unauthorized bootstrap token"
  } as any;
});
vi.stubGlobal("fetch", fetchMock);

import { ensureEnrolled } from "../../src/bootstrap/enroll";

beforeEach(() => {
  vi.useFakeTimers();
  hoisted.csrOutcomes = [];
  hoisted.connectCount = { csr: 0, pipeWait: 0 };
  storeState.current = null;
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

// Avanza microtasks + todos los timers pendientes en bucle hasta que la
// promesa de ensureEnrolled se asiente. El backoff del CSR usa setTimeout
// real (1s,2s,4s,8s); con fake timers hay que adelantarlos. Terminamos
// cuando la promesa resuelve/rechaza (marcada por el flag `done`).
async function driveToSettle(p: Promise<any>): Promise<void> {
  let done = false;
  p.finally(() => {
    done = true;
  });
  for (let i = 0; i < 40 && !done; i++) {
    await vi.advanceTimersByTimeAsync(0);
    // adelanta hasta 16s por iteración: cubre cualquier tramo del backoff.
    await vi.advanceTimersByTimeAsync(16_000);
  }
  await p;
}

describe("enroll — retry del CSR (5 intentos, backoff exponencial ~1s)", () => {
  it("éxito al primer intento: una sola conexión CSR, sin backoff", async () => {
    hoisted.csrOutcomes = ["ok"];

    // 401 en el POST ⇒ ENROLL_FATAL ⇒ ensureEnrolled rechaza tras el CSR OK.
    const p = ensureEnrolled().catch((e) => e);
    await driveToSettle(p);

    expect(hoisted.connectCount.csr).toBe(1);
  });

  it("éxito tardío: falla 2 veces y luego OK ⇒ 3 conexiones CSR", async () => {
    hoisted.csrOutcomes = ["fail", "fail", "ok"];

    const p = ensureEnrolled().catch((e) => e);
    await driveToSettle(p);

    expect(hoisted.connectCount.csr).toBe(3);
  });

  it("agotamiento: 5 fallos ⇒ 5 intentos CSR y ensureEnrolled rechaza (no entra al loop del backend)", async () => {
    hoisted.csrOutcomes = ["fail", "fail", "fail", "fail", "fail"];

    let rejected = false;
    const p = ensureEnrolled().catch((err) => {
      rejected = true;
      return err;
    });

    await driveToSettle(p);

    expect(hoisted.connectCount.csr).toBe(5); // exactamente 5 intentos
    expect(rejected).toBe(true); // propagó el último error
    expect(fetchMock).not.toHaveBeenCalled(); // nunca llegó al POST /enroll
  });
});
