// test/transport/grpc-stream.test.ts
//
// P0 — supervivencia del stream gRPC: backoff, circuit breaker, watchdog
// de silencio (comportamiento POST-fix idle-churn 2026-06-30) y reset del
// contador de reintentos.
//
// Fronteras mockeadas (naturales, no internals):
//   - ./grpc-client        → createGrpcClient devuelve un cliente fake cuyo
//                            Connect() entrega un EventEmitter con la misma
//                            superficie que el stream real (write/end/
//                            getLastServerActivityMs/getLastClientSendOkMs).
//   - ../queue/sqlite-outbox → el módulo real construye un singleton con DB
//                            en disco AL IMPORTAR; aquí se reemplaza por un
//                            fake en memoria.
//   - policy-store, device-facts-builder, pmp/state, pmp/remediation,
//     update-task           → dependencias del dispatcher de jobs; ninguna
//                            participa en los escenarios P0 pero sus imports
//                            arrastran fs/systeminformation/etc.
//   - node-pty / node-datachannel NUNCA se cargan: los únicos caminos que
//     los requieren (plugins/rcp) son require() lazy dentro de handlers que
//     estos tests no disparan.
//
// El módulo grpc-stream mantiene estado a nivel módulo (reconnectAttempts,
// reconnecting, metricsFlushTimer) → cada test hace vi.resetModules() y
// re-importa para partir de estado limpio.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { EventEmitter } from "events";

const mocks = vi.hoisted(() => ({
  createGrpcClient: vi.fn(),
  outbox: {
    enqueue: vi.fn(() => 1),
    leaseReady: vi.fn(() => [] as any[]),
    markSent: vi.fn(),
    markFailed: vi.fn(),
    markRejected: vi.fn(),
    recoverStaleInflight: vi.fn(),
    hasPendingOfType: vi.fn(() => false),
    cleanup: vi.fn(),
    getState: vi.fn(() => null as string | null),
    setState: vi.fn(),
    onChanged: vi.fn(() => () => {}),
    getNextReadyDelayMs: vi.fn(() => null as number | null)
  }
}));

vi.mock("../../src/transport/grpc-client", () => ({
  createGrpcClient: mocks.createGrpcClient
}));
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox: mocks.outbox }));
vi.mock("../../src/core/policy-store", () => ({
  PolicyStore: { computeHash: vi.fn(() => "hash") }
}));
vi.mock("../../src/domain/device-facts-builder", () => ({
  buildDeviceFacts: vi.fn(async () => ({}))
}));
vi.mock("../../src/plugins/pmp/state", () => ({
  updatePmpState: vi.fn(),
  isRemediateInFlight: vi.fn(() => false)
}));
vi.mock("../../src/plugins/pmp/remediation", () => ({ runRemediation: vi.fn() }));
vi.mock("../../src/update/update-task", () => ({ runUpdateTask: vi.fn() }));

// ── Constantes espejo del módulo bajo test ──────────────────────────────
const SILENCE_THRESHOLD_MS = 270_000;
const WATCHDOG_TICK_MS = 30_000;
const HEARTBEAT_INTERVAL_MS = 60_000;
const MAX_ATTEMPTS_BREAKER = 30;
// Delay máximo real de reconexión: min(exp + jitter, RECONNECT_MAX_MS * 2)
// = 120s (ver nota en el test de rangos).
const MAX_RECONNECT_DELAY_MS = 120_000;
// Ventana de avance que garantiza que el timer de reconexión venza.
const CYCLE_MS = MAX_RECONNECT_DELAY_MS + 10_000;

type FakeStream = EventEmitter & {
  written: any[];
  write: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
  lastServerActivityMs: number;
  lastClientSendOkMs: number;
  getLastServerActivityMs: () => number;
  getLastClientSendOkMs: (() => number) | undefined;
};

let streams: FakeStream[];
let clients: Array<{ Connect: () => FakeStream; isConnected: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> }>;
let ctx: any;

function makeFakeStream(): FakeStream {
  const s = new EventEmitter() as FakeStream;
  s.written = [];
  s.write = vi.fn((msg: any) => {
    s.written.push(msg);
    return true;
  });
  s.end = vi.fn();
  s.lastServerActivityMs = Date.now();
  s.lastClientSendOkMs = Date.now();
  s.getLastServerActivityMs = () => s.lastServerActivityMs;
  s.getLastClientSendOkMs = () => s.lastClientSendOkMs;
  return s;
}

function latestStream(): FakeStream {
  return streams[streams.length - 1];
}

function makeCtx() {
  return {
    config: { agentVersion: "1.1.21-test" },
    agent: { version: "1.1.21-test", platform: "test" },
    enrollment: {
      tenantId: "tenant-1",
      deviceId: "device-1",
      enrolledAtUtc: "2026-01-01T00:00:00.000Z",
      mtls: { clientCertPath: "/dev/null", caBundlePath: "/dev/null" },
      bootstrap: { channel: "stable", capabilities: ["amp"] }
    },
    store: { save: vi.fn() },
    priv: { call: vi.fn(async () => ({ ok: true })), close: vi.fn() },
    policy: { getVersion: () => "pv1", getHash: () => "ph1", save: vi.fn(async () => {}) },
    policyRuntime: {
      getEnabledPlugins: () => [],
      isInventoryEnabled: () => false,
      isComplianceEnabled: () => false,
      isPatchEnabled: () => false,
      isFeatureEnabled: () => false,
      pluginEnabled: () => false,
      applyUpdate: vi.fn(async () => {}),
      snapshot: () => ({})
    },
    plugins: { run: vi.fn(async () => ({})) },
    trayStatus: {
      markGrpcDisconnected: vi.fn(),
      markJobStarted: vi.fn(),
      markJobFinished: vi.fn(),
      markPolicyApplied: vi.fn()
    },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
  };
}

/** Entradas de log "scheduling reconnect" → [{ delayMs, attempt, reason }] */
function reconnectSchedules(): Array<{ delayMs: number; attempt: number; reason: string }> {
  return ctx.logger.warn.mock.calls
    .filter((c: any[]) => c[0] === "gRPC stream: scheduling reconnect")
    .map((c: any[]) => c[1]);
}

async function importFreshModule() {
  vi.resetModules();
  return await import("../../src/transport/grpc-stream");
}

async function startFresh() {
  const mod = await importFreshModule();
  const stopHandle = mod.startGrpcStream(ctx);
  return { mod, stopHandle };
}

/** Rompe el stream vigente y deja vencer el timer de reconexión. */
async function failAndReconnect() {
  latestStream().emit("error", new Error("boom"));
  await vi.advanceTimersByTimeAsync(CYCLE_MS);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  streams = [];
  clients = [];
  mocks.outbox.leaseReady.mockReturnValue([]);
  mocks.outbox.getState.mockReturnValue(null);
  mocks.outbox.getNextReadyDelayMs.mockReturnValue(null);
  mocks.outbox.onChanged.mockReturnValue(() => {});
  mocks.createGrpcClient.mockImplementation(() => {
    const stream = makeFakeStream();
    streams.push(stream);
    const client = {
      Connect: () => stream,
      isConnected: vi.fn(() => true),
      close: vi.fn()
    };
    clients.push(client);
    return client;
  });
  ctx = makeCtx();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("grpc-stream — backoff exponencial con jitter", () => {
  it("los delays crecen exponencialmente y cada uno cae en su rango [exp, min(2·exp, 120s)]", async () => {
    // NOTA (divergencia código vs. comentario del propio módulo):
    // el comentario en src/transport/grpc-stream.ts:45-51 documenta
    // "attempt 0 → 0..2s ... capped at 30..60s", pero la implementación
    // incrementa reconnectAttempts ANTES de computar el delay
    // (scheduleReconnect, línea ~1097 vs ~1117), así que el primer delay
    // real es [4s, 8s) y el cap real es [60s, 120s] — RECONNECT_MAX_MS*2.
    // Este test congela el comportamiento REAL.
    await startFresh();

    const expectedRanges: Array<[number, number]> = [];
    for (let attempt = 1; attempt <= 7; attempt++) {
      const exp = Math.min(2_000 * Math.pow(2, Math.min(attempt, 6)), 60_000);
      expectedRanges.push([exp, Math.min(exp * 2, MAX_RECONNECT_DELAY_MS)]);
    }

    for (let i = 0; i < 7; i++) {
      await failAndReconnect();
    }

    const schedules = reconnectSchedules();
    expect(schedules).toHaveLength(7);

    schedules.forEach((s, i) => {
      expect(s.attempt).toBe(i + 1);
      const [min, max] = expectedRanges[i];
      expect(s.delayMs, `attempt ${i + 1}`).toBeGreaterThanOrEqual(min);
      expect(s.delayMs, `attempt ${i + 1}`).toBeLessThanOrEqual(max);
    });

    // El piso del backoff crece hasta el cap: 4s, 8s, 16s, 32s, 60s, 60s...
    expect(expectedRanges.map(([min]) => min)).toEqual([
      4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000
    ]);
  });

  it("error y end consecutivos sobre el mismo stream roto agendan UNA sola reconexión", async () => {
    await startFresh();
    const s = latestStream();

    s.emit("error", new Error("broken pipe"));
    s.emit("end");

    expect(reconnectSchedules()).toHaveLength(1);
  });
});

describe("grpc-stream — circuit breaker (30 intentos consecutivos)", () => {
  it("al intento 30 sin READY: no agenda más reconexiones y hace process.exit(1) tras ~500ms", async () => {
    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation(((..._args: any[]) => undefined) as any);

    await startFresh();

    // 29 ciclos completos fallo→reconexión
    for (let i = 0; i < MAX_ATTEMPTS_BREAKER - 1; i++) {
      await failAndReconnect();
    }
    expect(reconnectSchedules()).toHaveLength(MAX_ATTEMPTS_BREAKER - 1);
    expect(exitSpy).not.toHaveBeenCalled();

    // Fallo n.º 30 → breaker: salida limpia, sin reconexión n.º 30
    latestStream().emit("error", new Error("boom"));

    expect(
      ctx.logger.error.mock.calls.some((c: any[]) =>
        String(c[0]).includes("circuit breaker tripped")
      )
    ).toBe(true);
    expect(ctx.trayStatus.markGrpcDisconnected).toHaveBeenCalled();
    expect(reconnectSchedules()).toHaveLength(MAX_ATTEMPTS_BREAKER - 1);

    // El exit se difiere 500ms para que el log llegue a disco
    expect(exitSpy).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(600);
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("grpc-stream — watchdog de silencio (post-fix idle-churn 2026-06-30)", () => {
  async function connectReady() {
    await startFresh();
    const s = latestStream();
    s.emit("data", { connected: true });
    return s;
  }

  it("silencio BIDIRECCIONAL > 270s → detecta zombie, marca tray desconectado y agenda reconexión", async () => {
    const s = await connectReady();
    // Ninguna dirección se refresca → ambas envejecen juntas
    await vi.advanceTimersByTimeAsync(SILENCE_THRESHOLD_MS + WATCHDOG_TICK_MS + 1_000);

    expect(
      ctx.logger.warn.mock.calls.some((c: any[]) =>
        String(c[0]).includes("bidirectional silence past threshold")
      )
    ).toBe(true);
    expect(ctx.trayStatus.markGrpcDisconnected).toHaveBeenCalled();
    const schedules = reconnectSchedules();
    expect(schedules.length).toBeGreaterThanOrEqual(1);
    expect(schedules[0].reason).toBe("stream_error");
    // El stream viejo quedó fuera de servicio
    expect(s.listenerCount("data")).toBe(0);
  });

  it("FREEZE del fix: tráfico saliente sin entrante NO marca desconexión falsa (idle-churn)", async () => {
    // Escenario exacto del bug 2026-05/06: dispositivo idle, el server no
    // ACKea heartbeats por diseño → lastServerActivityMs no se mueve, pero
    // el agente sigue escribiendo OK. ANTES del fix esto reconectaba cada
    // 270s; DESPUÉS, el watchdog exige que AMBAS direcciones estén muertas.
    const s = await connectReady();

    // 20 minutos de idle "receive-only stale": refrescamos el stamp de
    // escritura en cada tick del watchdog, el de recepción jamás.
    for (let i = 0; i < 40; i++) {
      s.lastClientSendOkMs = Date.now();
      await vi.advanceTimersByTimeAsync(WATCHDOG_TICK_MS);
    }

    expect(
      ctx.logger.warn.mock.calls.some((c: any[]) =>
        String(c[0]).includes("bidirectional silence past threshold")
      )
    ).toBe(false);
    expect(reconnectSchedules()).toHaveLength(0);
    expect(ctx.trayStatus.markGrpcDisconnected).not.toHaveBeenCalled();
  });

  it("simétrico: tráfico entrante sin salidas recientes tampoco dispara el watchdog", async () => {
    const s = await connectReady();

    for (let i = 0; i < 40; i++) {
      s.lastServerActivityMs = Date.now();
      await vi.advanceTimersByTimeAsync(WATCHDOG_TICK_MS);
    }

    expect(reconnectSchedules()).toHaveLength(0);
  });

  it("bridge viejo sin getLastClientSendOkMs: cae al chequeo receive-only (comportamiento pre-fix)", async () => {
    // Documenta el fallback deliberado: sendIdleMs = Infinity cuando el
    // bridge no expone el stamp de escritura → basta el silencio entrante.
    await startFresh();
    const s = latestStream();
    s.getLastClientSendOkMs = undefined;
    s.emit("data", { connected: true });

    await vi.advanceTimersByTimeAsync(SILENCE_THRESHOLD_MS + WATCHDOG_TICK_MS + 1_000);

    expect(
      ctx.logger.warn.mock.calls.some((c: any[]) =>
        String(c[0]).includes("bidirectional silence past threshold")
      )
    ).toBe(true);
    expect(reconnectSchedules().length).toBeGreaterThanOrEqual(1);
  });

  it("heartbeat que ve isConnected()===false fuerza reconexión inmediata (Patch D)", async () => {
    await connectReady();
    clients[clients.length - 1].isConnected.mockReturnValue(false);

    await vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL_MS + 1_000);

    expect(
      ctx.logger.warn.mock.calls.some((c: any[]) =>
        String(c[0]).includes("heartbeat tick saw stale connection")
      )
    ).toBe(true);
    expect(ctx.trayStatus.markGrpcDisconnected).toHaveBeenCalled();
    expect(reconnectSchedules().length).toBeGreaterThanOrEqual(1);
  });

  it("con la conexión sana, el heartbeat sale cada 60s con la identidad del device", async () => {
    const s = await connectReady();

    await vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL_MS + 1_000);

    const hb = s.written.filter((w) => w.heartbeat);
    expect(hb).toHaveLength(1);
    expect(hb[0].heartbeat).toMatchObject({
      deviceId: "device-1",
      tenantId: "tenant-1",
      agentVersion: "1.1.21-test"
    });
  });
});

describe("grpc-stream — reset del contador de reintentos", () => {
  it("el READY explícito (connected:true) resetea el backoff: el siguiente fallo vuelve a attempt 1", async () => {
    await startFresh();

    await failAndReconnect(); // attempt 1
    await failAndReconnect(); // attempt 2
    expect(reconnectSchedules().map((s) => s.attempt)).toEqual([1, 2]);

    // El tercer stream levanta de verdad
    latestStream().emit("data", { connected: true });
    expect(
      ctx.logger.info.mock.calls.some(
        (c: any[]) =>
          c[0] === "gRPC stream: bridge READY, resetting reconnect backoff" &&
          c[1]?.priorAttempts === 2
      )
    ).toBe(true);

    // Nuevo fallo → arranca de attempt 1 otra vez
    latestStream().emit("error", new Error("boom again"));
    const schedules = reconnectSchedules();
    expect(schedules[schedules.length - 1].attempt).toBe(1);
  });

  it("un data cualquiera (p.ej. ack) NO resetea el contador — sólo connected:true cuenta como READY", async () => {
    // Congela el fix anti-hammering: los mensajes sintéticos del bridge
    // (helloError/receiverError/ack) llegan por el mismo canal data ANTES
    // del READY real; resetear ahí rompía el backoff exponencial.
    await startFresh();

    await failAndReconnect(); // attempt 1

    latestStream().emit("data", { ack: { eventId: "device-1:99", status: 0 } });
    latestStream().emit("error", new Error("still down"));

    const schedules = reconnectSchedules();
    expect(schedules.map((s) => s.attempt)).toEqual([1, 2]);
  });
});

describe("grpc-stream — sender loop (drain del outbox)", () => {
  it("lease con límite MAX_IN_FLIGHT=3 y envío de FACTS_SNAPSHOT con eventId deviceId:outboxId", async () => {
    const batch = [
      {
        id: 7,
        type: "FACTS_SNAPSHOT",
        payload_json: { namespaces: { amp: { hw: {} } } },
        status: "IN_FLIGHT",
        attempts: 0
      }
    ];
    mocks.outbox.leaseReady.mockReturnValueOnce(batch).mockReturnValue([]);

    await startFresh();
    const s = latestStream();
    s.emit("data", { connected: true });
    // startDelayTimer (1s) + setImmediate del drain
    await vi.advanceTimersByTimeAsync(1_500);

    expect(mocks.outbox.leaseReady).toHaveBeenCalledWith(3);

    const factsWrites = s.written.filter((w) => w.facts);
    expect(factsWrites).toHaveLength(1);
    expect(factsWrites[0].facts.eventId).toBe("device-1:7");
    expect(factsWrites[0].facts.deviceId).toBe("device-1");
    const sent = JSON.parse(factsWrites[0].facts.payloadJson.toString("utf8"));
    expect(sent).toEqual(batch[0].payload_json);
  });

  it("tipos de evento no soportados en el drain se marcan FAILED sin tumbar el loop", async () => {
    mocks.outbox.leaseReady
      .mockReturnValueOnce([
        { id: 9, type: "LOG_BUNDLE", payload_json: { x: 1 }, status: "IN_FLIGHT", attempts: 0 }
      ])
      .mockReturnValue([]);

    await startFresh();
    latestStream().emit("data", { connected: true });
    await vi.advanceTimersByTimeAsync(1_500);

    expect(mocks.outbox.markFailed).toHaveBeenCalledWith(9, "Unsupported event type: LOG_BUNDLE");
  });
});
