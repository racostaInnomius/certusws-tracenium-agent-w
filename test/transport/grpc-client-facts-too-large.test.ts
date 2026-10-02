// test/transport/grpc-client-facts-too-large.test.ts
//
// «Demasiado grande» es definitivo; cualquier otro fallo, reintentable.
//
// TNS-OPER-SNOC04 (Server 2022), 28-sep-2026: el PrivSvc rechazaba al
// reensamblar el compliance del equipo (tope de 512 KiB) y el agente lo
// trataba como un fallo cualquiera: lanzaba, el stream emitía `error`,
// grpc-stream reconectaba y el outbox reenviaba el MISMO evento. Cuatro
// días así, sin que el servidor anotara nada y con la conexión cayendo cada
// pocos minutos.
//
// Lo que se fija: con `facts_too_large` el evento queda rechazado en el
// outbox, no se mandan más trozos y la conexión NO se toca. Con cualquier
// otro código, el camino de siempre (error → reconexión) sigue intacto.
// Se usa el createGrpcClient REAL con el PrivSvc doblado.

import { describe, it, expect, vi, beforeEach } from "vitest";

const { outbox } = vi.hoisted(() => ({
  outbox: { markSent: vi.fn(), markFailed: vi.fn(), markRejected: vi.fn() }
}));
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox }));
vi.mock("../../src/domain/cdp-baseline-repo", () => ({ promoteCdpDelivery: vi.fn(() => "none") }));

import { createGrpcClient, MAX_FACTS_PAYLOAD_BYTES } from "../../src/transport/grpc-client";

function connect(chunkResponse: (i: number) => any) {
  const ctx = {
    config: { agentVersion: "1.2.0-test", grpcEndpoint: "grpc.test.local:443" },
    enrollment: {
      tenantId: "tenant-1",
      deviceId: "device-1",
      mtls: { clientCertThumbprint: "cert-thumb", issuingCaThumbprint: "ca-thumb" },
      bootstrap: { capabilities: ["scp"] }
    },
    priv: {
      call: vi.fn(async (req: any) => {
        if (req.method === "grpc.connect") return { ok: true, result: { connected: true, ready: true } };
        if (req.method === "grpc.facts.chunk") return chunkResponse(req.params.chunkIndex);
        return { ok: true };
      }),
      close: vi.fn(),
      onPush: () => {}
    },
    policy: { getVersion: () => "pv1" },
    policyRuntime: { getEnabledPlugins: () => [] },
    trayStatus: { markGrpcDisconnected: vi.fn(), markHeartbeat: vi.fn(), markGrpcConnected: vi.fn() },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
  } as any;
  const stream = createGrpcClient(ctx).Connect();
  const errores: Error[] = [];
  stream.on("error", (e: Error) => errores.push(e));
  return { ctx, stream, errores };
}

async function waitFor(cond: () => boolean) {
  await vi.waitFor(() => {
    if (!cond()) throw new Error("todavía no");
  }, { timeout: 1000, interval: 5 });
}

const chunkCalls = (ctx: any) =>
  ctx.priv.call.mock.calls.map((c: any[]) => c[0]).filter((r: any) => r.method === "grpc.facts.chunk");

function facts(eventId: string, bytes: number) {
  return { facts: { eventId, namespace: "scp", namespaces: ["scp"], payloadJson: "a".repeat(bytes) } };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("FACTS troceado que el PrivSvc rechaza por tamaño", () => {
  it("⭐ facts_too_large: el evento queda rechazado, no se mandan más trozos y la conexión sigue", async () => {
    const { ctx, stream, errores } = connect((i) =>
      i === 3
        ? { ok: false, error: { code: "facts_too_large", message: "facts payload exceeds 16777216 bytes" } }
        : { ok: true, result: { received: true } }
    );
    await waitFor(() => ctx.trayStatus.markGrpcConnected.mock.calls.length > 0);

    stream.write(facts("device-1:756", 17 * 32_933));

    await waitFor(() => outbox.markRejected.mock.calls.length > 0);
    expect(outbox.markRejected).toHaveBeenCalledWith(756, expect.stringContaining("facts_too_large"));
    expect(chunkCalls(ctx).map((r: any) => r.params.chunkIndex)).toEqual([0, 1, 2, 3]);

    // Dejar correr la cadena: si fuera a emitir error, ya lo habría hecho.
    await new Promise((r) => setTimeout(r, 20));
    expect(errores).toEqual([]);
    expect(ctx.trayStatus.markGrpcDisconnected).not.toHaveBeenCalled();
    expect(outbox.markFailed).not.toHaveBeenCalled();
  });

  it("⭐ cualquier otro fallo de un trozo sigue tirando la conexión (reintentable)", async () => {
    const { ctx, stream, errores } = connect((i) =>
      i === 1 ? { ok: false, error: { code: "grpc_facts_chunk_error", message: "gRPC not connected" } } : { ok: true }
    );
    await waitFor(() => ctx.trayStatus.markGrpcConnected.mock.calls.length > 0);

    stream.write(facts("device-1:757", 100_000));

    await waitFor(() => errores.length > 0);
    expect(errores[0].message).toMatch(/FACTS_CHUNK_FAILED/);
    expect(outbox.markRejected).not.toHaveBeenCalled();
  });

  it("lo que no cabe en el servidor no se manda: ni un trozo", async () => {
    const { ctx, stream, errores } = connect(() => ({ ok: true }));
    await waitFor(() => ctx.trayStatus.markGrpcConnected.mock.calls.length > 0);

    stream.write(facts("device-1:758", MAX_FACTS_PAYLOAD_BYTES + 1));

    await waitFor(() => outbox.markRejected.mock.calls.length > 0);
    expect(outbox.markRejected).toHaveBeenCalledWith(758, expect.stringContaining("facts_too_large"));
    expect(chunkCalls(ctx)).toEqual([]);
    expect(errores).toEqual([]);
  });

  it("justo en el tope sí se manda", async () => {
    const { ctx, stream } = connect(() => ({ ok: true }));
    await waitFor(() => ctx.trayStatus.markGrpcConnected.mock.calls.length > 0);

    stream.write(facts("device-1:759", MAX_FACTS_PAYLOAD_BYTES));

    await waitFor(() => chunkCalls(ctx).length === 512);
    expect(outbox.markRejected).not.toHaveBeenCalled();
  });
});
