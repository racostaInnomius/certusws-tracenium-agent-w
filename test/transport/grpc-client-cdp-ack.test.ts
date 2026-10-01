// test/transport/grpc-client-cdp-ack.test.ts
//
// El ACK del control plane es la frontera de entrega: sólo un ACK_OK mueve
// la línea base de CDP. Un RETRY (la proyección falló) o un REJECTED (payload
// demasiado grande) la dejan donde estaba, y el siguiente escaneo reenvía.
// Se usa el createGrpcClient REAL y se inyecta el `grpc.ack` por el mismo
// canal de push que usa el PrivSvc.

import { describe, it, expect, vi, beforeEach } from "vitest";

const { promoteCdpDelivery, outbox } = vi.hoisted(() => ({
  promoteCdpDelivery: vi.fn((_id: number) => "promoted"),
  outbox: { markSent: vi.fn(), markFailed: vi.fn(), markRejected: vi.fn() }
}));
vi.mock("../../src/domain/cdp-baseline-repo", () => ({ promoteCdpDelivery }));
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox }));

import { createGrpcClient } from "../../src/transport/grpc-client";

let push: ((msg: any) => void) | null = null;

function connect() {
  const ctx = {
    config: { agentVersion: "1.2.0-test", grpcEndpoint: "grpc.test.local:443" },
    enrollment: {
      tenantId: "tenant-1",
      deviceId: "device-1",
      mtls: { clientCertThumbprint: "cert-thumb", issuingCaThumbprint: "ca-thumb" },
      bootstrap: { capabilities: ["cdp"] }
    },
    priv: {
      call: vi.fn(async () => ({ ok: true, result: { connected: true, ready: true } })),
      close: vi.fn(),
      onPush: (fn: (msg: any) => void) => {
        push = fn;
      }
    },
    policy: { getVersion: () => "pv1" },
    policyRuntime: { getEnabledPlugins: () => [] },
    trayStatus: { markGrpcDisconnected: vi.fn(), markHeartbeat: vi.fn(), markGrpcConnected: vi.fn() },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
  } as any;
  const stream = createGrpcClient(ctx).Connect();
  stream.on("error", () => {});
  return ctx;
}

const ack = (outboxId: number, status: number) =>
  push!({ method: "grpc.ack", params: { eventId: `device-1:${outboxId}`, status, message: "x" } });

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ACK → línea base de CDP", () => {
  it("⭐ ACK_OK: el envío llegó, la base de ESE envío avanza", () => {
    connect();
    ack(55, 0);
    expect(outbox.markSent).toHaveBeenCalledWith(55);
    expect(promoteCdpDelivery).toHaveBeenCalledWith(55);
  });

  it("⭐ ACK_RETRY (la proyección de CDP falló en el servidor): la base NO avanza", () => {
    connect();
    ack(56, 1);
    expect(outbox.markFailed).toHaveBeenCalled();
    expect(promoteCdpDelivery).not.toHaveBeenCalled();
  });

  it("ACK_REJECTED (payload demasiado grande): tampoco", () => {
    connect();
    ack(57, 2);
    expect(outbox.markRejected).toHaveBeenCalled();
    expect(promoteCdpDelivery).not.toHaveBeenCalled();
  });

  it("si promover falla, el ACK se sigue procesando (y el próximo escaneo reenvía)", () => {
    const ctx = connect();
    promoteCdpDelivery.mockImplementationOnce(() => {
      throw new Error("SQLITE_BUSY");
    });
    expect(() => ack(58, 0)).not.toThrow();
    expect(outbox.markSent).toHaveBeenCalledWith(58);
    expect(ctx.logger.warn).toHaveBeenCalledWith(
      "[grpc-client] CDP baseline promote failed",
      expect.objectContaining({ outboxId: 58 })
    );
  });
});
