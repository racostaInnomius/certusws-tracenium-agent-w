// test/transport/grpc-client.test.ts
//
// Regression coverage for a crash bug found 2026-08-13 on a device stuck
// in a ~5s gRPC reconnect loop: grpc-stream.ts's stop() calls
// stream.removeAllListeners() as part of a normal, already-handled
// disconnect. If a heartbeat IPC call that was in flight at that exact
// moment resolves as a failure a tick later, the heartbeat handler used
// to call `stream.emit("error", ...)` unconditionally — and Node's
// EventEmitter throws SYNCHRONOUSLY when you emit 'error' with zero
// listeners attached. That throw cascaded through two more unguarded
// `emit("error", ...)` call sites (the heartbeat handler's own catch,
// then the outer writeChain catch) and escaped as a genuine unhandled
// promise rejection, killing the whole agent process — turning a normal,
// already-being-handled disconnect into a crash that compounded the
// outage instead of just reconnecting cleanly.
//
// This file imports the REAL createGrpcClient (unlike
// grpc-stream.test.ts, which mocks it out entirely) so the emit-path
// itself is under test, not a fake.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createGrpcClient } from "../../src/transport/grpc-client";

function makeCtx(overrides: any = {}) {
  const priv = {
    call: vi.fn(async (req: any) => {
      if (req.method === "grpc.connect") {
        return { ok: true, result: { connected: true, ready: true } };
      }
      if (req.method === "grpc.heartbeat") {
        return { ok: false, error: { code: "heartbeat_send_failed" } };
      }
      return { ok: true };
    }),
    close: vi.fn()
  };

  return {
    config: { agentVersion: "1.1.33-test", grpcEndpoint: "grpc.test.local:443" },
    enrollment: {
      tenantId: "tenant-1",
      deviceId: "device-1",
      mtls: { clientCertThumbprint: "cert-thumb", issuingCaThumbprint: "ca-thumb" },
      bootstrap: { capabilities: ["amp"] }
    },
    priv,
    policy: { getVersion: () => "pv1" },
    policyRuntime: { getEnabledPlugins: () => [] },
    trayStatus: {
      markGrpcDisconnected: vi.fn(),
      markHeartbeat: vi.fn()
    },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    ...overrides
  } as any;
}

// stream.write()'s internals run inside a self-chaining promise
// (writeChain) that nothing in the public API exposes — poll for the
// expected side effect instead of awaiting a return value that doesn't
// exist.
async function waitForCall(fn: ReturnType<typeof vi.fn>, matcher?: (args: any[]) => boolean) {
  await vi.waitFor(() => {
    const hit = matcher
      ? fn.mock.calls.some((c) => matcher(c))
      : fn.mock.calls.length > 0;
    if (!hit) throw new Error("not called yet");
  }, { timeout: 1000, interval: 5 });
}

describe("grpc-client — heartbeat failure emit safety", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("does not throw when a heartbeat fails after the stream's listeners were removed", async () => {
    const ctx = makeCtx();
    const client = createGrpcClient(ctx);
    const stream = client.Connect();

    // No 'error' listener attached — simulates the exact post-stop()
    // state (grpc-stream.ts's stop() calls removeAllListeners()).
    expect(stream.listenerCount("error")).toBe(0);

    stream.write({
      heartbeat: { deviceId: "device-1", uptimeSeconds: 1, agentVersion: "1.1.33-test", policyVersion: "pv1" }
    });

    // The old code crashed the whole process here via an unhandled
    // rejection — nothing to assert on a crash directly, so the proof
    // is behavioral: the safe-drop path logged instead of throwing,
    // AND the write chain is still alive afterward (see the follow-up
    // write below) rather than permanently wedged by an unhandled
    // rejection inside writeChain.
    await waitForCall(ctx.logger.debug, (args) =>
      String(args[0]).includes("dropping error emit")
    );

    // Prove the chain wasn't poisoned: a subsequent write still reaches
    // PrivSvc normally.
    ctx.priv.call.mockClear();
    stream.write({
      heartbeat: { deviceId: "device-1", uptimeSeconds: 2, agentVersion: "1.1.33-test", policyVersion: "pv1" }
    });
    await waitForCall(ctx.priv.call, (args) => args[0]?.method === "grpc.heartbeat");
  });

  it("still emits 'error' normally when a listener IS attached (reconnect path intact)", async () => {
    const ctx = makeCtx();
    const client = createGrpcClient(ctx);
    const stream = client.Connect();

    const onError = vi.fn();
    stream.on("error", onError);

    stream.write({
      heartbeat: { deviceId: "device-1", uptimeSeconds: 1, agentVersion: "1.1.33-test", policyVersion: "pv1" }
    });

    await waitForCall(onError);
    expect(String(onError.mock.calls[0][0]?.message || "")).toContain("heartbeat_failed");
  });
});
