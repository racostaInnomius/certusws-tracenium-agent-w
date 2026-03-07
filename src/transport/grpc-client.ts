// src/transport/grpc-client.ts
import { EventEmitter } from "events";
import { AgentContext } from "../core/agent-context";
import { logger } from "../bootstrap/logger";

function normalizeTarget(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

type StreamLike = EventEmitter & {
  write: (msg: any) => void;
  end: () => void;
};

type GrpcBridgeClient = {
  Connect: () => StreamLike;
};

function attachPrivPushHandler(ctx: AgentContext, onPush: (msg: any) => void) {
  const priv: any = ctx.priv as any;

  if (typeof priv.onPush === "function") {
    priv.onPush(onPush);
    return;
  }

  if (typeof priv.on === "function") {
    priv.on("push", onPush);
    return;
  }

  logger.warn(
    "[grpc-client] PrivSvcClient has no push subscription method. " +
      "Implement ctx.priv.onPush(cb) OR make it an EventEmitter emitting 'push'."
  );
}

export function createGrpcClient(ctx: AgentContext): GrpcBridgeClient {
  const target = normalizeTarget(ctx.config.grpcEndpoint);
  logger.info(`[grpc-client] Using PrivSvc gRPC bridge → ${target}`);

  const stream = new EventEmitter() as StreamLike;

  let connected = false;
  let connecting = false;
  let ended = false;

  // Push from PrivSvc → re-emit as "data"
  attachPrivPushHandler(ctx, (pushMsg: any) => {
    try {
      const method = pushMsg?.method ?? null;
      const params = pushMsg?.params ?? null;

      if (!method) return;

      if (method === "win.grpc.ack") {
        stream.emit("data", { ack: params });
        return;
      }

      if (method === "win.grpc.control.runJob") {
        stream.emit("data", { runJob: params });
        return;
      }

      if (method === "win.grpc.control.rotateCert") {
        stream.emit("data", { rotateCert: params });
        return;
      }

      if (method === "win.grpc.control.streamClosed" || method === "win.grpc.disconnected") {
        connected = false;
        stream.emit("end");
        return;
      }

      // debug passthrough si quieres
      // stream.emit("data", { debug: { method, params } });
    } catch (e: any) {
      logger.error("[grpc-client] push handler error:", e?.message || e);
    }
  });

  async function ensureConnected() {
    if (ended) throw new Error("stream ended");
    if (connected) return;
    if (connecting) return;

    connecting = true;
    try {
      const tenantId = String(ctx.enrollment.tenantId || "");
      const deviceId = String(ctx.enrollment.deviceId || "");
      const agentVersion = String(ctx.config.agentVersion || "");

      const clientCertThumbprint = String((ctx.enrollment as any)?.mtls?.clientCertThumbprint || "");
      const issuingCaThumbprint = String((ctx.enrollment as any)?.mtls?.issuingCaThumbprint || "");

      if (!tenantId || !deviceId) throw new Error("Missing enrollment tenantId/deviceId");
      if (!clientCertThumbprint) throw new Error("Missing mtls.clientCertThumbprint in enrollment");
      if (!issuingCaThumbprint) throw new Error("Missing mtls.issuingCaThumbprint in enrollment");

      // ALINEADO A .NET: target + clientCertThumbprint + (tenant/device/version)
      const resp = await (ctx.priv as any).call({
        v: 1,
        id: "grpc-connect",
        method: "win.grpc.connect",
        params: {
          target, // "localhost:50051"
          clientCertThumbprint,
          issuingCaThumbprint, // opcional por ahora
          tenantId,
          deviceId,
          agentVersion
        },
        meta: { tenantId, deviceId }
      });

      if (!resp?.ok) {
        throw new Error(resp?.error?.message || resp?.error || "PrivSvc connect failed");
      }

      connected = true;
      logger.info("[grpc-client] PrivSvc gRPC bridge connected");
    } catch (e: any) {
      connected = false;
      stream.emit("error", e);
      throw e;
    } finally {
      connecting = false;
    }
  }

  stream.write = (msg: any) => {
    (async () => {
      await ensureConnected();

      // HELLO is handled by PrivSvc on connect; ignore hello from node
      if (msg?.hello) return;

      if (msg?.facts) {
        const eventId = String(msg.facts.eventId || "");
        const payloadJsonBytes = msg.facts.payloadJson;

        if (!eventId) throw new Error("facts.eventId required");

        let payloadJsonStr: string;
        if (Buffer.isBuffer(payloadJsonBytes)) payloadJsonStr = payloadJsonBytes.toString("utf8");
        else if (typeof payloadJsonBytes === "string") payloadJsonStr = payloadJsonBytes;
        else throw new Error("facts.payloadJson must be Buffer or string");

        const resp = await (ctx.priv as any).call({
          v: 1,
          id: `facts-${eventId}`,
          method: "win.grpc.facts.send",
          params: { eventId, payloadJson: payloadJsonStr },
          meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
        });

        if (!resp?.ok) {
          throw new Error(resp?.error?.message || resp?.error || "facts.send failed");
        }

        return;
      }

      logger.warn("[grpc-client] stream.write ignored unknown msg:", Object.keys(msg || {}));
    })().catch((err) => stream.emit("error", err));
  };

  stream.end = () => {
    ended = true;
    connected = false;

    (ctx.priv as any)
      .call({
        v: 1,
        id: "grpc-close",
        method: "win.grpc.close",
        params: {},
        meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
      })
      .catch(() => {});

    stream.emit("end");
  };

  return {
    Connect: () => {
      ensureConnected().catch(() => {});
      return stream;
    }
  };
}