// src/transport/grpc-client.ts
import { EventEmitter } from "events";
import { AgentContext } from "../core/agent-context";
import { logger } from "../bootstrap/logger";

function normalizeTarget(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

const MAX_FACTS_IPC_BYTES = 64 * 1024;

const FACTS_CHUNK_SIZE = 48 * 1024; // 48KB safe chunk size

function chunkString(str: string, size: number): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < str.length; i += size) {
    chunks.push(str.slice(i, i + size));
  }
  return chunks;
}

type StreamLike = EventEmitter & {
  write: (msg: any) => void;
  end: () => void;
};

type GrpcBridgeClient = {
  Connect: () => StreamLike;
  isConnected: () => boolean;
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
  let connectPromise: Promise<void> | null = null;
  let ended = false;
  let localClose = false;

  // serialize IPC writes to PrivSvc to avoid concurrent pipe writes
  let writeChain: Promise<void> = Promise.resolve();

  // Push from PrivSvc → re-emit as "data"
  attachPrivPushHandler(ctx, (pushMsg: any) => {
    try {
      const method = pushMsg?.method;
      if (!method) return;

      const params = pushMsg?.params ?? {};
      logger.info("[grpc-client] push message", { method, params });

      if (method === "win.grpc.ack") {
        stream.emit("data", { ack: params });
        return;
      }

      if (method === "win.grpc.connected") {
        connected = true;
        logger.info("[grpc-client] PrivSvc confirmed gRPC connected (READY)");
        stream.emit("data", { connected: true });
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

      if (method === "win.grpc.control.policyUpdate") {
        stream.emit("data", { policyUpdate: params });
        return;
      }

      if (method === "win.grpc.control.requestFacts") {
        stream.emit("data", { requestFacts: params });
        return;
      }

      if (method === "win.grpc.control.disconnect") {
        stream.emit("data", { disconnect: params });
        return;
      }

      if (method === "win.grpc.control.agentUpdate") {
        stream.emit("data", { agentUpdate: params });
        return;
      }

      if (method === "win.grpc.control.streamClosed" || method === "win.grpc.disconnected") {
        logger.warn("[grpc-client] gRPC bridge reported disconnect");
        connected = false;
        connectPromise = null;
        ended = false;

        // Remote disconnect: notify listeners, but do NOT mark this stream as locally ended
        // and do NOT send win.grpc.close back to PrivSvc.
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
    if (ended && localClose) throw new Error("stream ended");
    if (connected) return;

    if (connectPromise) {
      await connectPromise;
      return;
    }

    connectPromise = (async () => {
      try {
        const tenantId = String(ctx.enrollment.tenantId || "");
        const deviceId = String(ctx.enrollment.deviceId || "");
        const agentVersion = String(ctx.config.agentVersion || "");

        const clientCertThumbprint = String((ctx.enrollment as any)?.mtls?.clientCertThumbprint || "");
        const issuingCaThumbprint = String((ctx.enrollment as any)?.mtls?.issuingCaThumbprint || "");

        if (!tenantId || !deviceId) throw new Error("Missing enrollment tenantId/deviceId");
        if (!clientCertThumbprint) throw new Error("Missing mtls.clientCertThumbprint in enrollment");
        if (!issuingCaThumbprint) throw new Error("Missing mtls.issuingCaThumbprint in enrollment");

        logger.info("[grpc-client] requesting PrivSvc gRPC connect");

        const resp = await (ctx.priv as any).call({
          v: 1,
          id: "grpc-connect",
          method: "win.grpc.connect",
          params: {
            target,
            clientCertThumbprint,
            issuingCaThumbprint,
            tenantId,
            deviceId,
            agentVersion
          },
          meta: { tenantId, deviceId }
        });

        if (!resp?.ok) {
          throw new Error(resp?.error?.message || resp?.error || "PrivSvc connect failed");
        }

        const result = resp?.result ?? {};

        if (result.connected === true && result.ready === true) {
        connected = true;
        logger.info("[grpc-client] PrivSvc bridge READY (from connect response)");

        stream.emit("data", {
          connected: true,
          source: "connect_response"
        });

        return;
      }  

      if (result.connected === true) {
        connected = false;
        logger.info("[grpc-client] bridge accepted connect request, waiting for win.grpc.connected");
        return;
      }

        // Otherwise wait for the push notification from the bridge.
        connected = false;
        logger.info("[grpc-client] connect request accepted, waiting for win.grpc.connected confirmation");
      } catch (e: any) {
        connected = false;
        logger.error("[grpc-client] connect failed", e?.message || e);
        stream.emit("error", e);
        throw e;
      } finally {
        connectPromise = null;
      }
    })();

    await connectPromise;
  }

  stream.write = (msg: any) => {
    writeChain = writeChain
      .then(async () => {
        await ensureConnected();

        if (ended && localClose) {
          logger.warn("[grpc-client] write skipped: stream already ended locally");
          return;
        }

        if (!connected) {
          logger.warn("[grpc-client] write skipped: bridge not fully ready yet");
          return;
        }

        // HELLO is handled by PrivSvc on connect; ignore hello from node
        if (msg?.hello) return;

        if (msg?.facts) {
          const eventId = String(msg.facts.eventId || "");
          const payloadJsonBytes = msg.facts.payloadJson;

          if (!eventId) throw new Error("facts.eventId required");
          logger.info("[grpc-client] sending FACTS event", eventId);

          let payloadJsonStr: string;
          if (Buffer.isBuffer(payloadJsonBytes)) payloadJsonStr = payloadJsonBytes.toString("utf8");
          else if (typeof payloadJsonBytes === "string") payloadJsonStr = payloadJsonBytes;
          else throw new Error("facts.payloadJson must be Buffer or string");

          const payloadSizeBytes = Buffer.byteLength(payloadJsonStr, "utf8");
          logger.info("[grpc-client] FACTS payload size", { eventId, payloadSizeBytes });

          // If payload fits, send normally
          if (payloadSizeBytes <= MAX_FACTS_IPC_BYTES) {
            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `facts-${eventId}`,
              method: "win.grpc.facts.send",
              params: { eventId, payloadJson: payloadJsonStr },
              meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
            });

            if (!resp?.ok) {
              const errorCode = String(resp?.error?.code || "");
              const errorMessage = String(resp?.error?.message || resp?.error || "facts.send failed");

              if (errorCode === "request_too_large") {
                logger.warn("[grpc-client] switching to chunked FACTS send", { eventId, payloadSizeBytes });
              } else {
                throw new Error(errorMessage);
              }
            } else {
              return;
            }
          }

          // Chunked send fallback or large payload
          const chunks = chunkString(payloadJsonStr, FACTS_CHUNK_SIZE);
          logger.info("[grpc-client] sending FACTS in chunks", {
            eventId,
            totalChunks: chunks.length
          });

          for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];

            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `facts-chunk-${eventId}-${i}`,
              method: "win.grpc.facts.chunk",
              params: {
                eventId,
                chunkIndex: i,
                totalChunks: chunks.length,
                payloadChunk: chunk
              },
              meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
            });

            if (!resp?.ok) {
              const errorMessage = String(resp?.error?.message || resp?.error || "facts.chunk failed");
              throw new Error(`FACTS_CHUNK_FAILED:${errorMessage}`);
            }
          }

          logger.info("[grpc-client] FACTS chunked send completed", { eventId });
          return;
        }

        if (msg?.heartbeat) {
          const deviceId = String(
            msg.heartbeat.deviceId ||
            ctx.enrollment.deviceId ||
            ""
          );
          const uptimeSeconds = Number(msg.heartbeat.uptimeSeconds || 0);
          const agentVersion = String(msg.heartbeat.agentVersion || ctx.config.agentVersion || "");
          const policyVersion = String(msg.heartbeat.policyVersion || "");

          if (!deviceId) {
            logger.warn("[grpc-client] heartbeat ignored: deviceId missing");
            return;
          }

          // Heartbeat is handled internally by PrivSvc on the gRPC stream.
          logger.info("[grpc-client] heartbeat (handled by PrivSvc stream)", {
            deviceId,
            uptimeSeconds,
            agentVersion,
            policyVersion
          });

          return;
        }

        logger.warn("[grpc-client] stream.write ignored unknown message type", {
          keys: Object.keys(msg || {})
        });
      })
      .catch((err) => {
        const errCode = String(err?.code || "");
        const errMessage = String(err?.message || err || "");
        if (errCode === "EPIPE" || /EPIPE/i.test(errMessage)) {
          logger.warn("[grpc-client] EPIPE detected, marking connection as broken", {
            errCode,
            errMessage
          });
          connected = false;
          connectPromise = null;
        }
        stream.emit("error", err);
      });
  };

  stream.end = () => {
    if (ended) return;

    ended = true;
    localClose = true;
    connected = false;
    connectPromise = null;

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
      ended = false;
      localClose = false;
      ensureConnected().catch(() => {});
      return stream;
    },
    isConnected: () => connected
  };
}