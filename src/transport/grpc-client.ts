// src/transport/grpc-client.ts
import { EventEmitter } from "events";
import { AgentContext } from "../core/agent-context";
import { logger } from "../bootstrap/logger";
import { runUpdateTask } from "../update/update-task";
import { outbox } from "../queue/sqlite-outbox";

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

  ctx.logger?.info?.("[grpc-client] attaching PrivSvc push handler", {
    hasOnPush: typeof priv.onPush === "function",
    hasOn: typeof priv.on === "function"
  });

  if (typeof priv.onPush === "function") {
    ctx.logger?.info?.("[grpc-client] subscribing via priv.onPush()");
    priv.onPush(onPush);
    return;
  }

  if (typeof priv.on === "function") {
    ctx.logger?.info?.("[grpc-client] subscribing via priv.on('push')");
    priv.on("push", onPush);
    return;
  }

  ctx.logger?.warn(
    "[grpc-client] PrivSvcClient has no push subscription method. " +
      "Implement ctx.priv.onPush(cb) OR make it an EventEmitter emitting 'push'."
  );
}

export function createGrpcClient(ctx: AgentContext): GrpcBridgeClient {
  const target = normalizeTarget(ctx.config.grpcEndpoint);
  ctx.logger?.info(`[grpc-client] Using PrivSvc gRPC bridge → ${target}`);

  const stream = new EventEmitter() as StreamLike;

  let connected = false;
  let connectPromise: Promise<void> | null = null;
  let ended = false;
  let localClose = false;
  let agentUpdateInProgress = false;

  // serialize IPC writes to PrivSvc to avoid concurrent pipe writes
  let writeChain: Promise<void> = Promise.resolve();

  // track in-flight events to avoid duplicate sends before ACK
  const inFlightEvents = new Set<string>();

  // Push from PrivSvc → re-emit as "data"
  attachPrivPushHandler(ctx, (pushMsg: any) => {
    try {
      const method = pushMsg?.method;
      if (!method) return;

      const params = pushMsg?.params ?? {};
      ctx.logger?.info("[grpc-client] push message", { method, params });

      if (method === "grpc.ack") {
        ctx.logger?.info?.("[grpc-client] ACK push received", {
          rawEventId: params?.eventId,
          status: params?.status,
          message: params?.message
        });

        const normalized = {
          ...params,
          eventId: String(params?.eventId ?? "").trim()
        };

        // clear in-flight tracking
        try {
          if (normalized.eventId) {
            inFlightEvents.delete(normalized.eventId);
          }
        } catch {}

        // --- remote ACK (telemetry only; outbox already closed on IPC acceptance) ---
        try {
          const eventId = normalized.eventId;
          if (eventId) {
            const parts = eventId.split(":");
            const outboxId = Number(parts[parts.length - 1]);

            if (!isNaN(outboxId)) {
              const status = Number(normalized.status ?? 0);
              const message = String(normalized.message || "");

              if (status === 0) {
                outbox.markSent(outboxId);
                ctx.logger?.info?.("[grpc-client] ACK → markSent", { eventId, outboxId });
              } else {
                outbox.markFailed(outboxId, message || `ACK status ${status}`);
                ctx.logger?.warn?.("[grpc-client] ACK → markFailed", { eventId, outboxId, status });
              }
            }
          }
        } catch (err: any) {
          ctx.logger?.error?.("[grpc-client] ACK handling failed", err?.message || err);
        }

        stream.emit("data", { ack: normalized });
        return;
      }

      if (method === "grpc.connected") {
        connected = true;
        ctx.logger?.info("[grpc-client] PrivSvc confirmed gRPC connected (READY)");
        stream.emit("data", { connected: true });
        return;
      }

      if (method === "grpc.control.runJob") {
        stream.emit("data", { runJob: params });
        return;
      }

      if (method === "grpc.control.rotateCert") {
        stream.emit("data", { rotateCert: params });
        return;
      }

      if (method === "grpc.control.policyUpdate") {
        stream.emit("data", { policyUpdate: params });
        return;
      }

      if (method === "grpc.control.requestFacts") {
        stream.emit("data", { requestFacts: params });
        return;
      }

      if (method === "grpc.control.disconnect") {
        stream.emit("data", { disconnect: params });
        return;
      }

      if (method === "grpc.control.agentUpdate") {

        if (agentUpdateInProgress) {
          ctx.logger?.warn("[grpc-client] agentUpdate ignored: update already in progress");
          return;
        }

        const jobId = String(params?.jobId || "").trim();

        const version = String(params?.version || "").trim();
        const downloadUrl = String(params?.downloadUrl || "").trim();
        const checksum = String(params?.checksum || "").trim();

        ctx.logger?.info("[grpc-client] agentUpdate received", {
          jobId,
          version,
          hasUrl: !!downloadUrl,
          hasChecksum: !!checksum
        });

        // Validate required fields before proceeding
        if (!version || !downloadUrl || !checksum) {
          ctx.logger?.error("[grpc-client] invalid agentUpdate payload", {
            jobId,
            version,
            hasUrl: !!downloadUrl,
            hasChecksum: !!checksum
          });
          return;
        }

        stream.emit("data", { agentUpdate: params });

        agentUpdateInProgress = true;

        setImmediate(async () => {
          // Use jobId or fallback eventId for ACK
          const eventId = jobId || `agentUpdate-${Date.now()}`;
          try {
            await runUpdateTask(ctx, {
              targetVersion: version,
              downloadUrl,
              checksum,
              logger: ctx.logger || logger
            });

            // ACK success
            if (eventId) {
              try {
                await (ctx.priv as any).call({
                  v: 1,
                  id: `ack-${eventId}`,
                  method: "grpc.ack",
                  params: {
                    eventId,
                    status: 0,
                    message: "update_completed"
                  }
                });
                ctx.logger?.info("[grpc-client] agentUpdate ACK sent (success)", { eventId });
              } catch (ackErr: any) {
                ctx.logger?.error("[grpc-client] failed to send ACK (success)", {
                  eventId,
                  err: ackErr?.message || ackErr
                });
              }
            }

          } catch (err: any) {

            // ACK failure
            if (eventId) {
              try {
                await (ctx.priv as any).call({
                  v: 1,
                  id: `ack-${eventId}`,
                  method: "grpc.ack",
                  params: {
                    eventId,
                    status: 2,
                    message: err?.message || "update_failed"
                  }
                });
                ctx.logger?.warn("[grpc-client] agentUpdate ACK sent (failure)", { eventId });
              } catch (ackErr: any) {
                ctx.logger?.error("[grpc-client] failed to send ACK (failure)", {
                  eventId,
                  err: ackErr?.message || ackErr
                });
              }
            }

            ctx.logger?.error("[grpc-client] agentUpdate execution failed", {
              err: err?.message || err
            });

          } finally {
            agentUpdateInProgress = false;
          }
        });

        return;
      }

      if (method === "grpc.control.streamClosed" || method === "grpc.disconnected") {
        ctx.logger?.warn("[grpc-client] gRPC bridge reported disconnect");
        connected = false;
        connectPromise = null;
        ended = false;

        // Remote disconnect: notify listeners, but do NOT mark this stream as locally ended
        // and do NOT send grpc.close back to PrivSvc.
        stream.emit("end");
        return;
      }

      // debug passthrough si quieres
      // stream.emit("data", { debug: { method, params } });
    } catch (e: any) {
      ctx.logger?.error("[grpc-client] push handler error:", e?.message || e);
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

        ctx.logger?.info("[grpc-client] requesting PrivSvc gRPC connect");

        const resp = await (ctx.priv as any).call({
          v: 1,
          id: "grpc-connect",
          method: "grpc.connect",
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
        ctx.logger?.info("[grpc-client] PrivSvc bridge READY (from connect response)");

        stream.emit("data", {
          connected: true,
          source: "connect_response"
        });

        return;
      }  

      if (result.connected === true) {
        connected = false;
        ctx.logger?.info("[grpc-client] bridge accepted connect request, waiting for grpc.connected");
        return;
      }

        // Otherwise wait for the push notification from the bridge.
        connected = false;
        ctx.logger?.info("[grpc-client] connect request accepted, waiting for grpc.connected confirmation");
      } catch (e: any) {
        connected = false;
        ctx.logger?.error("[grpc-client] connect failed", e?.message || e);
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
          ctx.logger?.warn("[grpc-client] write skipped: stream already ended locally");
          return;
        }

        if (!connected) {
          ctx.logger?.warn("[grpc-client] write skipped: bridge not fully ready yet");
          return;
        }

        // HELLO is handled by PrivSvc on connect; ignore hello from node
        if (msg?.hello) return;

        if (msg?.facts) {
          const eventId = String(msg.facts.eventId || "");
          if (inFlightEvents.has(eventId)) {
            ctx.logger?.warn("[grpc-client] duplicate send prevented (in-flight)", { eventId });
            return;
          }
          inFlightEvents.add(eventId);

          if (!eventId) throw new Error("facts.eventId required");
          ctx.logger?.info("[grpc-client] sending FACTS event", eventId);

          let payloadJsonStr: string;
          if (Buffer.isBuffer(msg.facts.payloadJson)) payloadJsonStr = msg.facts.payloadJson.toString("utf8");
          else if (typeof msg.facts.payloadJson === "string") payloadJsonStr = msg.facts.payloadJson;
          else throw new Error("facts.payloadJson must be Buffer or string");

          const payloadSizeBytes = Buffer.byteLength(payloadJsonStr, "utf8");
          ctx.logger?.info("[grpc-client] FACTS payload size", payloadSizeBytes);

          // If payload fits, send normally
          if (payloadSizeBytes <= MAX_FACTS_IPC_BYTES) {
            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `facts-${eventId}`,
              method: "grpc.facts.send",
              params: { eventId, payloadJson: payloadJsonStr },
              meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
            });

            if (!resp?.ok) {
              const errorCode = String(resp?.error?.code || "");
              const errorMessage = String(resp?.error?.message || resp?.error || "facts.send failed");

              if (errorCode === "request_too_large") {
                ctx.logger?.warn("[grpc-client] switching to chunked FACTS send", { eventId, payloadSizeBytes });
              } else {
                throw new Error(errorMessage);
              }
            } else {
              // Close local outbox lifecycle on successful PrivSvc acceptance
              try {
                const parts = eventId.split(":");
                const outboxId = Number(parts[parts.length - 1]);
                if (!isNaN(outboxId)) {
                  outbox.markSent(outboxId);
                  ctx.logger?.info?.("[grpc-client] IPC accepted → markSent", { eventId, outboxId });
                }
              } catch (e: any) {
                ctx.logger?.error?.("[grpc-client] markSent after IPC failed", e?.message || e);
              }

              // release in-flight tracking
              inFlightEvents.delete(eventId);
              return;
            }
          }

          // Chunked send fallback or large payload
          const chunks = chunkString(payloadJsonStr, FACTS_CHUNK_SIZE);
          ctx.logger?.info("[grpc-client] sending FACTS in chunks", {
            eventId,
            totalChunks: chunks.length
          });

          for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];

            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `facts-chunk-${eventId}-${i}`,
              method: "grpc.facts.chunk",
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

          ctx.logger?.info("[grpc-client] FACTS chunked send completed", { eventId });

          // Close local outbox lifecycle after successful chunked IPC send
          try {
            const parts = eventId.split(":");
            const outboxId = Number(parts[parts.length - 1]);
            if (!isNaN(outboxId)) {
              outbox.markSent(outboxId);
              ctx.logger?.info?.("[grpc-client] IPC chunked accepted → markSent", { eventId, outboxId });
            }
          } catch (e: any) {
            ctx.logger?.error?.("[grpc-client] markSent after chunked IPC failed", e?.message || e);
          }

          // release in-flight tracking
          inFlightEvents.delete(eventId);

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
            ctx.logger?.warn("[grpc-client] heartbeat ignored: deviceId missing");
            return;
          }

          // Heartbeat is handled internally by PrivSvc on the gRPC stream.
          ctx.logger?.info("[grpc-client] heartbeat (handled by PrivSvc stream)", {
            //deviceId,
            //uptimeSeconds,
            //agentVersion,
            //policyVersion
          });

          return;
        }

        ctx.logger?.warn("[grpc-client] stream.write ignored unknown message type", {
          keys: Object.keys(msg || {})
        });
      })
      .catch((err) => {
        const errCode = String(err?.code || "");
        const errMessage = String(err?.message || err || "");
        if (errCode === "EPIPE" || /EPIPE/i.test(errMessage)) {
          ctx.logger?.warn("[grpc-client] EPIPE detected, marking connection as broken", {
            errCode,
            errMessage
          });
          connected = false;
          connectPromise = null;
        }
        // release in-flight on failure
        if (msg?.facts?.eventId) {
          inFlightEvents.delete(String(msg.facts.eventId));
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
    agentUpdateInProgress = false;

    (ctx.priv as any)
      .call({
        v: 1,
        id: "grpc-close",
        method: "grpc.close",
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