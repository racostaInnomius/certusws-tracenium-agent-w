// src/transport/grpc-stream.ts
import { AgentContext } from "../core/agent-context";
import { createGrpcClient } from "./grpc-client";
import { outbox } from "../queue/sqlite-outbox";
import { logger } from "../bootstrap/logger";
import { PolicyStore } from "../core/policy-store";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { Namespaces, DeviceFacts } from "../domain/device-facts";

type PendingAck = {
  outboxId: number;
  sentAtMs: number;
  baselineHash?: string | null;
  namespace?: string;
};

const SEND_INTERVAL_MS = 2000;
const ACK_TIMEOUT_MS = 30_000;
const MAX_IN_FLIGHT = 3;
const RECONNECT_DELAY_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 60_000;

function buildEventId(deviceId: string, outboxId: number) {
  return `${deviceId}:${outboxId}`;
}

export function startGrpcStream(ctx: AgentContext) {
  let startDelayTimer: NodeJS.Timeout | null = null;
  let senderInterval: NodeJS.Timeout | null = null;
  let heartbeatInterval: NodeJS.Timeout | null = null;
  const client: any = createGrpcClient(ctx);
  logger.info("gRPC stream: creating client");
let stream: any;
stream = client.Connect();
const pending = new Map<string, PendingAck>(); // eventId -> pending metadata
  let previousPending = -1;

  let rotationInProgress = false;
  let stopped = false;
  // ensure state reset on each stream start
  rotationInProgress = false;

  // Load persisted baseline hash and sent flag from SQLite state
  let lastBaselineHash: string | null = null;
  let baselineSent = false;
  try {
    lastBaselineHash = outbox.getState("baselineHash:amm");
    baselineSent = outbox.getState("baselineSent:amm") === "1";
  } catch {
    lastBaselineHash = null;
    baselineSent = false;
  }

  const stop = (opts?: { localClose?: boolean }) => {
    if (stopped) return;
    logger.warn("gRPC stream: stop() invoked, closing stream and timers");
    stopped = true;
    rotationInProgress = false;
    if (pending.size > 0) {
      logger.warn("Clearing pending ACKs on stop", { count: pending.size });
    }
    pending.clear();
    try { if (startDelayTimer) clearTimeout(startDelayTimer); } catch {}
    try { if (senderInterval) clearInterval(senderInterval); } catch {}
    try { if (heartbeatInterval) clearInterval(heartbeatInterval); } catch {}
    try { stream.removeAllListeners(); } catch {}

    if (opts?.localClose) {
      try { stream.end(); } catch {}
    }
  };

  // Accelerate recovery of IN_FLIGHT on restart
  try {
    outbox.recoverStaleInflight(60); // DEV
  } catch {}

  logger.info("gRPC stream: Connect() stream opened");

  logger.info("Agent hello context", {
    deviceId: ctx.enrollment.deviceId,
    tenantId: ctx.enrollment.tenantId,
    agentVersion: ctx.config.agentVersion,
    policyVersion: ctx.policy.getVersion(),
    capabilities: ["amm"]
  });

  // NOTE:
  // HELLO is now sent by PrivSvc during grpc.connect().
  // If you want to keep the same mental model, you can still write hello and PrivSvc will ignore.
  // stream.write({ hello: { ... } });

  // ---- Receiver (Control plane) ----
  stream.on("data", (msg: any) => {
    //logger.info("gRPC raw message received", msg);
    //logger.info("gRPC stream: message received", Object.keys(msg || {}));
    if (msg?.connected === true) {
      logger.info("gRPC stream: bridge ready", msg);
      rotationInProgress = false;
      return;
    }
    // ACK
    if (msg.ack) {
      const rawEventId = msg.ack.eventId;
      const eventId: string = String(rawEventId ?? "").trim();

      logger.info("ACK received (normalized)", {
        rawEventId,
        normalizedEventId: eventId,
        pendingSize: pending.size
      });

      const status: number = Number(msg.ack.status ?? 0); // enum numeric
      const message: string = msg.ack.message || "";

      if (!eventId) return;

      const p = pending.get(eventId);
      if (!p) {
        logger.warn("ACK without pending match", {
          eventId,
          pendingKeysSample: Array.from(pending.keys()).slice(0, 5)
        });
        return;
      }

      pending.delete(eventId);
      logger.info("gRPC ACK received", { eventId, status, message });

      if (status === 0 /* ACK_OK */) {
        try {
          outbox.markSent(p.outboxId);

          if (p.baselineHash) {
            lastBaselineHash = p.baselineHash;
            baselineSent = true;
            try {
              outbox.setState("baselineHash:amm", p.baselineHash);
              outbox.setState("baselineSent:amm", "1");
            } catch {}
          }

        } catch (e: any) {
          logger.error("markSent failed:", p.outboxId, e?.message || e);
        }
        return;
      }

      // ACK_RETRY / ACK_REJECTED:
      try {
        outbox.markFailed(p.outboxId, message || `ack status=${status}`);
      } catch (e: any) {
        logger.error("markFailed failed:", p.outboxId, e?.message || e);
      }
      return;
    }

    if (msg.queueFull) {
      logger.warn("gRPC bridge queueFull signal received", msg.queueFull);
      return;
    }
    // Jobs / rotate
    if (msg.runJob) {
      logger.info("gRPC control message: runJob received");
      logger.info("Received job:", msg.runJob?.jobId || msg.runJob);
    }
    if (msg.rotateCert) {
      logger.warn("gRPC control message: rotateCert received, pausing sender loop");
      rotationInProgress = true;
      logger.info("Rotate cert received:", msg.rotateCert || "");
      // PrivSvc should perform rotation and keep the bridge alive.
      // While rotation is in progress, we pause sending new facts to avoid churn.
    }

    if (msg.policyUpdate) {
      try {
        const policyVersion = String(msg.policyUpdate?.policyVersion || "");
        const payload = msg.policyUpdate?.policyJson;

        logger.info("gRPC control message: policyUpdate received", {
          policyVersion
        });

        if (!policyVersion || !payload) {
          logger.warn("policyUpdate ignored: missing required fields");
          return;
        }

        const payloadStr = Buffer.isBuffer(payload) ? payload.toString("utf8") : String(payload);

        let parsed: any;
        try {
          parsed = JSON.parse(payloadStr);
        } catch (e) {
          logger.error("policyUpdate JSON parse failed", e);
          return;
        }

        const computedHash = PolicyStore.computeHash(parsed);

        const localHash = ctx.policy.getHash();
        if (localHash === computedHash) {
          logger.info("policyUpdate skipped: already applied", { policyVersion });
          return;
        }

        ctx.policy
          .save(policyVersion, computedHash, parsed)
          .then(async () => {
            logger.info("Policy successfully updated", { policyVersion });
            try {
              await ctx.policyRuntime.applyUpdate();
              logger.info("Policy runtime reloaded", ctx.policyRuntime.snapshot());
            } catch (err: any) {
              logger.error("Policy runtime reload failed", err?.message || err);
            }
          })
          .catch((err: any) => {
            logger.error("Policy save failed", err?.message || err);
          });

      } catch (err: any) {
        logger.error("policyUpdate handler error", err?.message || err);
      }
      return;
    }

    if (msg.requestFacts) {
      logger.info("gRPC control message: requestFacts received", msg.requestFacts);

      (async () => {
        try {
          const namespaces = {} as Namespaces;

          // AMM
          if (ctx.policyRuntime.pluginEnabled("amm")) {
            try {
              namespaces.amm = await ctx.plugins.run("amm.collect");
            } catch (err) {
              logger.error("AMM collect failed (requestFacts)", { err });
            }
          }

          // SCM (future-ready)
          if (ctx.policyRuntime.pluginEnabled("scm")) {
            try {
              namespaces.scm = await ctx.plugins.run("scm.collect");
            } catch (err) {
              logger.error("SCM collect failed (requestFacts)", { err });
            }
          }

          if (Object.keys(namespaces).length === 0) {
            logger.warn("requestFacts: no namespaces collected, skipping");
            return;
          }

          const facts = await buildDeviceFacts(ctx, namespaces);

          // IMPORTANT: requestFacts ignores hasChanges (server explicitly requested)
          outbox.enqueue({
            type: "FACTS_SNAPSHOT",
            payload: facts
          });

          const softwareCount = Number(namespaces.amm?.software?.count ?? 0);

          logger.info("Immediate FACTS_SNAPSHOT enqueued from requestFacts", {
            factType: msg.requestFacts?.factType || "inventory",
            modules: Object.keys(namespaces),
            softwareCount
          });
        } catch (err: any) {
          logger.error("requestFacts immediate collection failed", err?.message || err);
        }
      })();

      return;
    }

    if (msg.agentUpdate) {
      logger.warn("gRPC control message: agentUpdate received", msg.agentUpdate);
      return;
    }

    if (msg.disconnect) {
      logger.warn("gRPC control message: disconnect requested by server");
      stop();
      setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
      return;
    }
  });

  stream.on("error", (err: any) => {
    if (stopped) return;
    logger.error("gRPC bridge error:", err?.message || err);
    logger.warn("gRPC stream: scheduling reconnect in", RECONNECT_DELAY_MS, "ms");
    // Do not mark events SENT here. IN_FLIGHT will be recovered by TTL.
    stop();
    setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
  });

  stream.on("end", () => {
    if (stopped) return;
    logger.warn("gRPC bridge closed. Reconnecting soon...");
    logger.warn("gRPC stream: end event received, scheduling reconnect in", RECONNECT_DELAY_MS, "ms");
    stop();
    setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
  });


  // ---- Sender loop (Data plane) ----
  const startSenderLoop = (): NodeJS.Timeout => setInterval(() => {
    try {
      if (pending.size !== previousPending) {
        logger.info("Sender loop state change", { pending: pending.size });
        previousPending = pending.size;
      }
      // 1) Expire ACKs (skip scan when nothing in flight)
      if (pending.size > 0) {
        const now = Date.now();
        for (const [eventId, p] of pending.entries()) {
          if (now - p.sentAtMs > ACK_TIMEOUT_MS) {
            pending.delete(eventId);
            try {
              outbox.markFailed(p.outboxId, "ACK timeout");
            } catch (e: any) {
              logger.error("markFailed (timeout) failed:", p.outboxId, e?.message || e);
            }
          }
        }
      }

      // 2) Pause sending during cert rotation to avoid churn
      if (rotationInProgress) return;

      // 3) Require ready stream before leasing anything
      if (stopped || !stream) {
        return;
      }

      if (!client.isConnected?.()) {
        // Expected during startup or transient reconnects → avoid noisy logs
        if (typeof (logger as any).debug === "function") {
          (logger as any).debug("Sender loop waiting: client not connected");
        }
        return;
      }

      // 4) Respect IN_FLIGHT window
      const availableSlots = MAX_IN_FLIGHT - pending.size;
      if (availableSlots <= 0) return;

      // 5) Lease ready events
      const batch = outbox.leaseReady(availableSlots);
      if (batch && batch.length > 0) {
        logger.info("Sender loop leased events", {
          count: batch.length,
          availableSlots,
          inFlight: pending.size
        });
      }
      if (!batch || batch.length === 0) return;

      for (const ev of batch) {
        const outboxId = Number(ev.id);
        const eventId = buildEventId(ctx.enrollment.deviceId, outboxId);

        if (!ev.payload_json) {
          outbox.markFailed(outboxId, "Empty payload_json");
          continue;
        }

        try {
          if (ev.type === "FACTS_SNAPSHOT") {
            // Baseline deduplication
            const parsedPayload: DeviceFacts =
              typeof ev.payload_json === "string"
                ? JSON.parse(ev.payload_json)
                : ev.payload_json;

            const baselineHash = parsedPayload?._meta?.baselineHash;
            const forceBaseline = parsedPayload?._meta?.forceBaseline === true;

            if (baselineHash && baselineHash === lastBaselineHash && baselineSent && !forceBaseline) {
              if (typeof (logger as any).debug === "function") {
                (logger as any).debug("Skipping FACTS (baseline unchanged)", { eventId });
              }
              try {
                outbox.markSent(outboxId);
              } catch {}
              continue;
            }

            logger.info("Sending FACTS event", { outboxId, eventId, type: ev.type });

            pending.set(eventId, {
              outboxId,
              sentAtMs: Date.now(),
              baselineHash,
              namespace: parsedPayload?.namespaces
                ? Object.keys(parsedPayload.namespaces)[0]
                : "amm"
            });

            logger.info("FACTS payload metadata", {
              eventId,
              baselineHash,
              baselineSent,
              forceBaseline
            });
            try {
              const sw = parsedPayload?.namespaces?.amm?.software;
              logger.info("STREAM FINAL SOFTWARE CHECK", {
                hasItems: !!sw?.items,
                itemsLength: sw?.items?.length,
                keys: Object.keys(sw || {})
              });
            } catch (e: any) {
              logger.error("STREAM SOFTWARE CHECK FAILED", e?.message || e);
            }

            stream.write({
              facts: {
                eventId,
                deviceId: ctx.enrollment.deviceId,
                namespace:
                  parsedPayload?.namespaces
                    ? Object.keys(parsedPayload.namespaces)[0]
                    : "amm",
                payloadJson: Buffer.from(
                  typeof ev.payload_json === "string"
                    ? ev.payload_json
                    : JSON.stringify(ev.payload_json),
                  "utf8"
                )
              }
            });


          } else if (ev.type === "FACTS_DELTA") {
            logger.info("Sending FACTS_DELTA event", { outboxId, eventId });

            pending.set(eventId, {
              outboxId,
              sentAtMs: Date.now(),
              namespace: "amm"
            });

            stream.write({
              facts: {
                eventId,
                deviceId: ctx.enrollment.deviceId,
                namespace: "amm",
                payloadJson: Buffer.from(
                  typeof ev.payload_json === "string"
                    ? ev.payload_json
                    : JSON.stringify(ev.payload_json),
                  "utf8"
                )
              }
            });

          } else {
            outbox.markFailed(outboxId, `Unsupported event type: ${ev.type}`);
          }
        } catch (err: any) {
          logger.error("FACTS send failed", { eventId, error: err?.message || err });
          pending.delete(eventId);
          outbox.markFailed(outboxId, err?.message || "facts.send failed");
        }
      }
    } catch (err: any) {
      logger.error("Sender loop error:", err?.message || err);
    }
  }, SEND_INTERVAL_MS);

  logger.info("gRPC sender loop will start shortly...");
  // Start sender loop after a short delay to allow gRPC bridge to establish
  startDelayTimer = setTimeout(() => {
    if (!stopped) {
      logger.info("gRPC sender loop started");
      if (!senderInterval) {
        senderInterval = startSenderLoop();
      }
      if (!heartbeatInterval) heartbeatInterval = setInterval(() => {
        try {
          if (rotationInProgress || stopped) return;
          if (!stream || !client.isConnected?.()) return;

          stream.write({
            heartbeat: {
              deviceId: ctx.enrollment.deviceId,
              tenantId: ctx.enrollment.tenantId,
              agentVersion: ctx.config.agentVersion,
              ts: Date.now()
            }
          });
        } catch (err: any) {
          logger.error("Heartbeat send failed", err?.message || err);
        }
      }, HEARTBEAT_INTERVAL_MS);
    }
  }, 1000);

  // (Optional) return stop handle if you later want to cleanly shut down
  return () => {
    stop();
  };
}