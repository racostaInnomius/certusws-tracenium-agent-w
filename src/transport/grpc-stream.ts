// src/transport/grpc-stream.ts
import { AgentContext } from "../core/agent-context";
import { createGrpcClient } from "./grpc-client";
import { outbox } from "../queue/sqlite-outbox";
import { PolicyStore } from "../core/policy-store";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { Namespaces, DeviceFacts } from "../domain/device-facts";

const ACK_TIMEOUT_MS = 60_000;
const MAX_IN_FLIGHT = 3;
const RECONNECT_DELAY_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 60_000;

function buildEventId(deviceId: string, outboxId: number) {
  return `${deviceId}:${outboxId}`;
}

export function startGrpcStream(ctx: AgentContext) {
  let startDelayTimer: NodeJS.Timeout | null = null;
  let retryTimer: NodeJS.Timeout | null = null;
  let heartbeatInterval: NodeJS.Timeout | null = null;
  let unsubscribeOutbox: (() => void) | null = null;
  let draining = false;
  let drainScheduled = false;
  const client: any = createGrpcClient(ctx);
  ctx.logger?.info?.("gRPC stream: creating client");
let stream: any;
stream = client.Connect();
// NOTE: pending ACK tracking removed; outbox lifecycle handled by grpc-client ACKs

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
    ctx.logger?.warn?.("gRPC stream: stop() invoked, closing stream and timers");
    stopped = true;
    rotationInProgress = false;
    try { if (startDelayTimer) clearTimeout(startDelayTimer); } catch {}
    try { if (retryTimer) clearTimeout(retryTimer); } catch {}
    try { if (heartbeatInterval) clearInterval(heartbeatInterval); } catch {}
    try { stream.removeAllListeners(); } catch {}

    try { unsubscribeOutbox?.(); } catch {}
    unsubscribeOutbox = null;

    if (opts?.localClose) {
      try { stream.end(); } catch {}
    }
  };

  // Accelerate recovery of IN_FLIGHT on restart
  try {
    outbox.recoverStaleInflight(60); // DEV
  } catch {}

  ctx.logger?.info?.("gRPC stream: Connect() stream opened");

  ctx.logger?.info?.("Agent hello context", {
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
      ctx.logger?.info?.("gRPC stream: bridge ready", msg);
      rotationInProgress = false;
      requestDrain("bridge_connected");
      return;
    }
    // ACK
    if (msg.ack) {
      const eventId: string = String(msg.ack.eventId ?? "").trim();
      if (!eventId) return;
      ctx.logger?.info?.("gRPC ACK received", {
        eventId,
        status: Number(msg.ack.status ?? 0),
        message: msg.ack.message || ""
      });
      return;
    }

    if (msg.queueFull) {
      ctx.logger?.warn?.("gRPC bridge queueFull signal received", msg.queueFull);
      return;
    }
    // Jobs / rotate
    if (msg.runJob) {
      ctx.logger?.info?.("gRPC control message: runJob received");
      ctx.logger?.info?.("Received job:", msg.runJob?.jobId || msg.runJob);
    }
    if (msg.rotateCert) {
      ctx.logger?.warn?.("gRPC control message: rotateCert received, pausing sender loop");
      rotationInProgress = true;
      ctx.logger?.info?.("Rotate cert received:", msg.rotateCert || "");
      // PrivSvc should perform rotation and keep the bridge alive.
      // While rotation is in progress, we pause sending new facts to avoid churn.
    }

    if (msg.policyUpdate) {
      try {
        const policyVersion = String(msg.policyUpdate?.policyVersion || "");
        const payload = msg.policyUpdate?.policyJson;

        ctx.logger?.info?.("gRPC control message: policyUpdate received", {
          policyVersion
        });

        if (!policyVersion || !payload) {
          ctx.logger?.warn?.("policyUpdate ignored: missing required fields");
          return;
        }

        const payloadStr = Buffer.isBuffer(payload) ? payload.toString("utf8") : String(payload);

        let parsed: any;
        try {
          parsed = JSON.parse(payloadStr);
        } catch (e) {
          ctx.logger?.error?.("policyUpdate JSON parse failed", e);
          return;
        }

        const computedHash = PolicyStore.computeHash(parsed);

        const localHash = ctx.policy.getHash();
        if (localHash === computedHash) {
          ctx.logger?.info?.("policyUpdate skipped: already applied", { policyVersion });
          return;
        }

        ctx.policy
          .save(policyVersion, computedHash, parsed)
          .then(async () => {
            ctx.logger?.info?.("Policy successfully updated", { policyVersion });
            try {
              await ctx.policyRuntime.applyUpdate();
              ctx.logger?.info?.("Policy runtime reloaded", ctx.policyRuntime.snapshot());
            } catch (err: any) {
              ctx.logger?.error?.("Policy runtime reload failed", err?.message || err);
            }
          })
          .catch((err: any) => {
            ctx.logger?.error?.("Policy save failed", err?.message || err);
          });

      } catch (err: any) {
        ctx.logger?.error?.("policyUpdate handler error", err?.message || err);
      }
      return;
    }

    if (msg.requestFacts) {
      ctx.logger?.info?.("gRPC control message: requestFacts received", msg.requestFacts);

      (async () => {
        try {
          const namespaces = {} as Namespaces;

          // AMM
          if (ctx.policyRuntime.pluginEnabled("amm")) {
            try {
              namespaces.amm = await ctx.plugins.run("amm.collect");
            } catch (err) {
              ctx.logger?.error?.("AMM collect failed (requestFacts)", { err });
            }
          }

          // SCM (future-ready)
          if (ctx.policyRuntime.pluginEnabled("scm")) {
            try {
              namespaces.scm = await ctx.plugins.run("scm.collect");
            } catch (err) {
              ctx.logger?.error?.("SCM collect failed (requestFacts)", { err });
            }
          }

          if (Object.keys(namespaces).length === 0) {
            ctx.logger?.warn?.("requestFacts: no namespaces collected, skipping");
            return;
          }

          const facts = await buildDeviceFacts(ctx, namespaces);

          // IMPORTANT: requestFacts ignores hasChanges (server explicitly requested)
          outbox.enqueue({
            type: "FACTS_SNAPSHOT",
            payload: facts
          });

          const softwareCount = Number(namespaces.amm?.software?.count ?? 0);

          ctx.logger?.info?.("Immediate FACTS_SNAPSHOT enqueued from requestFacts", {
            factType: msg.requestFacts?.factType || "inventory",
            modules: Object.keys(namespaces),
            softwareCount
          });
        } catch (err: any) {
          ctx.logger?.error?.("requestFacts immediate collection failed", err?.message || err);
        }
      })();

      return;
    }

    if (msg.agentUpdate) {
      const params = msg.agentUpdate;

      ctx.logger?.info?.("gRPC control message: agentUpdate received", {
        version: params?.version,
        force: params?.force
      });

      // avoid concurrent updates
      if ((ctx as any)._agentUpdateInProgress) {
        ctx.logger?.warn?.("agentUpdate ignored: update already in progress");
        return;
      }

      (ctx as any)._agentUpdateInProgress = true;

      // lazy import to avoid circular deps
      const { runUpdateTask } = require("../update/update-task");

      setImmediate(() => {
        runUpdateTask(ctx, {
          force: params?.force === true,
          targetVersion: params?.version || undefined,
          logger: ctx.logger
        })
          .catch((err: any) => {
            ctx.logger?.error?.("agentUpdate execution failed", {
              err: err?.message || err
            });
          })
          .finally(() => {
            (ctx as any)._agentUpdateInProgress = false;
          });
      });

      return;
    }

    if (msg.disconnect) {
      ctx.logger?.warn?.("gRPC control message: disconnect requested by server");
      stop();
      setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
      return;
    }
  });

  stream.on("error", (err: any) => {
    if (stopped) return;
    ctx.logger?.error?.("gRPC bridge error:", err?.message || err);
    ctx.logger?.warn?.("gRPC stream: scheduling reconnect in", RECONNECT_DELAY_MS, "ms");
    // Do not mark events SENT here. IN_FLIGHT will be recovered by TTL.
    stop();
    setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
  });

  stream.on("end", () => {
    if (stopped) return;
    ctx.logger?.warn?.("gRPC bridge closed. Reconnecting soon...");
    ctx.logger?.warn?.("gRPC stream: end event received, scheduling reconnect in", RECONNECT_DELAY_MS, "ms");
    stop();
    setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
  });


  // ---- Sender loop (Data plane) ----
  const armRetryTimer = () => {
    if (stopped) return;
    const delayMs = (outbox as any).getNextReadyDelayMs?.();
    if (delayMs == null) return;
    try { if (retryTimer) clearTimeout(retryTimer); } catch {}
    retryTimer = setTimeout(() => {
      retryTimer = null;
      requestDrain("retry_timer");
    }, delayMs);
  };

  const drainOnce = () => {
    drainScheduled = false;

    if (stopped || draining) return;
    if (rotationInProgress) { armRetryTimer(); return; }
    if (!stream || !client.isConnected?.()) { armRetryTimer(); return; }

    draining = true;
    try {
      const batch = outbox.leaseReady(MAX_IN_FLIGHT);
      if (!batch || batch.length === 0) {
        armRetryTimer();
        return;
      }

      ctx.logger?.info?.("Sender loop leased events", { count: batch.length });

      for (const ev of batch) {
        const outboxId = Number(ev.id);
        const eventId = buildEventId(ctx.enrollment.deviceId, outboxId);

        if (!ev.payload_json) {
          outbox.markFailed(outboxId, "Empty payload_json");
          continue;
        }

        try {
          if (ev.type === "FACTS_SNAPSHOT") {
            const parsedPayload: DeviceFacts =
              typeof ev.payload_json === "string"
                ? JSON.parse(ev.payload_json)
                : ev.payload_json;

            const baselineHash = parsedPayload?._meta?.baselineHash;
            const forceBaseline = parsedPayload?._meta?.forceBaseline === true;

            if (baselineHash && baselineHash === lastBaselineHash && baselineSent && !forceBaseline) {
              if (typeof (ctx.logger as any)?.debug === "function") {
                (ctx.logger as any).debug("Skipping FACTS (baseline unchanged)", { eventId });
              }
              try { outbox.markSent(outboxId); } catch {}
              continue;
            }

            ctx.logger?.info?.("Sending FACTS event", { outboxId, eventId, type: ev.type });
            ctx.logger?.info?.("FACTS payload metadata", { eventId, baselineHash, baselineSent, forceBaseline });

            try {
              const sw = parsedPayload?.namespaces?.amm?.software;
              ctx.logger?.info?.("STREAM FINAL SOFTWARE CHECK", {
                hasItems: !!sw?.items,
                itemsLength: sw?.items?.length,
                keys: Object.keys(sw || {})
              });
            } catch (e: any) {
              ctx.logger?.error?.("STREAM SOFTWARE CHECK FAILED", e?.message || e);
            }

            stream.write({
              facts: {
                eventId,
                deviceId: ctx.enrollment.deviceId,
                namespace: parsedPayload?.namespaces ? Object.keys(parsedPayload.namespaces)[0] : "amm",
                payloadJson: Buffer.from(
                  typeof ev.payload_json === "string" ? ev.payload_json : JSON.stringify(ev.payload_json),
                  "utf8"
                )
              }
            });

          } else if (ev.type === "FACTS_DELTA") {
            ctx.logger?.info?.("Sending FACTS_DELTA event", { outboxId, eventId });

            stream.write({
              facts: {
                eventId,
                deviceId: ctx.enrollment.deviceId,
                namespace: "amm",
                payloadJson: Buffer.from(
                  typeof ev.payload_json === "string" ? ev.payload_json : JSON.stringify(ev.payload_json),
                  "utf8"
                )
              }
            });

          } else {
            outbox.markFailed(outboxId, `Unsupported event type: ${ev.type}`);
          }
        } catch (err: any) {
          ctx.logger?.error?.("FACTS send failed", { eventId, error: err?.message || err });
          outbox.markFailed(outboxId, err?.message || "facts.send failed");
        }
      }
    } catch (err: any) {
      ctx.logger?.error?.("Sender loop error:", err?.message || err);
    } finally {
      draining = false;
      const nextDelay = (outbox as any).getNextReadyDelayMs?.();
      if (nextDelay === 0) {
        requestDrain("more_ready_now");
      } else {
        armRetryTimer();
      }
    }
  };

  const requestDrain = (_reason: string) => {
    if (stopped || drainScheduled) return;
    drainScheduled = true;
    setImmediate(drainOnce);
  };

  ctx.logger?.info?.("gRPC sender loop will start shortly...");
  // Start sender loop after a short delay to allow gRPC bridge to establish
  startDelayTimer = setTimeout(() => {
    if (!stopped) {
      ctx.logger?.info?.("gRPC sender loop started");
      if (typeof (outbox as any).onChanged === "function") {
        unsubscribeOutbox = (outbox as any).onChanged(() => {
          requestDrain("outbox_changed");
        });
      } else {
        // Fallback: trigger a single drain at startup if event API not available
        requestDrain("outbox_changed_fallback");
      }
      requestDrain("startup");
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
          ctx.logger?.error?.("Heartbeat send failed", err?.message || err);
        }
      }, HEARTBEAT_INTERVAL_MS);
    }
  }, 1000);

  // (Optional) return stop handle if you later want to cleanly shut down
  return () => {
    stop();
  };
}