// src/transport/grpc-stream.ts
import { AgentContext } from "../core/agent-context";
import { createGrpcClient } from "./grpc-client";
import { outbox } from "../queue";
import { logger } from "../bootstrap/logger";

type PendingAck = {
  outboxId: number;
  sentAtMs: number;
};

const SEND_INTERVAL_MS = 2000;
const ACK_TIMEOUT_MS = 30_000;
const MAX_IN_FLIGHT = 50;
const RECONNECT_DELAY_MS = 5_000;

function buildEventId(deviceId: string, outboxId: number) {
  return `${deviceId}:${outboxId}`;
}

export function startGrpcStream(ctx: AgentContext) {
  let timer: NodeJS.Timeout;
  const client: any = createGrpcClient(ctx);
  const pending = new Map<string, PendingAck>(); // eventId -> outbox row id

  let rotationInProgress = false;
  let stopped = false;

  const stop = () => {
    if (stopped) return;
    stopped = true;
    try {
      clearInterval(timer);
    } catch {}
    try {
      stream.removeAllListeners();
    } catch {}
    try {
      stream.end();
    } catch {}
  };

  // Accelerate recovery of IN_FLIGHT on restart
  try {
    outbox.recoverStaleInflight(60); // DEV
  } catch {}

  const stream = client.Connect();

  // NOTE:
  // HELLO is now sent by PrivSvc during win.grpc.connect().
  // If you want to keep the same mental model, you can still write hello and PrivSvc will ignore.
  // stream.write({ hello: { ... } });

  // ---- Receiver (Control plane) ----
  stream.on("data", (msg: any) => {
    // ACK
    if (msg.ack) {
      const eventId: string = String(msg.ack.eventId || "");
      const status: number = Number(msg.ack.status ?? 0); // enum numeric
      const message: string = msg.ack.message || "";

      if (!eventId) return;

      const p = pending.get(eventId);
      if (!p) {
        // late or already processed
        return;
      }

      pending.delete(eventId);

      if (status === 0 /* ACK_OK */) {
        try {
          outbox.markSent(p.outboxId);
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

    // Jobs / rotate
    if (msg.runJob) {
      logger.info("Received job:", msg.runJob?.jobId || msg.runJob);
    }
    if (msg.rotateCert) {
      rotationInProgress = true;
      logger.info("Rotate cert received:", msg.rotateCert || "");
      // PrivSvc should perform rotation and keep the bridge alive.
      // While rotation is in progress, we pause sending new facts to avoid churn.
    }
  });

  stream.on("error", (err: any) => {
    if (stopped) return;
    logger.error("gRPC bridge error:", err?.message || err);
    // Do not mark events SENT here. IN_FLIGHT will be recovered by TTL.
    stop();
    setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
  });

  stream.on("end", () => {
    if (stopped) return;
    logger.warn("gRPC bridge closed. Reconnecting soon...");
    stop();
    setTimeout(() => startGrpcStream(ctx), RECONNECT_DELAY_MS);
  });

  // ---- Sender loop (Data plane) ----
  timer = setInterval(() => {
    try {
      // 1) Expire ACKs
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

      // 2) Pause sending during cert rotation to avoid churn
      if (rotationInProgress) return;

      // 3) Respect IN_FLIGHT window
      const availableSlots = MAX_IN_FLIGHT - pending.size;
      if (availableSlots <= 0) return;

      // 4) Lease ready events
      const batch = outbox.leaseReady(Math.min(10, availableSlots));
      if (!batch || batch.length === 0) return;

      for (const ev of batch) {
        const outboxId = Number(ev.id);
        const eventId = buildEventId(ctx.enrollment.deviceId, outboxId);

        try {
          if (ev.type === "FACTS_SNAPSHOT") {
            stream.write({
              facts: {
                eventId,
                payloadJson: Buffer.from(ev.payload_json, "utf8")
              }
            });

            pending.set(eventId, { outboxId, sentAtMs: Date.now() });
          } else {
            outbox.markFailed(outboxId, `Unsupported event type: ${ev.type}`);
          }
        } catch (err: any) {
          pending.delete(eventId);
          outbox.markFailed(outboxId, err?.message || "facts.send failed");
        }
      }
    } catch (err: any) {
      logger.error("Sender loop error:", err?.message || err);
    }
  }, SEND_INTERVAL_MS);

  // (Optional) return stop handle if you later want to cleanly shut down
  return () => {
    stop();
  };
}