// src/core/service.ts
import { bootstrapContext } from "./bootstrap";
import { scheduler } from "./scheduler";
import { logger } from "../bootstrap/logger";
import { startGrpcStream } from "../transport/grpc-stream";
import { outbox } from "../queue/sqlite-outbox";

let shuttingDown = false;
let currentCtx: any = null;
let cleanupTimer: NodeJS.Timeout | undefined;

export async function startService() {
  try {
    logger.info("Starting Tracenium Agent Core...");

    const ctx = await bootstrapContext();
    currentCtx = ctx;
    // DEBUG: observe raw IPC messages from PrivSvc
    try {
      if (ctx.priv?.on) {
        ctx.priv.on("debug", (d: any) => {
          logger.info("[PrivSvc DEBUG]", d);
        });
      }
    } catch (e: any) {
      logger.warn("Failed to attach PrivSvc debug listener", e?.message || e);
    }
    // initialize persistent outbox (recover events from previous runs)
    try {
      outbox.recoverStaleInflight(600); // 10 minutes
      logger.info("Outbox recovery completed");
    } catch (e: any) {
      logger.warn("Outbox recovery failed", e?.message || e);
    }
    logger.info("Enrolled", {
      tenantId: ctx.enrollment.tenantId,
      deviceId: ctx.enrollment.deviceId
    });

    try {
      const snapshot = ctx.policyRuntime?.snapshot?.();
      if (snapshot) {
        logger.info("Active runtime policy", snapshot);
      }
    } catch (e: any) {
      logger.warn("Failed to read policy runtime snapshot", e?.message || e);
    }
    
    // Ping PrivSvc (best-effort)
    if (ctx.priv) {
      try {
        const resp: any = await Promise.race([
          ctx.priv.call({
            v: 1,
            id: `ping_${Date.now()}`,
            method: "ping",
            params: {},
            meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
          }),
          new Promise((_, reject) => setTimeout(() => reject(new Error("PrivSvc ping timeout")), 3000))
        ]);

        if (resp.ok) {
          logger.info("PrivSvc ping OK:", resp.result);
        } else {
          logger.warn("PrivSvc ping FAIL:", resp.error);
        }
      } catch (e: any) {
        logger.warn("PrivSvc not reachable (expected if not installed yet):", e?.message || e);
      }
    }

    // start control-plane stream
    startGrpcStream(ctx);

    // start task scheduler (policy-driven)
    await scheduler.start(ctx);

    // periodic outbox cleanup
    cleanupTimer = setInterval(() => {
      try {
        outbox.cleanup(14);
      } catch (e: any) {
        logger.warn("Outbox cleanup failed", e?.message || e);
      }
    }, 12 * 60 * 60 * 1000); // every 12h

    logger.info("Agent Core started.");
  } catch (err: any) {
    logger.error("Fatal startup error:", err?.message || err);
    process.exit(1);
  }
}

// Graceful shutdown (WinSW stop)
process.on("SIGTERM", async () => {
  if (shuttingDown) return;
  shuttingDown = true;

  logger.warn("Shutdown signal received...");

  try {
    if (cleanupTimer) {
      clearInterval(cleanupTimer);
    }

    if (typeof (scheduler as any).stop === "function") {
      await (scheduler as any).stop(currentCtx);
    }

    if (currentCtx?.priv?.close) {
      currentCtx.priv.close();
    }
  } catch (e: any) {
    logger.error("Shutdown error", e?.message || e);
  }

  process.exit(0);
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception:", err);
});

process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled rejection:", reason);
});