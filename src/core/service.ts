// src/core/service.ts
import { bootstrapContext } from "./bootstrap";
import { scheduler } from "./scheduler";
import { logger } from "../bootstrap/logger";
import { startGrpcStream } from "../transport/grpc-stream";
import { outbox } from "../queue/sqlite-outbox";

let shuttingDown = false;

export async function startService() {
  try {
    logger.info("Starting Tracenium Agent Core...");

    const ctx = await bootstrapContext();
    // DEBUG: observe raw IPC messages from PrivSvc
    try {
      if (ctx.priv && typeof (ctx.priv as any).on === "function") {
        (ctx.priv as any).on("debug", (d: any) => {
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
    logger.info("Enrolled:", ctx.enrollment.tenantId, ctx.enrollment.deviceId);

    try {
      const snapshot = ctx.policyRuntime?.snapshot?.();
      if (snapshot) {
        logger.info("Active runtime policy", snapshot);
      }
    } catch (e: any) {
      logger.warn("Failed to read policy runtime snapshot", e?.message || e);
    }
    
    // Ping PrivSvc (best-effort)
    if (process.platform === "win32") {
      try {
        const resp = await ctx.priv.call({
          v: 1,
          id: `ping_${Date.now()}`,
          method: "win.ping",
          params: {},
          meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
        });

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
    setInterval(() => {
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

  // TODO: implement scheduler.stopAll() for multipipeline shutdown when needed

  process.exit(0);
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception:", err);
});

process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled rejection:", reason);
});