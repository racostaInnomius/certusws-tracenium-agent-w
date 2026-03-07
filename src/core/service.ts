// src/core/service.ts
import { bootstrapContext } from "./bootstrap";
import { scheduler } from "./scheduler";
import { logger } from "../bootstrap/logger";
import { startGrpcStream } from "../transport/grpc-stream";

let shuttingDown = false;

export async function startService() {
  try {
    logger.info("Starting Tracenium Agent Core...");

    const ctx = await bootstrapContext();
    logger.info("Enrolled:", ctx.enrollment.tenantId, ctx.enrollment.deviceId);
    
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

    startGrpcStream(ctx);
    await scheduler.start(ctx);

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

  // TODO: implement scheduler.stop() when available

  process.exit(0);
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception:", err);
});

process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled rejection:", reason);
});