// src/core/service.ts
import { bootstrapContext } from "./bootstrap";
import { scheduler } from "./scheduler";
import { logger } from "../bootstrap/logger";
import { startGrpcStream } from "../transport/grpc-stream";
import { outbox } from "../queue/sqlite-outbox";
import type { AgentContext } from "./agent-context";

let shuttingDown = false;
let currentCtx: AgentContext | null = null;
let cleanupTimer: NodeJS.Timeout | undefined;

export async function startService() {
  try {
    logger.info("Starting Tracenium Agent Core...");

    const ctx = await bootstrapContext();
    currentCtx = ctx;
    const log = ctx.logger;
    // DEBUG: observe raw IPC messages from PrivSvc
    try {
      if (ctx.priv?.on) {
        ctx.priv.on("debug", (d: any) => {
          log.info("[PrivSvc DEBUG]", d);
        });
      }
    } catch (e: any) {
      log.warn("Failed to attach PrivSvc debug listener", e?.message || e);
    }
    // initialize persistent outbox (recover events from previous runs)
    try {
      outbox.recoverStaleInflight(600); // 10 minutes
      log.info("Outbox recovery completed");
    } catch (e: any) {
      log.warn("Outbox recovery failed", e?.message || e);
    }
    log.info("Enrolled", {
      tenantId: ctx.enrollment.tenantId,
      deviceId: ctx.enrollment.deviceId
    });

    try {
      const snapshot = ctx.policyRuntime?.snapshot?.();
      if (snapshot) {
        log.info("Active runtime policy", snapshot);
      }
    } catch (e: any) {
      log.warn("Failed to read policy runtime snapshot", e?.message || e);
    }
    
    // Ping PrivSvc (best-effort)
    if (ctx.priv) {
      try {
        const resp = (await Promise.race([
          ctx.priv.call({
            v: 1,
            id: `ping_${Date.now()}`,
            method: "ping",
            params: {},
            meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
          }),
          new Promise((_, reject) => setTimeout(() => reject(new Error("PrivSvc ping timeout")), 3000))
        ])) as any;

        if (resp.ok) {
          log.info("PrivSvc ping OK:");
          //log.info("PrivSvc ping OK:", resp.result);
        } else {
          log.warn("PrivSvc ping FAIL:", resp.error);
        }
      } catch (e: any) {
        log.warn("PrivSvc not reachable (expected if not installed yet):", e?.message || e);
      }
    }

    // start control-plane stream
    Promise.resolve(startGrpcStream(ctx)).catch((e: any) => {
      log.error("gRPC stream failed to start", e?.message || e);
    });

    // start task scheduler (policy-driven)
    await scheduler.start(ctx);

    // periodic outbox cleanup
    cleanupTimer = setInterval(() => {
      try {
        outbox.cleanup(14);
      } catch (e: any) {
        log.warn("Outbox cleanup failed", e?.message || e);
      }
    }, 12 * 60 * 60 * 1000); // every 12h

    log.info("Agent Core started.");
  } catch (err: any) {
    logger.error("Fatal startup error:", err?.message || err);
    process.exit(1);
  }
}

// Graceful shutdown (WinSW stop)
process.on("SIGTERM", async () => {
  if (shuttingDown) return;
  shuttingDown = true;

  const log = currentCtx?.logger || logger;

  log.warn("Shutdown signal received...");

  try {
    if (cleanupTimer) {
      clearInterval(cleanupTimer);
    }

    if (currentCtx && typeof (scheduler as any).stop === "function") {
      await (scheduler as any).stop(currentCtx);
    }

    if (currentCtx?.priv?.close) {
      currentCtx.priv.close();
    }
  } catch (e: any) {
    log.error("Shutdown error", e?.message || e);
  }

  process.exit(0);
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception:", err);
});

process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled rejection:", reason);
});