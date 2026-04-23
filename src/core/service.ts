// src/core/service.ts
import { bootstrapContext } from "./bootstrap";
import { scheduler } from "./scheduler";
import { logger } from "../bootstrap/logger";
import { startGrpcStream } from "../transport/grpc-stream";
import { outbox } from "../queue/sqlite-outbox";
import type { AgentContext } from "./agent-context";
import { maybeRenewClientCertificate } from "../bootstrap/cert-renewal";

let shuttingDown = false;
let currentCtx: AgentContext | null = null;
let cleanupTimer: NodeJS.Timeout | undefined;
let certRenewalTimer: NodeJS.Timeout | undefined;
let stopGrpcStream: (() => void) | null = null;

export async function startService() {
  try {
    logger.info("Starting Tracenium Agent Core...");

    const ctx = await bootstrapContext();
    currentCtx = ctx;
    const log = ctx.logger;
    // Gate the PrivSvc IPC DEBUG trace behind an env var. Every IPC
    // round-trip emits ~5 debug stages (call_write, raw_chunk_full,
    // ipc_raw_message, response_match / push_emit), so with heartbeats
    // every 60s + facts + update/compliance ticks the stdout is >90%
    // debug noise during normal operation — it drowns out the rare
    // real errors operators actually need to see.
    //
    // Opt in with DEBUG_PRIVSVC=1 when diagnosing IPC issues. Default
    // off mirrors the tenant-middleware silencing we did backend-side.
    const privsvcDebug =
      process.env.DEBUG_PRIVSVC === "1" || process.env.DEBUG_PRIVSVC === "true";
    try {
      if (privsvcDebug && ctx.priv?.on) {
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
        log.info("Active runtime policy - In Snapshot", snapshot);
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
    stopGrpcStream = startGrpcStream(ctx);

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

    // --- Periodic certificate renewal check ---
    //
    // Two problems the simple `setInterval(fn, 24h)` had:
    //
    //   1. Renewal storm. Every agent in the fleet checks on the same
    //      24-hour cadence, so a mass deployment puts the entire fleet
    //      at the renewal endpoint at hour 24, 48, 72... Adding uniform
    //      jitter across ±1 h spreads the herd.
    //
    //   2. Enrollment mutation race. The previous code called
    //      `maybeRenewClientCertificate({enrollment: currentCtx.enrollment, ...})`
    //      which captures the reference at call time, then awaits the
    //      privsvc round-trip. If gRPC pushed a rotateCert during that
    //      window, `currentCtx.enrollment` got mutated mid-await and we
    //      could end up writing back an inconsistent state. Snapshot
    //      locally so the renewal operates on a stable view.
    const CERT_RENEWAL_BASE_MS = Number(
      process.env.CERT_RENEWAL_CHECK_INTERVAL_MS || 24 * 60 * 60 * 1000
    );
    const CERT_RENEWAL_JITTER_MS = 60 * 60 * 1000; // ±1 h

    const armCertRenewal = () => {
      if (shuttingDown) return;
      if (certRenewalTimer) {
        clearTimeout(certRenewalTimer);
        certRenewalTimer = undefined;
      }
      const jitter = Math.floor(Math.random() * CERT_RENEWAL_JITTER_MS);
      const delayMs = CERT_RENEWAL_BASE_MS + jitter;

      certRenewalTimer = setTimeout(async () => {
        certRenewalTimer = undefined;
        if (!currentCtx || shuttingDown) return;

        // Snapshot the enrollment BEFORE the await. If a rotateCert
        // control message fires during our call, it'll mutate the
        // context; we want to detect that by comparing thumbprints
        // after, not to operate on a half-mutated record.
        const enrollmentSnapshot = {
          ...currentCtx.enrollment,
          mtls: { ...currentCtx.enrollment.mtls }
        };
        const previousThumbprint = enrollmentSnapshot.mtls.clientCertThumbprint;

        try {
          const renewed = await maybeRenewClientCertificate({
            enrollment: enrollmentSnapshot,
            store: currentCtx.store,
            priv: currentCtx.priv,
            logger: currentCtx.logger
          });

          // Re-check that nobody else mutated enrollment while we were
          // awaiting. If they did (e.g. gRPC rotateCert), drop our
          // renewal result on the floor — the other path already
          // installed a newer cert. The next tick will re-evaluate.
          const liveThumbprint = currentCtx.enrollment.mtls.clientCertThumbprint;
          if (liveThumbprint !== previousThumbprint) {
            log.warn("[cert-renewal] enrollment mutated during renewal, discarding result", {
              previousThumbprint,
              liveThumbprint,
              renewedThumbprint: renewed.mtls.clientCertThumbprint
            });
          } else {
            currentCtx.enrollment = renewed;

            if (
              renewed.mtls.clientCertThumbprint &&
              renewed.mtls.clientCertThumbprint !== previousThumbprint
            ) {
              log.info("[cert-renewal] restarting gRPC bridge after certificate renewal");
              if (stopGrpcStream) stopGrpcStream();
              stopGrpcStream = startGrpcStream(currentCtx);
            }
          }
        } catch (e: any) {
          log.warn("[cert-renewal] periodic renewal failed", e?.message || e);
        } finally {
          armCertRenewal();
        }
      }, delayMs);
    };
    armCertRenewal();

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
      cleanupTimer = undefined;
    }

    if (certRenewalTimer) {
      // cert renewal is now a chained setTimeout (see armCertRenewal);
      // clearTimeout is the matching disposer, though Node treats both
      // clearTimeout and clearInterval identically for timer objects.
      clearTimeout(certRenewalTimer);
      certRenewalTimer = undefined;
    }

    if (stopGrpcStream) {
      stopGrpcStream();
      stopGrpcStream = null;
    }

    if (currentCtx) {
      await scheduler.stop(currentCtx);
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
