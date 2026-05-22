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
let livenessWatchdogTimer: NodeJS.Timeout | undefined;
let stopGrpcStream: (() => void) | null = null;

// ── Liveness watchdog ───────────────────────────────────────────────
//
// Polls the trayStatus store every minute. If its last successful save
// happened more than MAX_STATUS_STALE_MS ago, the event loop is wedged
// somewhere (a worker promise that never settles, a privsvc socket
// half-open with no error event, etc.) and we exit so the service
// manager (launchd on macOS, systemd on Linux, WinSW + SCM on Windows)
// recycles us with clean state.
//
// Why this exists: every other layer of self-healing — worker
// stuck-flags, cached-client invalidation, scheduleReconnect — depends
// on the event loop being able to run callbacks. When the loop is
// fully stuck on an unresolved await, all those mechanisms become
// dead code. Status file writes are the canary because almost every
// real activity in the agent writes the status (heartbeats every 60s,
// reconnects, jobs, policy changes); a 5-minute silence means
// everything is stuck.
//
// 5 minutes vs 60 seconds for STALE: heartbeats fire every 60s, so 5
// min is 5 consecutive missed heartbeat-writes. Generous enough that
// a one-shot slow disk or transient privsvc hiccup doesn't kill us;
// strict enough that we recover in single-digit minutes instead of
// the 36 hours of zombie we observed in prod.
const LIVENESS_CHECK_INTERVAL_MS = 60_000;
const MAX_STATUS_STALE_MS = 5 * 60 * 1000;
// Grace period after startup before the watchdog can fire. Cold
// bootstrap (enrollment fetch, policy hydrate, outbox recovery) can
// legitimately take 30–90s on first boot, and we don't write the
// status file until trayStatus.writeStartupSnapshot runs. The
// constructor's `lastWriteAtMs = Date.now()` covers that, but the
// grace adds a safety margin so the watchdog never trips on the
// startup race itself.
const LIVENESS_STARTUP_GRACE_MS = 5 * 60 * 1000;
const livenessStartedAtMs = Date.now();

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

    try {
      const traySnapshot = ctx.trayStatus.writeStartupSnapshot(ctx);
      log.info("Tray status snapshot initialized", {
        file: ctx.trayStatus.getPath(),
        grpcConnected: traySnapshot.grpc.connected,
        policyVersion: traySnapshot.policy.version,
        plugins: traySnapshot.policy.plugins
      });
    } catch (e: any) {
      log.warn("Failed to initialize tray status snapshot", e?.message || e);
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

    // ── RCP capability re-advertise on policy change ─────────────────
    //
    // The `capabilities` field only travels on the initial Hello; once
    // the gRPC stream is up, the agent has no protocol-level way to
    // tell the backend "I now also advertise rcp.file". A PolicyUpdate
    // that flips remoteShell/File/Screen therefore has no observable
    // effect at the backend until the next full reconnect — by default,
    // that's the heartbeat-timeout silence window (minutes). For the
    // RCP UX that's unacceptable: an operator toggles "Remote screen
    // share" in Policies and expects the Screen button to enable on
    // the Remote Control page within seconds.
    //
    // Fix: watch the policyRuntime for featuresChanged events and
    // force a reconnect whenever any of the three RCP flags actually
    // changed (we compare against the previous snapshot so unrelated
    // featuresChanged events — selfUpdate toggled, etc. — don't trigger
    // a needless drop). The reconnect path already exists; calling
    // client.close() on the cached grpc client tears down the stream,
    // the supervisor in grpc-stream.ts builds a fresh client, and the
    // next Hello carries the updated capabilities array.
    //
    // ~1-2s downtime per RCP flag flip, which is fine — RCP sessions
    // can't be in flight at the same moment a feature is being toggled
    // (the same operator is doing both in different tabs).
    let lastRcpFlags = {
      remoteShell:  Boolean(ctx.policyRuntime.isFeatureEnabled("remoteShell")),
      remoteFile:   Boolean(ctx.policyRuntime.isFeatureEnabled("remoteFile")),
      remoteScreen: Boolean(ctx.policyRuntime.isFeatureEnabled("remoteScreen")),
    };
    ctx.policyRuntime.on("featuresChanged", () => {
      const next = {
        remoteShell:  Boolean(ctx.policyRuntime.isFeatureEnabled("remoteShell")),
        remoteFile:   Boolean(ctx.policyRuntime.isFeatureEnabled("remoteFile")),
        remoteScreen: Boolean(ctx.policyRuntime.isFeatureEnabled("remoteScreen")),
      };
      const changed =
        next.remoteShell  !== lastRcpFlags.remoteShell  ||
        next.remoteFile   !== lastRcpFlags.remoteFile   ||
        next.remoteScreen !== lastRcpFlags.remoteScreen;
      if (!changed) return;
      log?.info?.(
        "[rcp] policy flags changed — forcing gRPC reconnect to re-advertise capabilities",
        { from: lastRcpFlags, to: next }
      );
      lastRcpFlags = next;
      try {
        // Cached client lives on ctx — see grpc-client.ts. close() is
        // idempotent and the supervisor reconnects automatically.
        (ctx as any).__grpcClientInstance?.close?.();
      } catch (err: any) {
        log?.warn?.("[rcp] re-advertise close failed", {
          err: err?.message || String(err),
        });
      }
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

    // Arm the process-level liveness watchdog. This is the last-resort
    // defense: if every other recovery mechanism fails because the
    // event loop itself is wedged, this exits the process so launchd
    // restarts us. See the constants above for rationale.
    livenessWatchdogTimer = setInterval(() => {
      if (shuttingDown) return;
      const sinceStartupMs = Date.now() - livenessStartedAtMs;
      if (sinceStartupMs < LIVENESS_STARTUP_GRACE_MS) return;

      try {
        const lastWriteMs = currentCtx?.trayStatus?.getLastWriteMs?.();
        if (typeof lastWriteMs !== "number") return; // store not ready yet
        const staleMs = Date.now() - lastWriteMs;
        if (staleMs > MAX_STATUS_STALE_MS) {
          // Use the global `logger`, not `log` (= ctx.logger). The ctx
          // logger may share state with whatever component is wedged;
          // the global one writes to stdout/stderr directly. We want
          // the breadcrumb to land regardless of which subsystem is on
          // fire.
          // Service-manager name in the log message is picked at
          // runtime so the breadcrumb is accurate per-platform. The
          // mechanism is identical: non-zero exit → SM relaunches
          // (KeepAlive=true on launchd, Restart=always on systemd,
          // WinSW's <onfailure action="restart"> on Windows).
          const recycler =
            process.platform === "win32" ? "WinSW" :
            process.platform === "darwin" ? "launchd" : "systemd";
          logger.error(
            "Liveness watchdog: tray status not updated in " +
              `${Math.round(staleMs / 1000)}s (> ${MAX_STATUS_STALE_MS / 1000}s threshold). ` +
              `Event loop is wedged. Exiting so ${recycler} can recycle the process.`
          );
          // Same 250ms flush window as the crash handlers in
          // service.ts. unref so the timer can't keep the loop alive
          // beyond what's already in there.
          setTimeout(() => process.exit(1), 250).unref();
        }
      } catch (e: any) {
        // The watchdog itself must never throw — otherwise it'd become
        // the source of the very crash it's trying to prevent. Log
        // and continue.
        logger.warn(
          "Liveness watchdog: check threw",
          e?.message || String(e)
        );
      }
    }, LIVENESS_CHECK_INTERVAL_MS);
    (livenessWatchdogTimer as any)?.unref?.();

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

    if (livenessWatchdogTimer) {
      clearInterval(livenessWatchdogTimer);
      livenessWatchdogTimer = undefined;
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

// Crash handlers — log and EXIT.
//
// History: the previous implementation logged the error and let the
// process continue running. That seemed safe (one failed promise
// shouldn't take the agent down) but in practice it created a much
// worse failure mode: a single uncaught error from the privsvc
// socket reconnect path (ECONNREFUSED after privsvc was restarted by
// launchd) would silently land here, the event loop would continue
// with corrupted state (cached gRPC client pointing at a dead socket,
// running-job flags stuck true, status file frozen), and the agent
// would appear "alive" to launchd for days while doing zero useful
// work. The tray icon kept showing the last persisted state
// ("offline, http 504 stream timeout") because the writer that
// updates it was wedged in the same event loop.
//
// The correct behavior for a launchd-managed daemon is the opposite:
// surface every unrecoverable error as a process exit so launchd can
// recycle us. KeepAlive in the .plist means we come back within
// seconds, with a clean event loop and a fresh socket connection.
// A few minutes of "process restarted" beats days of zombie.
//
// We exit(1) — not (0) — so launchd treats this as an abnormal exit
// and ThrottleInterval governs restart cadence, preventing a tight
// crash loop from frying the box. Also: a non-zero code shows up in
// `launchctl print` and `log show` so the failure stays visible
// rather than being mistaken for a clean shutdown.
//
// The 250ms delay gives the logger transport a chance to flush its
// buffer (Node's stdout/stderr to a pipe is non-blocking, so an
// immediate exit can truncate the last few lines we care about most).
function crashAndExit(label: string, err: unknown): void {
  try {
    logger.error(`${label}:`, err);
  } catch {
    // Logger itself may be broken — last-resort stderr write so we
    // at least leave a forensic breadcrumb before the process dies.
    try {
      process.stderr.write(`${label}: ${String(err)}\n`);
    } catch {
      // Nothing left to do.
    }
  }
  // Detach event loop influence from any pending operations before
  // exit. unref'd timer fires only if event loop is otherwise empty;
  // if something is still queued it'll keep the loop alive, but the
  // setTimeout itself can't extend that window.
  setTimeout(() => process.exit(1), 250).unref();
}

process.on("uncaughtException", (err) => {
  crashAndExit("Uncaught exception", err);
});

process.on("unhandledRejection", (reason) => {
  crashAndExit("Unhandled rejection", reason);
});
