// src/core/scheduler.ts

import { outbox } from "../queue/sqlite-outbox";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { AgentContext } from "./agent-context";
import type { Namespaces } from "../domain/device-facts";
import type { AmpNamespace } from "../domain/amp-types";
import type { CdpNamespace } from "../domain/cdp-types";
import type { PmpNamespace } from "../domain/pmp-types";
import type { ScpNamespace } from "../domain/scp-types";
import { runUpdateTask } from "../update/update-task";

// Change-detection hash helpers live in namespace-hash.ts so they can
// be unit-tested without this file's outbox/update-task import graph.
import { hashNamespace, buildScpStateForHash, buildPmpStateForHash } from "./namespace-hash";

// Force-clear threshold for the *Running guard flags. If a worker has
// been "running" for longer than this, we assume it's hung on some
// upstream IO that will never return (privsvc socket gone half-open
// post sleep/wake, or HTTP fetch to api.tracenium.com stuck because
// the resolver cached an unreachable answer) and force the flag down
// so the NEXT tick can start a clean run.
//
// Why we don't try to abort the original run: it's awaited deep inside
// awaits that we don't own (plugin code, network libs, dpkg/winwmi
// calls). The hung promise will eventually settle when the OS gives up
// on the underlying syscall — and when it does, the finally-block sets
// the flag to false again, which is idempotent. The new tick we
// started in parallel may overlap briefly, but that's strictly better
// than "no inventory for 36 hours" which is what we observed in prod.
//
// 30 minutes is generous on purpose. Real legitimate worker durations:
//   inventory  : ~5–60 s (longer on big AMP catalogs)
//   compliance : ~5–30 s
//   patch      : 1–10 min (PMP scan), apply phase is bounded separately
//   update     : 30 s – 5 min (download + verify; install path forks
//                an installer subprocess and returns immediately)
//
// Hitting 30 min on any of these means something is unrecoverable.
const WORKER_STUCK_TIMEOUT_MS = 30 * 60 * 1000;

/**
 * Espera mínima antes del primer inventario tras arrancar.
 *
 * ⚠️ Este arranque rápido existe porque su ausencia se vio en producción: dos
 * Macs actualizadas a 1.1.52 seguían mostrándose en 1.1.50 y 1.1.51 en el
 * portal media hora después. El agente correcto ya estaba corriendo y
 * conectado — lo que faltaba era el snapshot que lleva la versión, y ése sólo
 * sale en el tick de inventario, que por defecto es cada SEIS HORAS.
 *
 * El scheduler ya tenía dos disparadores para justo este caso
 * (`forceInitialSnapshot` y `versionChanged`), y los dos funcionan; el problema
 * es que sólo se evalúan CUANDO CORRE EL TICK. Adelantar el primero es lo que
 * hace que sirvan.
 *
 * No es cero: el agente acaba de arrancar y conviene dejarlo estabilizar la
 * conexión gRPC y el privsvc antes de pedirle un inventario completo.
 */
const INITIAL_INVENTORY_DELAY_MS = 45 * 1000;

/**
 * Ventana sobre la que se reparte ese primer tick.
 *
 * ⚠️ Cinco minutos, no treinta segundos como el jitter de régimen. Una
 * actualización de flota reinicia muchos agentes casi a la vez, y todos
 * arrancarían su primer inventario en la misma ventana: el arreglo del dato
 * viejo se convertiría en una tormenta de snapshots contra el backend.
 */
const INITIAL_TICK_SPREAD_MS = 5 * 60 * 1000;

/**
 * Cuánto esperar antes del siguiente tick de un pipeline.
 *
 * Exportada y pura porque aquí vive la decisión, y la decisión tiene dos
 * regímenes que es fácil confundir:
 *
 *   primer tick  →  espera corta (45 s) repartida en una ventana ANCHA (5 min)
 *   en régimen   →  intervalo completo repartido en una ventana estrecha (30 s)
 *
 * ⚠️ Las ventanas resuelven problemas distintos y por eso no se comparten. La
 * estrecha desincroniza agentes que llevan horas corriendo. La ancha existe
 * porque una actualización de flota reinicia muchos agentes casi a la vez: sin
 * ella, el arreglo de un dato viejo se convertiría en una tormenta de
 * snapshots contra el backend en la misma ventana de 30 s.
 */
export function computeTickDelay(opts: {
  baseIntervalMs: number;
  jitterRangeMs: number;
  /** Presente SÓLO en el primer armado de un pipeline. */
  firstDelayMs?: number;
  /** Inyectable para que los tests no dependan del azar. */
  random?: () => number;
}): number {
  const rnd = opts.random ?? Math.random;
  const isFirst = opts.firstDelayMs !== undefined;
  const spreadMs = isFirst ? INITIAL_TICK_SPREAD_MS : opts.jitterRangeMs;
  const base = isFirst ? opts.firstDelayMs! : opts.baseIntervalMs;
  return base + Math.floor(rnd() * spreadMs);
}

class Scheduler {

  private timers: Map<string, NodeJS.Timeout> = new Map();
  // Which pipelines are currently "armed". We track this separately from
  // `timers` because a pipeline that's mid-tick (setTimeout has already
  // fired, run() is executing, next arm hasn't happened yet) has no
  // entry in `timers` but MUST be considered active so a straggler
  // re-arm after `stopAll()` doesn't resurrect a dead pipeline.
  private pipelineActive: Set<string> = new Set();
  private ctx: AgentContext | null = null;
  private inventoryRunning: boolean = false;
  private complianceRunning: boolean = false;
  private updateRunning: boolean = false;
  private patchRunning: boolean = false;
  private cdpRunning: boolean = false;

  // Wall-clock start timestamps for the *Running guards above. 0 when
  // not running. Used by `checkStuckWorker()` so the overlap-detection
  // path can distinguish "started 10s ago and still working" (normal)
  // from "started 2 hours ago and never finished" (zombie, force-clear).
  // Without these the guards became permanent shutoffs once the first
  // tick wedged — the precise production failure mode we're patching.
  private inventoryStartedAt: number = 0;
  private complianceStartedAt: number = 0;
  private updateStartedAt: number = 0;
  private patchStartedAt: number = 0;
  private cdpStartedAt: number = 0;

  /**
   * Returns true if the caller should proceed with a fresh run.
   * Returns false if the previous run is still legitimately in flight
   * and the caller should skip this tick.
   *
   * Side effect on stuck detection: logs an error and force-clears the
   * provided startedAtRef + the running flag (via the caller assigning
   * the result back). Callers must mutate their *Running and *StartedAt
   * fields based on the return; we can't do that from here without
   * generics / reflection that just clutters the call sites.
   */
  private checkStuckWorker(
    label: string,
    isRunning: boolean,
    startedAt: number
  ): { proceed: boolean; clearStuck: boolean } {
    if (!isRunning) {
      return { proceed: true, clearStuck: false };
    }
    const elapsed = Date.now() - startedAt;
    if (elapsed > WORKER_STUCK_TIMEOUT_MS) {
      logger.error(
        `${label} has been running for ${Math.round(elapsed / 1000)}s ` +
          `(> ${WORKER_STUCK_TIMEOUT_MS / 1000}s threshold). ` +
          `Force-clearing stuck flag and starting a new run.`
      );
      return { proceed: true, clearStuck: true };
    }
    logger.warn(`${label} already running, skipping overlapping execution`, {
      elapsedMs: elapsed
    });
    return { proceed: false, clearStuck: false };
  }
  // Forces one full AMP snapshot on the first inventory tick after the
  // daemon starts — ensures the server receives current posture after
  // an upgrade / reinstall / reboot, even if the AMP delta baseline on
  // disk says "no changes" (e.g. no apps added/removed between runs).
  private initialInventorySent: boolean = false;
  private policyListeners: Array<{
    event: string;
    handler: (...args: any[]) => void;
  }> = [];

  async start(ctx: AgentContext) {
    this.clearPolicyListeners();
    this.ctx = ctx;
    this.initialInventorySent = false;

    logger.info("TaskScheduler starting...");

    // immediate first run
    await this.runInventory(ctx);

    this.startPipelines(ctx);

    // --- dynamic policy bindings ---
    this.addPolicyListener(ctx, "inventoryIntervalChanged", (interval: number) => {
      logger.info("[scheduler] inventory interval updated", { interval });

      const existing = this.timers.get("inventory");
      if (existing) {
        clearInterval(existing);
        this.timers.delete("inventory");
      }

      if (ctx.policyRuntime.isInventoryEnabled()) {
        const jitter = Math.floor(Math.random() * 30000);

        const timer = setInterval(() => {
          logger.info("[scheduler] inventory tick");
          this.runInventory(ctx).catch(err =>
            logger.error("Inventory error", { err })
          );
        }, interval * 1000 + jitter);

        this.timers.set("inventory", timer);
      }
    });

    this.addPolicyListener(ctx, "pluginsChanged", (plugins: string[]) => {
      logger.info("[scheduler] plugins updated", { plugins });
      this.startPipelines(ctx);

      // Forzar un inventory tick INMEDIATO para que las nuevas
      // capabilities (que incluyen los plugins habilitados) lleguen
      // al backend sin esperar el próximo ciclo de inventory (default
      // 8h). Sin esto, el operador habilita PMP en tenant policy →
      // agente recibe + aplica → pero el dashboard plugin-coverage
      // sigue mostrando 0 PMP hasta el próximo inventory cycle, lo
      // cual confunde al operador y hace que parezca un bug.
      //
      // El runInventory enqueua via factsPipeline; si hay otro
      // inventory en flight, el pipeline lo serializa naturalmente.
      this.runInventory(ctx).catch(err =>
        logger.warn("[scheduler] post-policy inventory tick failed", { err: err?.message || err })
      );
    });

    this.addPolicyListener(ctx, "modulesChanged", (modules: string[]) => {
      logger.info("[scheduler] modules updated", { modules });
      this.startPipelines(ctx);

      // Mismo motivo que pluginsChanged: las modules habilitadas
      // (compliance, patch, etc.) impactan el agent_payload reportado
      // y los métricos de dashboard. Forzamos un inventory tick para
      // refresh inmediato.
      this.runInventory(ctx).catch(err =>
        logger.warn("[scheduler] post-policy inventory tick failed (modules)", { err: err?.message || err })
      );
    });

    this.addPolicyListener(ctx, "patchIntervalChanged", (interval: number) => {
      logger.info("[scheduler] patch interval updated", { interval });
      this.startPipelines(ctx);
    });

    this.addPolicyListener(ctx, "cdpIntervalChanged", (interval: number) => {
      logger.info("[scheduler] cdp interval updated", { interval });
      this.startPipelines(ctx);
    });

    this.addPolicyListener(ctx, "featuresChanged", (features: any) => {
      logger.info("[scheduler] features updated", { features });
      this.startPipelines(ctx);
    });
  }

  async stop(_ctx?: AgentContext) {
    logger.info("TaskScheduler stopping...");
    this.stopAll();
    this.clearPolicyListeners();
    this.ctx = null;
    logger.info("TaskScheduler stopped");
  }

  private addPolicyListener(
    ctx: AgentContext,
    event: string,
    handler: (...args: any[]) => void
  ) {
    ctx.policyRuntime.on(event, handler);
    this.policyListeners.push({ event, handler });
  }

  private clearPolicyListeners() {
    if (!this.ctx) {
      this.policyListeners = [];
      return;
    }

    for (const { event, handler } of this.policyListeners) {
      try {
        this.ctx.policyRuntime.off(event, handler);
      } catch {}
    }

    this.policyListeners = [];
  }

  /**
   * Arm `run` with fresh jitter every tick.
   *
   * Why chained setTimeout instead of setInterval:
   *
   *   setInterval(cb, base + jitter)
   *
   * samples `jitter` exactly once at pipeline start and reuses it forever.
   * So if two agents in the same tenant boot in the same minute, they
   * both hit the backend at `(start + base + jitter)`, then at
   * `(start + 2*(base + jitter))`, and so on — identical cadence, zero
   * desynchronisation. Great for throughput benchmarks, terrible for
   * production where we want the fleet spread out.
   *
   * Chained setTimeout with a fresh `Math.random()` on every re-arm
   * guarantees drift: after a few ticks, formerly-synchronised agents
   * have spread across the full [0, jitterRangeMs) range.
   *
   * The `pipelineActive` Set gate ensures that if `stopAll()` runs while
   * a tick is mid-execution, the re-arm is suppressed — otherwise we'd
   * leak a ghost timer that fires after the scheduler was told to stop.
   */
  private armJitteredPipeline(
    key: string,
    baseIntervalMs: number,
    jitterRangeMs: number,
    run: () => void,
    firstDelayMs?: number
  ): void {
    if (!this.pipelineActive.has(key)) return;

    const delayMs = computeTickDelay({ baseIntervalMs, jitterRangeMs, firstDelayMs });

    const timer = setTimeout(() => {
      // Clear the stored handle before running — a tick already in
      // flight shouldn't be clearTimeout()'d by stopAll.
      this.timers.delete(key);

      try {
        run();
      } catch (err) {
        logger.error("[scheduler] tick threw synchronously", { key, err });
      }

      // Re-arm with a fresh jitter sample. Drift accumulates naturally.
      // Sin firstDelayMs: el arranque rápido es una sola vez.
      this.armJitteredPipeline(key, baseIntervalMs, jitterRangeMs, run);
    }, delayMs);

    this.timers.set(key, timer);
  }

  private startPipelines(ctx: AgentContext) {

    this.stopAll();

    // inventory pipeline
    if (ctx.policyRuntime.isInventoryEnabled()) {

      const intervalSeconds = ctx.policyRuntime.getInventoryInterval();

      logger.info("Inventory pipeline configured", {
        intervalSeconds,
        jitterRangeMs: 30000
      });

      this.pipelineActive.add("inventory");
      this.armJitteredPipeline("inventory", intervalSeconds * 1000, 30000, () => {
        logger.info("[scheduler] inventory tick");
        this.runInventory(ctx).catch(err =>
          logger.error("Inventory error", { err })
        );
      // ⚠️ Sólo el inventario adelanta su primer tick. Es el único cuya
      // demora es visible para el operador: la versión del agente, el
      // software y el hardware que muestra el portal salen de aquí. El resto
      // de pipelines pueden esperar su turno.
      }, INITIAL_INVENTORY_DELAY_MS);
    }

    // update pipeline
    if (ctx.policyRuntime.isUpdateEnabled()) {
      // Sprint 1 of Policy v2 moved this from hardcoded `6 * 60 * 60`
      // to a policy-driven value. Default stays 21600s (6h) for
      // backward compat — operators see no behavior change unless
      // they explicitly tune `update.intervalSeconds` (or its v2
      // equivalent `agent.schedules.update.intervalSeconds`).
      const intervalSeconds = ctx.policyRuntime.getUpdateInterval();

      logger.info("Update pipeline enabled", { intervalSeconds });

      // immediate run (no jitter for first execution)
      this.runUpdate(ctx).catch(err =>
        logger.error("Update pipeline initial run error", { err })
      );

      this.pipelineActive.add("update");
      this.armJitteredPipeline("update", intervalSeconds * 1000, 30000, () => {
        logger.info("[scheduler] update tick");
        this.runUpdate(ctx).catch(err =>
          logger.error("Update pipeline error", { err })
        );
      });
    }

    if (ctx.policyRuntime.isComplianceEnabled()) {

      const intervalSeconds = ctx.policyRuntime.getComplianceInterval();

      logger.info("Compliance pipeline enabled", { intervalSeconds });

      this.runCompliance(ctx).catch(err =>
        logger.error("Compliance pipeline initial run error", { err })
      );

      this.pipelineActive.add("compliance");
      this.armJitteredPipeline("compliance", intervalSeconds * 1000, 30000, () => {
        logger.info("[scheduler] compliance tick");
        this.runCompliance(ctx).catch(err =>
          logger.error("Compliance pipeline error", { err })
        );
      });
    }

    // cdp pipeline — certificate discovery. Gated on the plugin flag
    // alone (no module toggle): a tenant opts in by adding "cdp" to
    // plugins.enabled, which is also the kill-switch.
    if (ctx.policyRuntime.pluginEnabled("cdp")) {

      const intervalSeconds = ctx.policyRuntime.getCdpInterval();

      logger.info("CDP pipeline enabled", { intervalSeconds });

      this.runCdp(ctx).catch(err =>
        logger.error("CDP pipeline initial run error", { err })
      );

      this.pipelineActive.add("cdp");
      this.armJitteredPipeline("cdp", intervalSeconds * 1000, 30000, () => {
        logger.info("[scheduler] cdp tick");
        this.runCdp(ctx).catch(err =>
          logger.error("CDP pipeline error", { err })
        );
      });
    }

    // patch pipeline (future)
    if (ctx.policyRuntime.isPatchEnabled()) {

      const intervalSeconds = ctx.policyRuntime.getPatchInterval();

      logger.info("Patch pipeline enabled", { intervalSeconds });

      this.runPatch(ctx).catch(err =>
        logger.error("Patch pipeline initial run error", { err })
      );

      this.pipelineActive.add("patch");
      this.armJitteredPipeline("patch", intervalSeconds * 1000, 30000, () => {
        logger.info("[scheduler] patch tick");
        this.runPatch(ctx).catch(err =>
          logger.error("Patch pipeline error", { err })
        );
      });
    }
  }

  reload() {

    if (!this.ctx) return;

    logger.info("TaskScheduler reload requested");

    this.startPipelines(this.ctx);
  }

  private stopAll() {

    // clearTimeout and clearInterval are interchangeable in Node — they
    // dispatch on the timer kind internally — so this works whether the
    // stored handle came from setTimeout (jittered pipelines) or
    // setInterval (legacy code paths, in case any remain).
    this.pipelineActive.clear();
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }

    this.timers.clear();
  }

  private async runInventory(ctx: AgentContext) {

    if (!ctx.policyRuntime.isInventoryEnabled()) {
      logger.info("Inventory module disabled by policy, skipping inventory");
      return;
    }

    if (!ctx.policyRuntime.pluginEnabled("amp")) {
      logger.info("AMP plugin disabled by policy, skipping inventory");
      return;
    }

    {
      const { proceed, clearStuck } = this.checkStuckWorker(
        "Inventory",
        this.inventoryRunning,
        this.inventoryStartedAt
      );
      if (!proceed) return;
      if (clearStuck) {
        // Previous run is zombie. Drop the guard so the new run below
        // can proceed; the zombie's finally-block will set it to false
        // again whenever it eventually unblocks (no-op vs our new run
        // which has its own setter at the bottom of this block).
        this.inventoryRunning = false;
        this.inventoryStartedAt = 0;
      }
    }

    this.inventoryRunning = true;
    this.inventoryStartedAt = Date.now();

    try {

      logger.info("Collecting AMP facts...")
        //deviceId: ctx.enrollment.deviceId,
        //policyVersion: (ctx.policyRuntime as any).getPolicyVersion?.()
      //});

      const namespaces = {} as Namespaces;

      // AMP (Asset Management)
      if (ctx.policyRuntime.pluginEnabled("amp")) {
        try {
          namespaces.amp = await ctx.plugins.run("amp.collect") as AmpNamespace;
        } catch (err) {
          logger.error("AMP plugin execution failed", { err });
        }
      }

      // No namespaces collected
      if (Object.keys(namespaces).length === 0) {
        logger.warn("No plugin namespaces returned, skipping snapshot");
        return;
      }

      // Determine if ANY module has changes
      const hasAnyChanges = Object.values(namespaces).some((ns: any) => {
        if (!ns) return false;
        return (
          ns?.software?.hasChanges === true ||
          ns?.printers?.hasChanges === true ||
          ns?.hasChanges === true
        );
      });

      // Always ship the first snapshot after a daemon (re)start. The
      // persisted software baseline survives pkg re-installs, so the
      // delta alone would skip the upload and the server would never
      // see the post-upgrade state. Marking the flag AFTER enqueue so
      // a failure here keeps forcing retries on subsequent ticks.
      const forceInitialSnapshot = !this.initialInventorySent;

      // Second trigger: force a re-snapshot whenever the running
      // agentVersion differs from what was baked into the last shipped
      // snapshot. Prevents the degenerate case where:
      //   1. Agent at 1.0.87 sends a snapshot.
      //   2. Agent auto-updates to 1.1.0 (restart, initial snapshot
      //      fires, but gRPC/outbox were briefly down so it fails to
      //      ship).
      //   3. Subsequent ticks see `hasAnyChanges=false` (software is
      //      unchanged) and skip the enqueue. Backend is stuck with a
      //      phantom "1.0.87" view of a device that's really on 1.1.0.
      //
      // The hash over the namespace intentionally excludes `agent.*`
      // (version, coreVersion, capabilities) because we want software
      // changes to drive the cadence — but a version bump is itself a
      // semantic change the backend needs to know about. We track it
      // separately in outbox state.
      const lastSentVersion = outbox.getState("lastSentAgentVersion");
      const currentVersion = ctx.config.agentVersion || "";
      const versionChanged = lastSentVersion !== currentVersion;

      if (!hasAnyChanges && !forceInitialSnapshot && !versionChanged) {
        logger.info("Skipping FACTS enqueue — no changes detected (all modules)", {
          deviceId: ctx.enrollment.deviceId,
          currentVersion,
          lastSentVersion
        });
        return;
      }

      if (versionChanged && !hasAnyChanges && !forceInitialSnapshot) {
        logger.info("Forcing FACTS enqueue — agentVersion changed since last snapshot", {
          previousVersion: lastSentVersion,
          currentVersion
        });
      }

      // When we're forcing a snapshot (startup OR version-change) and
      // the AMP provider returned software without items (delta said
      // "no changes"), re-hydrate items from the baseline so the
      // server doesn't get a partial snapshot on first contact.
      const needsRehydrate = forceInitialSnapshot || versionChanged;
      if (needsRehydrate && namespaces.amp?.software && namespaces.amp.software.items == null) {
        try {
          const { loadSoftwareBaseline } = await import("../domain/software-baseline-repo");
          const baseline = loadSoftwareBaseline() ?? [];
          if (baseline.length > 0) {
            namespaces.amp.software.items = baseline as any;
            namespaces.amp.software.count = baseline.length;
          }
        } catch (err) {
          logger.warn("Failed to rehydrate AMP software baseline for initial snapshot", { err });
        }
      }

      // Same rehydration for printers on a forced snapshot: the delta cycle
      // elides items[] when unchanged, so a first-contact/version-change
      // snapshot must carry the full printer list from the local baseline.
      if (needsRehydrate && namespaces.amp?.printers && namespaces.amp.printers.items == null) {
        try {
          const { loadPrinterBaseline } = await import("../domain/printer-baseline-repo");
          const baseline = loadPrinterBaseline() ?? [];
          if (baseline.length > 0) {
            namespaces.amp.printers.items = baseline as any;
            namespaces.amp.printers.count = baseline.length;
          }
        } catch (err) {
          logger.warn("Failed to rehydrate AMP printer baseline for initial snapshot", { err });
        }
      }

      const facts = await buildDeviceFacts(ctx, namespaces);

      outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
      });

      // Record the agentVersion we just shipped so the next tick's
      // `versionChanged` check works correctly. Stored in outbox state
      // (SQLite), so it survives daemon restarts — exactly what we
      // want, since an upgrade+restart is the scenario this fix targets.
      try {
        outbox.setState("lastSentAgentVersion", currentVersion);
      } catch (err) {
        logger.warn("Failed to persist lastSentAgentVersion", { err });
      }

      // Stamp the wall-clock time the inventory snapshot just shipped.
      // The control-message path (`collectFactsSnapshot` over gRPC)
      // reads this to skip a redundant collect when the backend asks
      // for a snapshot moments after the scheduler already sent one —
      // the pathology that produced 4-second-paired sends with one
      // empty twin (see grpc-stream.ts cooldown check).
      try {
        outbox.setState("lastSentFactsAt:inventory", String(Date.now()));
      } catch (err) {
        logger.warn("Failed to persist lastSentFactsAt:inventory", { err });
      }

      this.initialInventorySent = true;

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        modules: Object.keys(namespaces),
        hasAnyChanges,
        forceInitialSnapshot,
        versionChanged,
        currentVersion,
        ampSoftwareItems: Array.isArray(namespaces.amp?.software?.items)
          ? namespaces.amp.software.items.length
          : 0
      });

    } catch (err) {

      logger.error("Inventory pipeline failed", { err });

    } finally {

      this.inventoryRunning = false;
      this.inventoryStartedAt = 0;

    }
  }

  private async runCompliance(ctx: AgentContext) {

    if (!ctx.policyRuntime.isComplianceEnabled()) {
      logger.info("Compliance module disabled by policy, skipping compliance");
      return;
    }

    if (!ctx.policyRuntime.pluginEnabled("scp")) {
      logger.info("SCP plugin disabled by policy, skipping compliance");
      return;
    }

    {
      const { proceed, clearStuck } = this.checkStuckWorker(
        "Compliance",
        this.complianceRunning,
        this.complianceStartedAt
      );
      if (!proceed) return;
      if (clearStuck) {
        this.complianceRunning = false;
        this.complianceStartedAt = 0;
      }
    }

    this.complianceRunning = true;
    this.complianceStartedAt = Date.now();

    try {
      logger.info("Collecting SCP facts...");

      const namespaces = {} as Namespaces;

      try {
        namespaces.scp = await ctx.plugins.run("scp.collect") as ScpNamespace;
      } catch (err) {
        logger.error("SCP plugin execution failed", { err });
      }

      if (!namespaces.scp) {
        logger.warn("No SCP namespace returned, skipping compliance snapshot");
        return;
      }

      const currentHash = hashNamespace(buildScpStateForHash(namespaces.scp));
      const previousHash = outbox.getState("namespaceHash:scp");
      const hasChanges = currentHash !== previousHash;

      namespaces.scp.hasChanges = hasChanges;

      if (!hasChanges) {
        logger.info("Skipping SCP FACTS enqueue — no changes detected", {
          deviceId: ctx.enrollment.deviceId,
          namespace: "scp"
        });
        return;
      }

      const facts = await buildDeviceFacts(ctx, namespaces);

      outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
      });
      outbox.setState("namespaceHash:scp", currentHash);
      try {
        outbox.setState("lastSentFactsAt:compliance", String(Date.now()));
      } catch (err) {
        logger.warn("Failed to persist lastSentFactsAt:compliance", { err });
      }

      // Schema 2.0: the agent no longer emits a checks[] array — the
      // server-side catalog evaluator produces findings. We log the
      // evidence blocks present instead so we can trace what reached the
      // backend without needing to re-parse the payload.
      const scpEvidenceKeys = Object.keys(namespaces.scp).filter(
        (k) => k !== "schemaVersion" && k !== "collector" && k !== "hasChanges"
      );

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        modules: Object.keys(namespaces),
        hasAnyChanges: hasChanges,
        scpSchemaVersion: namespaces.scp.schemaVersion,
        scpCollectorVersion: namespaces.scp.collector?.version ?? null,
        scpEvidenceKeys
      });

      // ── Sprint 2 of Policy v2: security enforcer pass ───────────
      //
      // Piggybacks on the compliance pipeline because:
      //   1. We've just collected fresh SCP evidence; the enforcer's
      //      read-state probes effectively re-confirm what the
      //      collector saw, but on a per-checkId basis.
      //   2. The compliance cadence (default 8h) matches the
      //      right "how often should we re-check posture drift"
      //      cadence too — every 30 min would hammer hosts, every
      //      24h would be too lax to catch drift before audit.
      //   3. The compliance gate (isComplianceEnabled +
      //      pluginEnabled("scp")) is the right gate for RUNNING the
      //      pass — leer estado y reportar drift es compliance.
      //
      // ⚠️ Lo que ese gate NO cubre es la ESCRITURA. Con el modelo de tiers,
      // remediar en el endpoint lo habilita PMP (enterprise), no SCP
      // (professional). Ese corte vive dentro del enforcer
      // (`effectiveMode`, que degrada `auto` a `report-only` sin pmp) y NO
      // aquí: apagar el pase entero le quitaría al tenant la detección de
      // drift, que sí ha pagado.
      //
      // The enforcer is fail-soft: any error inside swallows here
      // so a busted privsvc call doesn't take down the compliance
      // pipeline that just succeeded.
      try {
        const { runSecurityEnforce } = await import("../security/enforcer");
        await runSecurityEnforce(ctx);
      } catch (secErr: any) {
        logger.warn("Security enforce pass failed (non-fatal)", {
          error: secErr?.message || String(secErr),
        });
      }

    } catch (err) {

      logger.error("Compliance pipeline failed", { err });

    } finally {

      this.complianceRunning = false;
      this.complianceStartedAt = 0;

    }
  }

  private async runCdp(ctx: AgentContext) {

    if (!ctx.policyRuntime.pluginEnabled("cdp")) {
      logger.info("CDP plugin disabled by policy, skipping certificate discovery");
      return;
    }

    {
      const { proceed, clearStuck } = this.checkStuckWorker(
        "CDP",
        this.cdpRunning,
        this.cdpStartedAt
      );
      if (!proceed) return;
      if (clearStuck) {
        this.cdpRunning = false;
        this.cdpStartedAt = 0;
      }
    }

    this.cdpRunning = true;
    this.cdpStartedAt = Date.now();

    try {
      logger.info("Collecting CDP certificate inventory...");

      const namespaces = {} as Namespaces;

      try {
        namespaces.cdp = await ctx.plugins.run("cdp.collect") as CdpNamespace;
      } catch (err) {
        logger.error("CDP plugin execution failed", { err });
      }

      if (!namespaces.cdp) {
        logger.warn("No CDP namespace returned, skipping certificate snapshot");
        return;
      }

      // Unlike SCP, hasChanges is computed by the plugin itself against
      // its SQLite baseline (AMP-style delta) — no hash gate needed here.
      if (!namespaces.cdp.hasChanges) {
        logger.info("Skipping CDP FACTS enqueue — no certificate changes detected", {
          deviceId: ctx.enrollment.deviceId,
          namespace: "cdp",
          certCount: namespaces.cdp.certificates?.count ?? 0
        });
        return;
      }

      const facts = await buildDeviceFacts(ctx, namespaces);

      outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
      });
      try {
        outbox.setState("lastSentFactsAt:cdp", String(Date.now()));
      } catch (err) {
        logger.warn("Failed to persist lastSentFactsAt:cdp", { err });
      }

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        modules: Object.keys(namespaces),
        cdpSchemaVersion: namespaces.cdp.schemaVersion,
        cdpCertCount: namespaces.cdp.certificates?.count ?? 0,
        cdpMode: namespaces.cdp.certificates?.items ? "baseline" : "delta",
        cdpTruncated: namespaces.cdp.truncated,
        cdpCollectorError: namespaces.cdp.collectorError?.phase ?? null
      });

    } catch (err) {

      logger.error("CDP pipeline failed", { err });

    } finally {

      this.cdpRunning = false;
      this.cdpStartedAt = 0;

    }
  }

  private async runUpdate(ctx: AgentContext) {

    if (!ctx.policyRuntime.isUpdateEnabled()) {
      logger.info("Update disabled by policy, skipping update check");
      return;
    }

    {
      const { proceed, clearStuck } = this.checkStuckWorker(
        "Update",
        this.updateRunning,
        this.updateStartedAt
      );
      if (!proceed) return;
      if (clearStuck) {
        this.updateRunning = false;
        this.updateStartedAt = 0;
      }
    }

    this.updateRunning = true;
    this.updateStartedAt = Date.now();

    try {

      logger.info("Running update check...", {
        deviceId: ctx.enrollment.deviceId
      });

      await runUpdateTask(ctx, {
        logger,
        force: true,
        // Prefer the site's distribution point over the internet. Without this
        // the periodic check — which is how the fleet actually moves, since it
        // needs no job — always pulled the installer over the WAN, once per
        // endpoint, even where a DP on the same switch already held it. The
        // per-OS updater falls through to the direct download on its own, so a
        // stale or unreachable DP costs a few seconds, not the update.
        dpBaseUrls: ctx.policyRuntime?.dpBaseUrls?.() ?? []
      });

    } catch (err) {

      logger.error("Update task failed", { err });

    } finally {

      this.updateRunning = false;
      this.updateStartedAt = 0;

    }
  }

  private async runPatch(ctx: AgentContext) {

    if (!ctx.policyRuntime.isPatchEnabled()) {
      logger.info("Patch module disabled by policy, skipping patch scan");
      return;
    }

    if (!ctx.policyRuntime.pluginEnabled("pmp")) {
      logger.info("PMP plugin disabled by policy, skipping patch scan");
      return;
    }

    // Use the typed field directly — the other three pipelines
    // (inventoryRunning / complianceRunning / updateRunning) all access
    // their guard via `this.xRunning`, and mixing any-casts in just one
    // pipeline hides future bugs from the compiler (e.g. a typo in the
    // property name would silently create a second unused property
    // rather than failing typecheck).
    {
      const { proceed, clearStuck } = this.checkStuckWorker(
        "Patch scan",
        this.patchRunning,
        this.patchStartedAt
      );
      if (!proceed) return;
      if (clearStuck) {
        this.patchRunning = false;
        this.patchStartedAt = 0;
      }
    }

    this.patchRunning = true;
    this.patchStartedAt = Date.now();

    try {
      logger.info("Collecting PMP facts...");

      const namespaces = {} as Namespaces;

      try {
        namespaces.pmp = await ctx.plugins.run("pmp.collect") as PmpNamespace;
      } catch (err) {
        logger.error("PMP plugin execution failed", { err });
      }

      if (!namespaces.pmp) {
        logger.warn("No PMP namespace returned, skipping patch snapshot");
        return;
      }

      const currentHash = hashNamespace(buildPmpStateForHash(namespaces.pmp));
      const previousHash = outbox.getState("namespaceHash:pmp");
      const hasChanges = currentHash !== previousHash;

      namespaces.pmp.hasChanges = hasChanges;

      if (!hasChanges) {
        logger.info("Skipping PMP FACTS enqueue — no changes detected", {
          deviceId: ctx.enrollment.deviceId,
          namespace: "pmp"
        });
        return;
      }

      const facts = await buildDeviceFacts(ctx, namespaces);

      outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
      });
      outbox.setState("namespaceHash:pmp", currentHash);
      try {
        outbox.setState("lastSentFactsAt:patch", String(Date.now()));
      } catch (err) {
        logger.warn("Failed to persist lastSentFactsAt:patch", { err });
      }

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        modules: Object.keys(namespaces),
        hasAnyChanges: hasChanges,
        pmpInstalledPatchCount: Number(namespaces.pmp.scan?.installedPatchCount ?? 0)
      });

    } catch (err) {

      logger.error("Patch pipeline failed", { err });

    } finally {

      this.patchRunning = false;
      this.patchStartedAt = 0;

    }
  }
}

export const scheduler = new Scheduler();
