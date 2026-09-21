// src/core/scheduler.ts

import { outbox } from "../queue/sqlite-outbox";
import { decideFactsSend, namespacesHaveChanges } from "./inventory-send-gate";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { AgentContext } from "./agent-context";
import type { Namespaces } from "../domain/device-facts";
import type { AmpNamespace } from "../domain/amp-types";
import type { CdpNamespace } from "../domain/cdp-types";
import type { PmpNamespace } from "../domain/pmp-types";
import type { ScpNamespace } from "../domain/scp-types";
import { runUpdateTask } from "../update/update-task";
import os from "os";
import { DexCollector, defaultMemPct, defaultSourceDeps } from "../plugins/dex/dex-collector";
import { readCpuTimes } from "../plugins/dex/dex-windows";

// Change-detection hash helpers live in namespace-hash.ts so they can
// be unit-tested without this file's outbox/update-task import graph.
import { hashNamespace, buildScpStateForHash, buildPmpStateForHash } from "./namespace-hash";
import { decideComplianceSend } from "./compliance-send-gate";
import {
  PIPELINE_KEYS,
  capabilitySignature,
  diffPipelinePlan,
  readPipelinePlan,
  type PipelineKey,
  type PipelinePlan,
} from "./pipeline-plan";
import {
  STARTUP_SERIAL_ORDER,
  STARTUP_STEP_CAP_MS,
  startupPatchDelayMs,
} from "./startup-sequence";

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
  /**
   * ADR-0030 — experiencia del equipo. Va aparte de los pipelines del plan:
   * tiene dos ritmos (muestra por minuto, envío por hora), no pasa por el
   * carril del PrivSvc y no depende de intervalos de la política; se apaga
   * solo cuando AMP no está activo.
   */
  private dex: DexCollector | null = null;
  /**
   * Lo que está armado ahora mismo, y la firma de plugins+módulos que se
   * reportó. Contra esto se compara cada evento de policy: ver pipeline-plan.ts.
   */
  private plan: PipelinePlan | null = null;
  private capabilitySig: string | null = null;
  /**
   * Secuencia de arranque (startup-sequence.ts). La generación la anula al
   * parar o rearrancar; `startupPending` son los pipelines que la secuencia aún
   * no ha corrido: el reconciliador NO los lanza por su cuenta, o una policy
   * recibida al conectar dispararía el escaneo de parches saltándose la espera.
   */
  private startupGen = 0;
  private startupPending: Set<PipelineKey> = new Set();
  /** Uptime de la MÁQUINA en segundos. Inyectable en tests. */
  machineUptimeSeconds: () => number = () => os.uptime();
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
    this.startDex(ctx);

    // --- dynamic policy bindings ---
    //
    // ⚠️ `applyUpdate()` emite TODOS estos eventos en cada aplicación, y el
    // backend reenvía la policy aunque no haya cambiado. Antes cada uno
    // relanzaba los pipelines con escaneo inmediato: un reenvío ponía a la flota
    // entera a escanear a la vez. Ahora todos pasan por la misma reconciliación,
    // que sólo actúa sobre lo que cambió — el primero que llega aplica el diff
    // completo y los demás no encuentran nada. Ver pipeline-plan.ts.
    for (const event of [
      "inventoryIntervalChanged",
      "updateIntervalChanged",
      "complianceIntervalChanged",
      "cdpIntervalChanged",
      "patchIntervalChanged",
      "pluginsChanged",
      "modulesChanged",
      "featuresChanged",
    ]) {
      this.addPolicyListener(ctx, event, () => this.reconcilePipelines(ctx, event));
    }
  }

  /**
   * Aplica a los pipelines SÓLO lo que la policy cambió de verdad.
   *
   *   nada cambió            → nada
   *   armado / intervalo     → re-armar ese pipeline, sin correrlo
   *   pasa a hacer trabajo   → re-armar y correr ya
   *   plugins/módulos        → tick de inventario inmediato, para que el portal
   *                            vea las capabilities nuevas sin esperar al ciclo
   *                            (el motivo del tick forzado que había aquí)
   */
  private reconcilePipelines(ctx: AgentContext, reason: string) {
    const next = readPipelinePlan(ctx.policyRuntime);
    const { rearm, runNow } = diffPipelinePlan(this.plan, next);
    const sig = capabilitySignature(
      ctx.policyRuntime.getEnabledPlugins(),
      ctx.policyRuntime.listEnabledModules()
    );
    const capabilitiesChanged = sig !== this.capabilitySig;
    this.plan = next;
    this.capabilitySig = sig;

    if (rearm.length === 0 && runNow.length === 0 && !capabilitiesChanged) {
      logger.debug?.("[scheduler] policy re-applied, pipelines unchanged", { reason });
      return;
    }

    logger.info("[scheduler] policy changed the pipelines", { reason, rearm, runNow, capabilitiesChanged });

    for (const key of rearm) {
      this.stopPipeline(key);
      if (next[key].armed) this.armPipeline(ctx, key, next[key].intervalSeconds, false);
    }
    for (const key of runNow) {
      if (key === "inventory") continue;
      // La secuencia de arranque lo correrá en su turno, con el plan de entonces.
      if (this.startupPending.has(key)) continue;
      this.runPipelineNow(ctx, key);
    }
    if (runNow.includes("inventory") || capabilitiesChanged) {
      this.runPipelineNow(ctx, "inventory");
    }
  }

  private startDex(ctx: AgentContext) {
    this.dex?.stop();
    try {
      this.dex = new DexCollector({
        enabled: () => ctx.policyRuntime.pluginEnabled("amp"),
        nowMs: () => Date.now(),
        readCpu: () => readCpuTimes(),
        readMemPct: () => defaultMemPct(),
        sources: defaultSourceDeps(),
        getState: (k) => outbox.getState(k),
        setState: (k, v) => outbox.setState(k, v),
        enqueue: (payload) => outbox.enqueue({ type: "FACTS_SNAPSHOT", payload }),
        logger,
      });
      this.dex.start();
    } catch (err) {
      // Fail-soft: DEX no puede tumbar el scheduler.
      logger.warn("[dex] collector failed to start", { err });
      this.dex = null;
    }
  }

  async stop(_ctx?: AgentContext) {
    logger.info("TaskScheduler stopping...");
    this.dex?.stop();
    this.dex = null;
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

  /**
   * Arranque completo: al iniciar el scheduler y en un reload() explícito. Los
   * eventos de policy NO pasan por aquí — ver reconcilePipelines.
   */
  private startPipelines(ctx: AgentContext) {

    this.stopAll();

    const plan = readPipelinePlan(ctx.policyRuntime);
    this.plan = plan;
    this.capabilitySig = capabilitySignature(
      ctx.policyRuntime.getEnabledPlugins(),
      ctx.policyRuntime.listEnabledModules()
    );

    for (const key of PIPELINE_KEYS) {
      if (!plan[key].armed) continue;
      logger.info(`${key} pipeline enabled`, { intervalSeconds: plan[key].intervalSeconds });
      this.armPipeline(ctx, key, plan[key].intervalSeconds, true);
    }

    // El inventario ya corrió en start() y adelanta su primer tick. El update es
    // una comprobación de red, no va por el carril del PrivSvc: corre ya.
    if (plan.update.armed) this.runPipelineNow(ctx, "update");
    // compliance → CDP → parches, en serie y con la espera de uptime.
    void this.runStartupSequence(ctx);
  }

  /** Ver startup-sequence.ts. Nunca lanza. */
  private async runStartupSequence(ctx: AgentContext): Promise<void> {
    const gen = ++this.startupGen;
    this.startupPending = new Set(STARTUP_SERIAL_ORDER);
    const alive = () => gen === this.startupGen;

    for (const key of STARTUP_SERIAL_ORDER) {
      if (!alive()) return;

      if (key === "patch") {
        const waitMs = startupPatchDelayMs(this.machineUptimeSeconds());
        if (waitMs > 0) {
          logger.info("[scheduler] startup patch scan waits for machine uptime", { waitMs });
          await delay(waitMs);
          if (!alive()) return;
        }
      }

      // El plan VIGENTE, no el del arranque: una policy pudo cambiarlo mientras
      // tanto (y el reconciliador dejó este pipeline para aquí).
      this.startupPending.delete(key);
      if (!this.plan?.[key].armed) continue;

      const finished = await withCap(this.runPipeline(ctx, key), STARTUP_STEP_CAP_MS).catch(err => {
        logger.error(`${key} startup run error`, { err });
        return true;
      });
      if (!finished) {
        logger.warn(`[scheduler] startup ${key} still running after cap, moving on`, {
          capMs: STARTUP_STEP_CAP_MS
        });
      }
    }
  }

  /**
   * Arma el temporizador de un pipeline. `initial` sólo al arrancar: es lo que
   * adelanta el primer tick del inventario (INITIAL_INVENTORY_DELAY_MS). Un
   * cambio de intervalo NO lo usa, o cada cambio de policy traería un
   * inventario extra a los 45 s.
   */
  private armPipeline(ctx: AgentContext, key: PipelineKey, intervalSeconds: number, initial: boolean) {
    this.pipelineActive.add(key);
    // ⚠️ Sólo el inventario adelanta su primer tick. Es el único cuya demora es
    // visible para el operador: la versión del agente, el software y el
    // hardware que muestra el portal salen de aquí.
    const firstDelayMs = initial && key === "inventory" ? INITIAL_INVENTORY_DELAY_MS : undefined;
    this.armJitteredPipeline(
      key,
      intervalSeconds * 1000,
      30000,
      () => {
        logger.info(`[scheduler] ${key} tick`);
        this.runPipeline(ctx, key).catch(err => logger.error(`${key} pipeline error`, { err }));
      },
      firstDelayMs
    );
  }

  private runPipelineNow(ctx: AgentContext, key: PipelineKey) {
    this.runPipeline(ctx, key).catch(err => logger.error(`${key} pipeline immediate run error`, { err }));
  }

  private runPipeline(ctx: AgentContext, key: PipelineKey): Promise<void> {
    switch (key) {
      case "inventory":
        return this.runInventory(ctx);
      case "update":
        return this.runUpdate(ctx);
      case "compliance":
        return this.runCompliance(ctx);
      case "cdp":
        return this.runCdp(ctx);
      case "patch":
        return this.runPatch(ctx);
    }
  }

  /** Para UN pipeline. Un tick ya en curso termina; su re-armado queda anulado. */
  private stopPipeline(key: PipelineKey) {
    this.pipelineActive.delete(key);
    const timer = this.timers.get(key);
    if (timer) clearTimeout(timer);
    this.timers.delete(key);
  }

  reload() {

    if (!this.ctx) return;

    logger.info("TaskScheduler reload requested");

    this.startPipelines(this.ctx);
  }

  private stopAll() {

    // Anula una secuencia de arranque en curso (incluida su espera de uptime).
    this.startupGen++;
    this.startupPending.clear();

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
      const hasAnyChanges = namespacesHaveChanges(namespaces as Record<string, any>);

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

      // Third trigger (ADR-0020 F2): «llevo demasiado tiempo callado».
      //
      // ⚠️ SIN ESTO EL SERVIDOR NO PUEDE DISTINGUIR «ESTABLE» DE «APAGADO». Este
      // gate se salta el envío cuando nada cambió, así que un portátil
      // encendido con el software quieto no manda NADA durante días. Medido
      // en T111 (21 días): hueco máximo entre envíos por equipo p50 3,6 d. Una
      // regla de software requerido/prohibido tiene que saber si el inventario
      // que mira está fresco, y el silencio no dice nada.
      //
      // Cuando salta, el namespace de software va en su forma no-op
      // (`hasChanges:false`, sin items ni delta): NO se rehidrata el baseline
      // —eso sólo lo necesitan el arranque y el cambio de versión—, así que
      // cuesta un mensaje pequeño al día. El backend ya trata el no-op
      // (modo 3 de applySoftwareDelta) y ahí sella «recogido a tal hora».
      //
      // Usa `lastSentFactsAt:inventory`, que ya se estampa en cada envío. Si no
      // existe —agente recién actualizado—, cuenta como vencido: un envío de
      // más una vez es mejor que no saber.
      const lastSentAtRaw = Number(outbox.getState("lastSentFactsAt:inventory"));
      const gate = decideFactsSend({
        hasAnyChanges,
        forceInitialSnapshot,
        versionChanged,
        lastSentAtMs: lastSentAtRaw,
        nowMs: Date.now(),
      });
      const silenceExceeded = gate.reasons.includes("silence");

      if (!gate.send) {
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

      // La línea que se busca en campo para confirmar que el latido sale.
      if (silenceExceeded && !hasAnyChanges && !forceInitialSnapshot && !versionChanged) {
        logger.info("Forcing FACTS enqueue — inventory silence exceeded (no-op heartbeat)", {
          lastSentAtMs: lastSentAtRaw
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
      // ADR-0027 — integridad de ficheros. Va ANTES de SCP y aparte: viaja en
      // su propio mensaje, y el snapshot de SCP de abajo puede salir temprano
      // (sin cambios) sin que eso deje la vigilancia de ficheros sin correr.
      // Fail-soft: un disco lento o un permiso raro no tumban el cumplimiento.
      try {
        const { runFileIntegrityPass, realFs } = await import("../plugins/scp/file-integrity-pipeline");
        const { loadFileIntegrityBaseline, replaceFileIntegrityBaseline } = await import("../domain/file-integrity-baseline-repo");
        const { FACTS_SCHEMA_VERSION } = await import("../update/update-source-report");
        const fim = await runFileIntegrityPass({
          platform: os.platform(),
          policy: ctx.policyRuntime.getFileIntegrity(),
          fs: realFs,
          now: Date.now(),
          getState: (k) => outbox.getState(k),
          setState: (k, v) => outbox.setState(k, v),
          enqueue: (payload) => outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: payload as any }),
          loadBaseline: loadFileIntegrityBaseline,
          replaceBaseline: replaceFileIntegrityBaseline,
          schemaVersion: FACTS_SCHEMA_VERSION,
        });
        if (fim.sent) logger.info("FIM facts enqueued", { kind: fim.kind, scope: fim.scope, files: fim.files });
      } catch (fimErr: any) {
        logger.warn("File integrity pass failed (non-fatal)", { error: fimErr?.message || String(fimErr) });
      }

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

      // P3-11 — sin cambios también se manda una vez al día: el snapshot con
      // fecha es la evidencia de que el equipo se evaluó. Ver
      // compliance-send-gate.ts.
      const complianceGate = decideComplianceSend({
        hasChanges,
        lastSentAtMs: Number(outbox.getState("lastSentFactsAt:compliance")),
        nowMs: Date.now()
      });
      if (!complianceGate.send) {
        logger.info("Skipping SCP FACTS enqueue — no changes detected", {
          deviceId: ctx.enrollment.deviceId,
          namespace: "scp"
        });
        return;
      }
      if (!hasChanges) {
        logger.info("Forcing SCP FACTS enqueue — compliance silence exceeded (daily heartbeat)", {
          deviceId: ctx.enrollment.deviceId
        });
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

/** Espera sin retener el proceso: parar el agente no debe esperar a esto. */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => {
    const t = setTimeout(resolve, ms);
    (t as any).unref?.();
  });
}

/** true si `p` terminó antes de `ms`; false si se agotó el techo (p sigue corriendo). */
async function withCap(p: Promise<unknown>, ms: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const cap = new Promise<boolean>(resolve => {
    timer = setTimeout(() => resolve(false), ms);
    (timer as any).unref?.();
  });
  try {
    return await Promise.race([p.then(() => true), cap]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export const scheduler = new Scheduler();
