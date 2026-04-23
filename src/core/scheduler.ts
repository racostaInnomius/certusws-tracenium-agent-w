// src/core/scheduler.ts

import { outbox } from "../queue/sqlite-outbox";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { AgentContext } from "./agent-context";
import type { Namespaces } from "../domain/device-facts";
import type { AmpNamespace } from "../domain/amp-types";
import type { PmpNamespace } from "../domain/pmp-types";
import type { ScpNamespace } from "../domain/scp-types";
import { runUpdateTask } from "../update/update-task";
import crypto from "crypto";

function normalizeForHash(value: unknown): unknown {
  if (value === undefined) {
    return null;
  }

  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(normalizeForHash);
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entryValue]) => [key, normalizeForHash(entryValue)]);

  return Object.fromEntries(entries);
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map((key) => `"${key}":${stableStringify((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function hashNamespace(value: unknown): string {
  return crypto.createHash("sha256").update(stableStringify(normalizeForHash(value))).digest("hex");
}

function buildScpStateForHash(namespace: ScpNamespace) {
  const { hasChanges: _ignored, ...rest } = namespace;
  return rest;
}

function buildPmpStateForHash(namespace: PmpNamespace) {
  const { hasChanges: _ignored, ...rest } = namespace;
  return rest;
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

      // rebuild pipelines safely
      this.startPipelines(ctx);
    });

    this.addPolicyListener(ctx, "modulesChanged", (modules: string[]) => {
      logger.info("[scheduler] modules updated", { modules });
    });

    this.addPolicyListener(ctx, "featuresChanged", (features: any) => {
      logger.info("[scheduler] features updated", { features });
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
    run: () => void
  ): void {
    if (!this.pipelineActive.has(key)) return;

    const jitter = Math.floor(Math.random() * jitterRangeMs);
    const delayMs = baseIntervalMs + jitter;

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
      });
    }

    // update pipeline
    if (ctx.policyRuntime.isUpdateEnabled()) {
      const intervalSeconds = 6 * 60 * 60; // 6h default

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

    // patch pipeline (future)
    if (ctx.policyRuntime.isPatchEnabled()) {

      const intervalSeconds = 24 * 60 * 60; // 24h default

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

    if (this.inventoryRunning) {
      logger.warn("Inventory already running, skipping overlapping execution");
      return;
    }

    this.inventoryRunning = true;

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
        return ns?.software?.hasChanges === true || ns?.hasChanges === true;
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

    if (this.complianceRunning) {
      logger.warn("Compliance already running, skipping overlapping execution");
      return;
    }

    this.complianceRunning = true;

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

    } catch (err) {

      logger.error("Compliance pipeline failed", { err });

    } finally {

      this.complianceRunning = false;

    }
  }

  private async runUpdate(ctx: AgentContext) {

    if (!ctx.policyRuntime.isUpdateEnabled()) {
      logger.info("Update disabled by policy, skipping update check");
      return;
    }

    if (this.updateRunning) {
      logger.warn("Update already running, skipping overlapping execution");
      return;
    }

    this.updateRunning = true;

    try {

      logger.info("Running update check...", {
        deviceId: ctx.enrollment.deviceId
      });

      await runUpdateTask(ctx, {
        logger,
        force: true
      });

    } catch (err) {

      logger.error("Update task failed", { err });

    } finally {

      this.updateRunning = false;

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
    if (this.patchRunning) {
      logger.warn("Patch scan already running, skipping overlapping execution");
      return;
    }

    this.patchRunning = true;

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

    }
  }
}

export const scheduler = new Scheduler();
