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
  private ctx: AgentContext | null = null;
  private inventoryRunning: boolean = false;
  private complianceRunning: boolean = false;
  private updateRunning: boolean = false;
  private patchRunning: boolean = false;
  private policyListeners: Array<{
    event: string;
    handler: (...args: any[]) => void;
  }> = [];

  async start(ctx: AgentContext) {
    this.clearPolicyListeners();
    this.ctx = ctx;

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

  private startPipelines(ctx: AgentContext) {

    this.stopAll();

    // inventory pipeline
    if (ctx.policyRuntime.isInventoryEnabled()) {

      const intervalSeconds = ctx.policyRuntime.getInventoryInterval();
      const jitter = Math.floor(Math.random() * 30000);

      logger.info("Inventory pipeline configured", {
        intervalSeconds,
        jitter
      });

      const timer = setInterval(() => {
        logger.info("[scheduler] inventory tick");
        this.runInventory(ctx).catch(err =>
          logger.error("Inventory error", { err })
        );
      }, intervalSeconds * 1000 + jitter);

      this.timers.set("inventory", timer);
    }

    // update pipeline
    if (ctx.policyRuntime.isUpdateEnabled()) {
      const intervalSeconds = 6 * 60 * 60; // 6h default
      const jitter = Math.floor(Math.random() * 30000);

      logger.info("Update pipeline enabled", { intervalSeconds });

      // immediate run (no jitter for first execution)
      this.runUpdate(ctx).catch(err =>
        logger.error("Update pipeline initial run error", { err })
      );

      // scheduled runs with jitter
      const timer = setInterval(() => {
        logger.info("[scheduler] update tick");
        this.runUpdate(ctx).catch(err =>
          logger.error("Update pipeline error", { err })
        );
      }, intervalSeconds * 1000 + jitter);

      this.timers.set("update", timer);
    }

    if (ctx.policyRuntime.isComplianceEnabled()) {

      const intervalSeconds = ctx.policyRuntime.getComplianceInterval();

      logger.info("Compliance pipeline enabled", { intervalSeconds });

      this.runCompliance(ctx).catch(err =>
        logger.error("Compliance pipeline initial run error", { err })
      );

      const timer = setInterval(() => {
        logger.info("[scheduler] compliance tick");
        this.runCompliance(ctx).catch(err =>
          logger.error("Compliance pipeline error", { err })
        );
      }, intervalSeconds * 1000);

      this.timers.set("compliance", timer);
    }

    // patch pipeline (future)
    if (ctx.policyRuntime.isPatchEnabled()) {

      const intervalSeconds = 24 * 60 * 60; // 24h default

      logger.info("Patch pipeline enabled", { intervalSeconds });

      this.runPatch(ctx).catch(err =>
        logger.error("Patch pipeline initial run error", { err })
      );

      const timer = setInterval(() => {
        logger.info("[scheduler] patch tick");
        this.runPatch(ctx).catch(err =>
          logger.error("Patch pipeline error", { err })
        );
      }, intervalSeconds * 1000);

      this.timers.set("patch", timer);
    }
  }

  reload() {

    if (!this.ctx) return;

    logger.info("TaskScheduler reload requested");

    this.startPipelines(this.ctx);
  }

  private stopAll() {

    for (const timer of this.timers.values()) {
      clearInterval(timer);
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

      if (!hasAnyChanges) {
        logger.info("Skipping FACTS enqueue — no changes detected (all modules)", {
          deviceId: ctx.enrollment.deviceId
        });
        return;
      }

      const facts = await buildDeviceFacts(ctx, namespaces);

      outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
      });

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        modules: Object.keys(namespaces),
        hasAnyChanges,
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

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        modules: Object.keys(namespaces),
        hasAnyChanges: hasChanges,
        scpChecks: Array.isArray(namespaces.scp.checks)
          ? namespaces.scp.checks.length
          : 0
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

    if ((this as any).patchRunning) {
      logger.warn("Patch scan already running, skipping overlapping execution");
      return;
    }

    (this as any).patchRunning = true;

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

      (this as any).patchRunning = false;

    }
  }
}

export const scheduler = new Scheduler();
