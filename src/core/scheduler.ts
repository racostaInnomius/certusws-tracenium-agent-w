// src/core/scheduler.ts

import { outbox } from "../queue/sqlite-outbox";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { AgentContext } from "./agent-context";
import type { Namespaces } from "../domain/device-facts";
import type { AmpNamespace } from "../domain/amp-types";
import { runUpdateTask } from "../update/update-task";

class Scheduler {

  private timers: Map<string, NodeJS.Timeout> = new Map();
  private ctx: AgentContext | null = null;
  private inventoryRunning: boolean = false;
  private updateRunning: boolean = false;
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

    // compliance pipeline (future)
    if (ctx.policyRuntime.isComplianceEnabled()) {

      const intervalSeconds = 4 * 60 * 60; // 4h default

      logger.info("Compliance pipeline enabled", { intervalSeconds });

      const timer = setInterval(() => {
        logger.info("Compliance pipeline tick (not implemented yet)");
      }, intervalSeconds * 1000);

      this.timers.set("compliance", timer);
    }

    // patch pipeline (future)
    if (ctx.policyRuntime.isPatchEnabled()) {

      const intervalSeconds = 24 * 60 * 60; // 24h default

      logger.info("Patch pipeline enabled", { intervalSeconds });

      const timer = setInterval(() => {
        logger.info("Patch pipeline tick (not implemented yet)");
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

      // SCP (future: Security Compliance Plugin)
      if (ctx.policyRuntime.isComplianceEnabled() && ctx.policyRuntime.pluginEnabled("scp")) {
        try {
          namespaces.scp = await ctx.plugins.run("scp.collect");
        } catch (err) {
          logger.error("SCP plugin execution failed", { err });
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

      // prevent duplicate FACTS flooding (do not enqueue if one is already pending)
      const hasPending = (outbox as any).hasPendingOfType?.("FACTS_SNAPSHOT");

      if (hasPending) {
        logger.info("Skipping FACTS enqueue — pending event exists", {
          deviceId: ctx.enrollment.deviceId
        });
        return;
      }

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
}

export const scheduler = new Scheduler();
