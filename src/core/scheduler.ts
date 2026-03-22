// src/core/scheduler.ts

import { outbox } from "../queue/sqlite-outbox";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { AgentContext } from "./agent-context";
import type { Namespaces } from "../domain/device-facts";
import type { AmmNamespace } from "../domain/amm-types";
import { runUpdateTask } from "../update/update-task";

class Scheduler {

  private timers: Map<string, NodeJS.Timeout> = new Map();
  private ctx: AgentContext | null = null;
  private inventoryRunning: boolean = false;
  private updateRunning: boolean = false;

  async start(ctx: AgentContext) {
    this.ctx = ctx;

    logger.info("TaskScheduler starting...");

    // immediate first run
    await this.runInventory(ctx);

    this.startPipelines(ctx);

    // listen for policy changes
    ctx.policyRuntime.on("inventoryIntervalChanged", (interval: number) => {
      logger.info("Inventory interval changed by policy", { interval });
      this.reload();
    });

    ctx.policyRuntime.on("pluginsChanged", (plugins: string[]) => {
      logger.info("Plugin configuration changed", { plugins });
      this.reload();
    });
  }

  private startPipelines(ctx: AgentContext) {

    this.stopAll();

    // inventory pipeline
    if (ctx.policyRuntime.pluginEnabled("amm")) {

      const intervalSeconds = ctx.policyRuntime.getInventoryInterval();
      const jitter = Math.floor(Math.random() * 30000);

      logger.info("Inventory pipeline configured", {
        intervalSeconds,
        jitter
      });

      const timer = setInterval(() => {
        this.runInventory(ctx).catch(err =>
          logger.error("Inventory error", { err })
        );
      }, intervalSeconds * 1000 + jitter);

      this.timers.set("inventory", timer);
    }

    // update pipeline
    if (ctx.policyRuntime.pluginEnabled("update")) {

      const intervalSeconds = 6 * 60 * 60; // 6h default

      logger.info("Update pipeline enabled", { intervalSeconds });

      const timer = setInterval(() => {
        this.runUpdate(ctx).catch(err =>
          logger.error("Update pipeline error", { err })
        );
      }, intervalSeconds * 1000);

      this.timers.set("update", timer);
    }

    // compliance pipeline (future)
    if (ctx.policyRuntime.pluginEnabled("compliance")) {

      const intervalSeconds = 4 * 60 * 60; // 4h default

      logger.info("Compliance pipeline enabled", { intervalSeconds });

      const timer = setInterval(() => {
        logger.info("Compliance pipeline tick (not implemented yet)");
      }, intervalSeconds * 1000);

      this.timers.set("compliance", timer);
    }

    // patch pipeline (future)
    if (ctx.policyRuntime.pluginEnabled("patch")) {

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

    if (!ctx.policyRuntime.pluginEnabled("amm")) {
      logger.info("AMM plugin disabled by policy, skipping inventory");
      return;
    }

    if (this.inventoryRunning) {
      logger.warn("Inventory already running, skipping overlapping execution");
      return;
    }

    this.inventoryRunning = true;

    try {

      logger.info("Collecting AMM facts...", {
        deviceId: ctx.enrollment.deviceId,
        policyVersion: (ctx.policyRuntime as any).getPolicyVersion?.()
      });

      const namespaces = {} as Namespaces;

      // AMM (Asset Management)
      if (ctx.policyRuntime.pluginEnabled("amm")) {
        try {
          namespaces.amm = await ctx.plugins.run("amm.collect") as AmmNamespace;
        } catch (err) {
          logger.error("AMM plugin execution failed", { err });
        }
      }

      // SCM (future: Security / Compliance)
      if (ctx.policyRuntime.pluginEnabled("scm")) {
        try {
          namespaces.scm = await ctx.plugins.run("scm.collect");
        } catch (err) {
          logger.error("SCM plugin execution failed", { err });
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
        ammSoftwareItems: Array.isArray(namespaces.amm?.software?.items)
          ? namespaces.amm.software.items.length
          : 0
      });

    } catch (err) {

      logger.error("Inventory pipeline failed", { err });

    } finally {

      this.inventoryRunning = false;

    }
  }

  private async runUpdate(ctx: AgentContext) {

    if (!ctx.policyRuntime.pluginEnabled("update")) {
      logger.info("Update plugin disabled by policy, skipping update check");
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
        logger
      });

    } catch (err) {

      logger.error("Update task failed", { err });

    } finally {

      this.updateRunning = false;

    }
  }
}

export const scheduler = new Scheduler();