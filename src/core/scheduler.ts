// src/core/scheduler.ts

import { outbox } from "../queue/sqlite-outbox";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { AgentContext } from "./agent-context";

class Scheduler {

  private timers: Map<string, NodeJS.Timeout> = new Map();
  private ctx: AgentContext | null = null;
  private inventoryRunning: boolean = false;

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
          logger.error("Inventory error:", err)
        );
      }, intervalSeconds * 1000 + jitter);

      this.timers.set("inventory", timer);
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

      let ammNamespace;

      try {
        ammNamespace = await ctx.plugins.run("amm.collect");
      } catch (err) {
        logger.error("AMM plugin execution failed", err);
        return;
      }

      if (!ammNamespace) {
        logger.warn("AMM plugin returned no data, skipping snapshot");
        return;
      }

      const facts = await buildDeviceFacts(ctx, {
        amm: ammNamespace
      });

      outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
      });

      logger.info("FACTS_SNAPSHOT enqueued", {
        deviceId: ctx.enrollment.deviceId,
        softwareHasItems: !!ammNamespace.software?.items,
        softwareItemsLength: Array.isArray(ammNamespace.software?.items)
        ? ammNamespace.software.items.length
        : undefined
      });

    } catch (err) {

      logger.error("Inventory pipeline failed", err);

    } finally {

      this.inventoryRunning = false;

    }
  }
}

export const scheduler = new Scheduler();