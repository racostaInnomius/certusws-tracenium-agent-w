// src/core/service.ts
import { collectAMM } from "../plugins/amm";
import { outbox } from "../queue/outbox";
import { logger } from "../bootstrap/logger";
import { buildDeviceFacts } from "../domain/device-facts-builder";

import type { AgentContext } from "./agent-context";

class Scheduler {
  async start(ctx: AgentContext) {
    // Ejecutar inmediatamente
    await this.collectInventory(ctx);

    // Luego cada 6 horas
    setInterval(() => {
      this.collectInventory(ctx).catch(err =>
        logger.error("Inventory error:", err)
      );
    }, 6 * 60 * 60 * 1000);
  }

  private async collectInventory(ctx: AgentContext) {
    logger.info("Collecting AMM facts...");

    const ammNamespace = await collectAMM(ctx);
    const facts = await buildDeviceFacts(ctx, { amm: ammNamespace });

    outbox.enqueue({
        type: "FACTS_SNAPSHOT",
        payload: facts
    });

    logger.info("FACTS_SNAPSHOT enqueued.");
    logger.info(`FACTS_SNAPSHOT enqueued. AMM count=${ammNamespace.softwareInventory?.count}`);
  }
}

export const scheduler = new Scheduler();