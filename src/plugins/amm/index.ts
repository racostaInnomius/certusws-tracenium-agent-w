// src/plugins/amm/index.ts
import os from "os";
import { getProvider } from "./providers";
import type { AgentContext } from "../../core/agent-context";
import type { AmmNamespace } from "../../domain/amm-types";

export async function collectAMM(ctx: AgentContext): Promise<AmmNamespace> {
  const platform = os.platform();
  const provider = getProvider(platform);

  const result = await provider.collect(ctx);

  // Defensa básica (evita romper scheduler si un provider falla silenciosamente)
  if (!result || typeof result !== "object") {
    throw new Error(`AMM provider returned invalid result for platform ${platform}`);
  }

  return result;
}