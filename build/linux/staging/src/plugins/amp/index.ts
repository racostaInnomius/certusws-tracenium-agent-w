// src/plugins/amp/index.ts
import os from "os";
import { getProvider } from "./providers";
import type { AgentContext } from "../../core/agent-context";
import type { AmpNamespace } from "../../domain/amp-types";

export async function collectAMP(ctx: AgentContext): Promise<AmpNamespace> {
  const platform = os.platform();
  const provider = getProvider(platform);

  const result = await provider.collect(ctx);

  // Defensa básica (evita romper scheduler si un provider falla silenciosamente)
  if (!result || typeof result !== "object") {
    throw new Error(`AMP provider returned invalid result for platform ${platform}`);
  }

  return result;
}