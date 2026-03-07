// src/plugins/amm/index.ts
import os from "os";
import { getProvider } from "./providers";
import type { AgentContext } from "../../core/agent-context";

export async function collectAMM(ctx: AgentContext) {
  const provider = getProvider(os.platform());
  return provider.collect(ctx);
}