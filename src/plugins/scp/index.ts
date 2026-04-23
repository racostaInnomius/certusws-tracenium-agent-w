// src/plugins/scp/index.ts
import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type { ScpNamespace } from "../../domain/scp-types";
import { collectMacosScp } from "./providers/macos";
import { collectWindowsScp } from "./providers/windows";

export async function collectSCP(ctx: AgentContext): Promise<ScpNamespace> {
  const platform = os.platform();

  if (platform === "win32") {
    return collectWindowsScp(ctx);
  }

  if (platform === "darwin") {
    return collectMacosScp(ctx);
  }

  // Schema 2.0 fallback for unsupported platforms. No synthetic findings:
  // the backend evaluator will produce not_applicable for every catalog
  // entry because none of the evidence paths exist.
  return {
    schemaVersion: "2.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    collectorError: {
      message: `SCP collector is not implemented for platform ${platform}`,
      phase: "platform_unsupported"
    }
  };
}
