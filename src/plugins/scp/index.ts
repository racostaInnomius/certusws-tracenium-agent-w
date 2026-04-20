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

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    overall: {
      status: "unknown",
      score: 0
    },
    checks: [
      {
        checkId: "scp.platform.unsupported",
        category: "collector",
        severity: "info",
        status: "unknown",
        title: `SCP collector is not implemented for platform ${platform}`,
        remediation: {
          type: "none",
          summary: "No remediation available until the platform collector is implemented."
        }
      }
    ]
  };
}
