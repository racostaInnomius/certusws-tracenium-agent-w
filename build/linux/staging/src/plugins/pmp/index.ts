import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type { PmpNamespace } from "../../domain/pmp-types";
import { collectMacosPmp } from "./providers/macos";
import { collectWindowsPmp } from "./providers/windows";
import { collectLinuxPmp } from "./providers/linux";

export async function collectPMP(ctx: AgentContext): Promise<PmpNamespace> {
  const platform = os.platform();

  if (platform === "win32") {
    return collectWindowsPmp(ctx);
  }

  if (platform === "darwin") {
    return collectMacosPmp(ctx);
  }

  if (platform === "linux") {
    return collectLinuxPmp(ctx);
  }

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "pmp",
      version: ctx.config.agentVersion
    },
    hasChanges: false,
    overall: {
      status: "error",
      score: 0
    },
    scan: {
      scannedAtUtc: new Date().toISOString(),
      source: "patch_management_unavailable",
      mode: "inventory_only",
      installedPatchCount: 0,
      securityPatchCount: 0,
      items: []
    },
    remediation: {
      status: "idle",
      rebootRequired: false,
      installedCount: 0,
      failedCount: 0,
      results: []
    }
  };
}
