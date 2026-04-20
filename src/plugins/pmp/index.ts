import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type { PmpNamespace } from "../../domain/pmp-types";
import { collectWindowsPmp } from "./providers/windows";

export async function collectPMP(ctx: AgentContext): Promise<PmpNamespace> {
  const platform = os.platform();

  if (platform === "win32") {
    return collectWindowsPmp(ctx);
  }

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "pmp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    overall: {
      status: "error",
      score: 0
    },
    scan: {
      scannedAtUtc: new Date().toISOString(),
      source: "windows_security_compliance_inventory",
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
