import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type { PmpNamespace } from "../../domain/pmp-types";
import { collectMacosPmp } from "./providers/macos";
import { collectWindowsPmp } from "./providers/windows";
import { collectLinuxPmp } from "./providers/linux";
import { refreshNudgesAfterScan } from "./os-update-nudge";

export async function collectPMP(ctx: AgentContext): Promise<PmpNamespace> {
  const platform = os.platform();

  if (platform === "win32") {
    return collectWindowsPmp(ctx);
  }

  if (platform === "darwin") {
    const ns = await collectMacosPmp(ctx);
    // Lo que el escaneo ya no lista está instalado: deja de pedírselo al
    // usuario. Aquí porque TODO escaneo de macOS pasa por este punto —el
    // programado y el del job—. Un fallo no puede tirar el escaneo.
    try {
      refreshNudgesAfterScan(ctx, ns);
    } catch (err) {
      ctx.logger?.warn?.("os-update nudge refresh failed", { err });
    }
    return ns;
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
