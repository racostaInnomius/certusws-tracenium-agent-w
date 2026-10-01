import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type { PmpNamespace } from "../../domain/pmp-types";
import { collectMacosPmp } from "./providers/macos";
import { collectWindowsPmp } from "./providers/windows";
import { collectLinuxPmp } from "./providers/linux";
import { refreshOsUpdateActionsAfterScan } from "./os-update-action";
import { trayPatchFromScan } from "../../status/tray-patch";

/**
 * Todo escaneo de parches —el programado y el de un job, en los tres
 * sistemas— pasa por aquí: la bandeja dice lo que vio ESTE escaneo, no el
 * resultado de la última instalación congelado al arrancar (1-oct). Un fallo
 * al escribirlo no puede tirar el escaneo.
 */
export async function collectPMP(ctx: AgentContext): Promise<PmpNamespace> {
  const ns = await collectForPlatform(ctx);
  try {
    ctx.trayStatus?.setPatch(trayPatchFromScan(ns));
  } catch (err) {
    ctx.logger?.warn?.("tray patch status update failed", { err });
  }
  return ns;
}

async function collectForPlatform(ctx: AgentContext): Promise<PmpNamespace> {
  const platform = os.platform();

  if (platform === "win32") {
    return collectWindowsPmp(ctx);
  }

  if (platform === "darwin") {
    const ns = await collectMacosPmp(ctx);
    // Lo que el escaneo ya no lista está instalado: la acción `os.update`
    // se cierra (ADR-0036 D1, «hecho» = observado). Aquí porque TODO escaneo
    // de macOS pasa por este punto —el programado y el del job—. Un fallo no
    // puede tirar el escaneo.
    try {
      refreshOsUpdateActionsAfterScan(ctx, ns);
    } catch (err) {
      ctx.logger?.warn?.("os.update user action refresh failed", { err });
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
