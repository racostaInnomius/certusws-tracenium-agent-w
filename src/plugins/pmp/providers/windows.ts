import type { AgentContext } from "../../../core/agent-context";
import type { PmpNamespace, PmpScanItem } from "../../../domain/pmp-types";

function normalizeArray(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return [value];
  return [];
}

async function readSecurityCompliance(ctx: AgentContext): Promise<any> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `pmp_${Date.now()}`,
    method: "patch.scan",
    params: {},
    meta: {
      tenantId: ctx.enrollment.tenantId,
      deviceId: ctx.enrollment.deviceId
    }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "patch.scan failed");
  }

  return resp.result || {};
}

function normalizePatchItems(items: any[]): PmpScanItem[] {
  return items.map((item) => ({
    hotFixId: Array.isArray(item?.kbArticleIds) && item.kbArticleIds.length > 0
      ? String(item.kbArticleIds[0])
      : undefined,
    title: item?.title ? String(item.title) : undefined,
    installedBy: undefined,
    installedOn: undefined,
    source: "windows_update_agent"
  }));
}

export async function collectWindowsPmp(ctx: AgentContext): Promise<PmpNamespace> {
  let posture: any = {};
  let scanItems: PmpScanItem[] = [];
  let overallStatus: PmpNamespace["overall"]["status"] = "inventory_only";

  try {
    posture = await readSecurityCompliance(ctx);
    scanItems = normalizePatchItems(normalizeArray(posture?.items));
    overallStatus = posture?.status === "updates_available"
      ? "updates_available"
      : posture?.status === "healthy"
        ? "healthy"
        : "inventory_only";
  } catch (err: any) {
    overallStatus = "error";
    return {
      schemaVersion: "1.0",
      collector: {
        plugin: "pmp",
        version: ctx.config.agentVersion
      },
      hasChanges: true,
      overall: {
        status: overallStatus,
        score: 0
      },
      scan: {
        scannedAtUtc: new Date().toISOString(),
        source: "windows_update_agent",
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
        results: [
          {
            result: "failed",
            message: err?.message || String(err)
          }
        ]
      }
    };
  }

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "pmp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    overall: {
      status: overallStatus,
      score: scanItems.length > 0 ? 100 : 0
    },
    scan: {
      scannedAtUtc: posture?.scannedAtUtc ?? new Date().toISOString(),
      source: "windows_update_agent",
      mode: "inventory_only",
      installedPatchCount: Number(posture?.updateCount ?? scanItems.length),
      securityPatchCount: Number(posture?.securityUpdateCount ?? scanItems.length),
      items: scanItems
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
