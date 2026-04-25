import type { AgentContext } from "../../../core/agent-context";
import type { PmpNamespace, PmpScanItem } from "../../../domain/pmp-types";
import { loadPmpState } from "../state";

function normalizeArray(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return [value];
  return [];
}

async function readPatchScan(ctx: AgentContext): Promise<any> {
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
    hotFixId: item?.label ? String(item.label) : undefined,
    title: item?.title ? String(item.title) : undefined,
    // `softwareupdate --list` does not expose a severity field. We
    // emit "unknown" explicitly (rather than leaving it undefined) so
    // the cross-platform schema stays uniform — backend/UI can render
    // "Unknown severity" as a distinct bucket instead of treating
    // the absence as "no field shipped". Future enhancement: cross-
    // reference each label against an external CVE feed (NVD/MSRC)
    // to enrich macOS items with a real severity.
    severity: "unknown",
    installedBy: undefined,
    installedOn: undefined,
    source: "apple_software_update"
  }));
}

function deriveOverallStatus(
  scanStatus: "healthy" | "updates_available" | "inventory_only" | "error",
  remediation: PmpNamespace["remediation"]
): PmpNamespace["overall"]["status"] {
  if (remediation?.status === "in_progress") {
    return "installing";
  }

  if (remediation?.rebootRequired) {
    return "reboot_required";
  }

  return scanStatus;
}

function deriveOverallScore(status: PmpNamespace["overall"]["status"]): number {
  switch (status) {
    case "healthy":
      return 100;
    case "reboot_required":
      return 60;
    case "updates_available":
      return 40;
    case "inventory_only":
      return 20;
    case "installing":
      return 30;
    case "scan_pending":
    case "idle":
      return 10;
    case "error":
    default:
      return 0;
  }
}

export async function collectMacosPmp(ctx: AgentContext): Promise<PmpNamespace> {
  const remediationState = loadPmpState();
  const remediation: NonNullable<PmpNamespace["remediation"]> = {
    status: remediationState.status || "idle",
    mode: remediationState.mode,
    startedAtUtc: remediationState.startedAtUtc,
    finishedAtUtc: remediationState.finishedAtUtc,
    rebootRequired: remediationState.rebootRequired === true,
    installedCount: Number(remediationState.installedCount ?? 0),
    failedCount: Number(remediationState.failedCount ?? 0),
    selectedCount: Number(remediationState.selectedCount ?? 0),
    lastError: remediationState.lastError,
    results: remediationState.results || []
  };

  let posture: any = {};
  let scanItems: PmpScanItem[] = [];
  let scanStatus: "healthy" | "updates_available" | "inventory_only" | "error" = "inventory_only";

  try {
    posture = await readPatchScan(ctx);
    scanItems = normalizePatchItems(normalizeArray(posture?.items));
    scanStatus = posture?.status === "updates_available"
      ? "updates_available"
      : posture?.status === "healthy"
        ? "healthy"
        : "inventory_only";
  } catch (err: any) {
    const message = err?.message || String(err);
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
        source: "apple_software_update",
        mode: "inventory_only",
        installedPatchCount: 0,
        securityPatchCount: 0,
        items: []
      },
      remediation: remediation.status === "idle" && !(remediation.results || []).length
        ? {
            ...remediation,
            lastError: message,
            results: [
              {
                result: "failed",
                message
              }
            ]
          }
        : remediation
    };
  }

  const overallStatus = deriveOverallStatus(scanStatus, remediation);

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "pmp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    overall: {
      status: overallStatus,
      score: deriveOverallScore(overallStatus)
    },
    scan: {
      scannedAtUtc: posture?.scannedAtUtc ?? new Date().toISOString(),
      source: "apple_software_update",
      mode: "inventory_only",
      installedPatchCount: Number(posture?.updateCount ?? scanItems.length),
      securityPatchCount: Number(posture?.securityUpdateCount ?? scanItems.length),
      items: scanItems
    },
    remediation
  };
}
