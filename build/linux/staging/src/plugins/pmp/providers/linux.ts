// src/plugins/pmp/providers/linux.ts
//
// PMP namespace producer for Linux. Phase 6 ships scan only — patch
// install (and remediation) wires in Phase 7 with the same shape
// macOS uses (loadPmpState() into the `remediation` block below).
//
// Mirrors src/plugins/pmp/providers/macos.ts almost line-for-line.
// The differences are:
//   * `source: "linux_apt" | "linux_dnf" | "linux_zypper"` from the
//     privsvc result instead of hardcoded "apple_software_update".
//   * Item normalization preserves Linux-specific fields (`type`,
//     `cveIds`, `rebootRequired`) that the privsvc emits per family.
//   * No CVE cross-reference fallback — the privsvc handler already
//     extracts CVEs where they're available (RHEL via `dnf updateinfo`).
//     macOS punted on severity entirely; we have at least pocket-
//     based + advisory-based severity here.

import type { AgentContext } from "../../../core/agent-context";
import type { PmpNamespace, PmpScanItem, PmpSeverity } from "../../../domain/pmp-types";
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
      deviceId: ctx.enrollment.deviceId,
    },
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "patch.scan failed");
  }

  return resp.result || {};
}

function asSeverity(value: unknown): PmpSeverity {
  const v = String(value || "").toLowerCase();
  if (v === "critical" || v === "important" || v === "moderate" || v === "low") return v;
  return "unknown";
}

function asType(value: unknown): PmpScanItem["type"] {
  const v = String(value || "").toLowerCase();
  if (v === "security" || v === "bugfix" || v === "enhancement" || v === "update") return v;
  return undefined;
}

function normalizePatchItems(items: any[]): PmpScanItem[] {
  return items.map((item) => ({
    hotFixId: item?.hotFixId ? String(item.hotFixId) : undefined,
    title: item?.title ? String(item.title) : undefined,
    severity: asSeverity(item?.severity),
    type: asType(item?.type),
    cveIds: Array.isArray(item?.cveIds) ? item.cveIds.map(String) : undefined,
    rebootRequired: item?.rebootRequired === true ? true : undefined,
    installedBy: undefined,
    installedOn: undefined,
    source: item?.source ? String(item.source) : undefined,
  }));
}

// Maps the privsvc's `source` enum back to the PmpNamespace.scan.source
// type literal. Defensive against future privsvc strings — anything we
// don't recognize collapses to `patch_management_unavailable`, which
// is the right "graceful degrade" value (the catalog evaluator marks
// the items as not_applicable rather than inventing pass/fail).
function asScanSource(value: unknown): NonNullable<PmpNamespace["scan"]>["source"] {
  switch (String(value || "")) {
    case "linux_apt":
      return "linux_apt";
    case "linux_dnf":
      return "linux_dnf";
    case "linux_zypper":
      return "linux_zypper";
    default:
      return "patch_management_unavailable";
  }
}

function deriveOverallStatus(
  scanStatus: "healthy" | "updates_available" | "inventory_only" | "error",
  remediation: PmpNamespace["remediation"]
): PmpNamespace["overall"]["status"] {
  if (remediation?.status === "in_progress") return "installing";
  if (remediation?.rebootRequired) return "reboot_required";
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

export async function collectLinuxPmp(ctx: AgentContext): Promise<PmpNamespace> {
  // Same remediation-state path macOS uses. Phase 7 will populate
  // the state via `patch.install` ack handling; today on Linux this
  // returns the default idle shape until Phase 7 lands.
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
    results: remediationState.results || [],
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
        version: ctx.config.agentVersion,
      },
      hasChanges: true,
      overall: {
        status: "error",
        score: 0,
      },
      scan: {
        scannedAtUtc: new Date().toISOString(),
        source: "patch_management_unavailable",
        mode: "inventory_only",
        installedPatchCount: 0,
        securityPatchCount: 0,
        items: [],
      },
      remediation: remediation.status === "idle" && !(remediation.results || []).length
        ? {
            ...remediation,
            lastError: message,
            results: [{ result: "failed", message }],
          }
        : remediation,
    };
  }

  const overallStatus = deriveOverallStatus(scanStatus, remediation);

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "pmp",
      version: ctx.config.agentVersion,
    },
    hasChanges: true,
    overall: {
      status: overallStatus,
      score: deriveOverallScore(overallStatus),
    },
    scan: {
      scannedAtUtc: posture?.scannedAtUtc ?? new Date().toISOString(),
      source: asScanSource(posture?.source),
      mode: "inventory_only",
      installedPatchCount: Number(posture?.updateCount ?? scanItems.length),
      securityPatchCount: Number(posture?.securityUpdateCount ?? 0),
      items: scanItems,
    },
    remediation,
  };
}
