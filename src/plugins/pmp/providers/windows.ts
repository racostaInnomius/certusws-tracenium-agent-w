import os from "os";
import type { AgentContext } from "../../../core/agent-context";
import type { PmpNamespace, PmpScanItem, PmpSeverity } from "../../../domain/pmp-types";
import { loadPmpState } from "../state";
import { deriveScanNote } from "../scan-note";

// MSRC severity strings that come from `IUpdate.MsrcSeverity` (the
// canonical set Microsoft publishes for security updates). The wire
// value is a free-form string in WUA's COM API; we normalize to our
// PmpSeverity enum so the backend / UI never needs to care which
// platform reported it.
function normalizeMsrcSeverity(raw: unknown): PmpSeverity {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "critical") return "critical";
  if (s === "important") return "important";
  if (s === "moderate") return "moderate";
  if (s === "low") return "low";
  return "unknown";
}

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
    // PrivSvc reads `IUpdate.MsrcSeverity` and forwards it as a string
    // in the `msrcSeverity` field. Older PrivSvc builds may omit it —
    // fall through to `unknown` in that case so the schema stays
    // consistent across deployments mid-rollout.
    severity: normalizeMsrcSeverity(item?.msrcSeverity),
    installedBy: undefined,
    installedOn: undefined,
    source: "windows_update_agent"
  }));
}

/**
 * ¿Hay un reinicio pendiente DE VERDAD?
 *
 * ⚠️ Hasta 2026-09-17 esto era `remediation.rebootRequired`: la marca que dejó
 * la última instalación en pmp-state.json, que nada borraba al reiniciar. En
 * T111 cuatro servidores ya reiniciados (MSIG-DOMAIN01, MSIG-FILESHARE,
 * MSIG-TSPDC, MSIG-WSUS) salían «reboot pending»; Windows decía que no.
 *
 *   `live` (PrivSvc nuevo lee WUA + CBS + WU)  → manda
 *   sin `live` (PrivSvc anterior)              → la marca, salvo que la máquina
 *                                                arrancara después de instalar
 *
 * `remediation.rebootRequired` se sigue mandando tal cual: es el histórico de la
 * instalación, no el estado de la máquina.
 */
export function resolveWindowsRebootPending(input: {
  live: unknown;
  remediation: { rebootRequired?: boolean; finishedAtUtc?: string } | null | undefined;
  /** Hora del último arranque de la MÁQUINA (ms). */
  bootAtMs: number;
}): boolean {
  if (typeof input.live === "boolean") return input.live;
  if (input.remediation?.rebootRequired !== true) return false;
  const finishedMs = Date.parse(String(input.remediation.finishedAtUtc ?? ""));
  if (Number.isFinite(finishedMs) && Number.isFinite(input.bootAtMs) && input.bootAtMs > finishedMs) {
    return false;
  }
  return true;
}

function deriveOverallStatus(
  scanStatus: "healthy" | "updates_available" | "inventory_only" | "error",
  remediation: PmpNamespace["remediation"],
  rebootPending: boolean
): PmpNamespace["overall"]["status"] {
  if (remediation?.status === "in_progress") {
    return "installing";
  }

  if (rebootPending) {
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

export async function collectWindowsPmp(
  ctx: AgentContext,
  /** Uptime de la máquina en segundos. Inyectable en tests. */
  machineUptimeSeconds: () => number = () => os.uptime()
): Promise<PmpNamespace> {
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
    posture = await readSecurityCompliance(ctx);
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
        source: "windows_update_agent",
        mode: "inventory_only",
        installedPatchCount: 0,
        securityPatchCount: 0,
        items: [],
        // The reason belongs on the SCAN. It used to live only in
        // remediation.lastError, which reads as "the install failed" for
        // something that never got as far as scanning.
        note: message
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

  const livePending = typeof posture?.rebootPending === "boolean" ? posture.rebootPending : undefined;
  const rebootPending = resolveWindowsRebootPending({
    live: livePending,
    remediation,
    bootAtMs: Date.now() - machineUptimeSeconds() * 1000
  });
  const overallStatus = deriveOverallStatus(scanStatus, remediation, rebootPending);

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
      source: "windows_update_agent",
      mode: "inventory_only",
      // privsvc returns status:"unknown" + a `note` (stderr tail) when the
      // Windows Update scan produced no stdout at all — the usual signature of
      // a WUA/WSUS query that errored out. Dropping it turned a diagnosable
      // fault into "Inventory Only, 0 patches", which looks like a healthy
      // machine with nothing pending.
      note: deriveScanNote(posture),
      // Sólo cuando el PrivSvc lo leyó en vivo. Ausente = PrivSvc anterior: el
      // backend aplica entonces su propia regla del arranque posterior.
      ...(livePending !== undefined ? { rebootPending: livePending } : {}),
      installedPatchCount: Number(posture?.updateCount ?? scanItems.length),
      securityPatchCount: Number(posture?.securityUpdateCount ?? scanItems.length),
      items: scanItems
    },
    remediation
  };
}
