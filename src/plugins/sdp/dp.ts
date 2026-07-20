// src/plugins/sdp/dp.ts
//
// Distribution Phase B — the agent-side handler for a SOFTWARE_DP_PREFETCH
// job. This agent has been designated a distribution point for its site: warm
// the LAN cache with the package (via the normal cdn → origin tiers) so the
// site's held install jobs can be released with this DP as their first source.
//
// Thin by design: validation + one privsvc call (sdp.dp.prefetch does the
// download, hash gate, cache write, LRU eviction, and lazily starts the mTLS
// blob server). Ack mapping:
//   ackStatus 0 — cache is warm + server up → backend releases the site.
//   ackStatus 1 — transient (download failed) → orchestrator retries; the
//                 backend's prefetch deadline fail-opens regardless.
//   ackStatus 2 — permanent (bad payload / identity unavailable).

import type { AgentContext } from "../../core/agent-context";
import { normalizeSources } from "./index";

export type DpPrefetchAck = {
  ackStatus: 0 | 1 | 2;
  ackMessage: string;
};

function msg(outcome: "success" | "failed", deploymentId: number, extras: Record<string, string | number | undefined> = {}): string {
  const parts = [`software_dp_prefetch:${outcome}`, `deploymentId=${deploymentId}`];
  for (const [k, v] of Object.entries(extras)) {
    if (v === undefined) continue;
    parts.push(`${k}=${String(v).replace(/[;\n]/g, " ").slice(0, 120)}`);
  }
  return parts.join(";");
}

export async function runDpPrefetch(
  ctx: AgentContext,
  jobId: string,
  payload: any
): Promise<DpPrefetchAck> {
  const deploymentId = Number(payload?.deploymentId) || 0;
  const sha256 = String(payload?.sha256 || "").toLowerCase();
  const sources = normalizeSources(payload?.sources);

  if (!/^[0-9a-f]{64}$/.test(sha256) || sources.length === 0) {
    return {
      ackStatus: 2,
      ackMessage: msg("failed", deploymentId, { reason: "invalid_payload" }),
    };
  }

  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `sdp-dp-prefetch-${jobId}-${Date.now()}`,
      method: "sdp.dp.prefetch",
      params: {
        sha256,
        sources,
        sizeBytes: payload?.sizeBytes ?? undefined,
        // Leave headroom under the 900s job timeout so we ack the failure
        // ourselves instead of letting the orchestrator time the job out.
        timeoutSeconds: 840,
        ...(Number(payload?.bandwidthLimitKbps) > 0
          ? { rateLimitKbps: Number(payload.bandwidthLimitKbps) }
          : {}),
      },
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    });

    if (resp?.ok && resp.result?.ready === true) {
      return {
        ackStatus: 0,
        ackMessage: msg("success", deploymentId, {
          cached: resp.result?.cached ? 1 : 0,
          src: typeof resp.result?.servedFrom === "string" ? resp.result.servedFrom : undefined,
        }),
      };
    }

    // Cache may be warm but the server couldn't start (missing identity,
    // port busy) — that's not retryable by downloading again: permanent so
    // the backend fail-opens immediately instead of waiting the deadline.
    if (resp?.ok) {
      return {
        ackStatus: 2,
        ackMessage: msg("failed", deploymentId, {
          reason: String(resp.result?.serverReason || "dp_server_not_running"),
        }),
      };
    }

    const code = String((resp as any)?.error?.code || "prefetch_failed");
    return {
      ackStatus: code === "download_failed" ? 1 : 2,
      ackMessage: msg("failed", deploymentId, { reason: code }),
    };
  } catch (err: any) {
    ctx.logger?.error?.("[sdp.dp] prefetch threw", { jobId, error: err?.message || String(err) });
    return {
      ackStatus: 1,
      ackMessage: msg("failed", deploymentId, { reason: "exception" }),
    };
  }
}
