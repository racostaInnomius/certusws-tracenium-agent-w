// privsvc/macos/src/pmp-remediation.ts
//
// Patch Management v2 — privsvc handlers for non-patch remediation
// on macOS. Phase 1 ships ZERO Windows-checkIds-applicable handlers
// (the 4 P1 checkIds — TLS, ciphers, SMBv1, firewall profiles —
// are all `windows.*`); this file is the macOS counterpart that
// returns `unsupported_check` for everything until Phase 2 lights
// up the macOS coverage (FileVault, gatekeeper, screen lock, SIP).
//
// We DO ship the file + router cases now so:
//   1. The IPC contract works on macOS hosts (no `not_supported`
//      router miss that the agent's privsvc-IPC client would treat
//      as a privsvc bug rather than a Phase 1 limitation).
//   2. Phase 2 has a clear seam to land per-checkId handlers
//      without touching the agent or backend.
//
// HANDLERS map keyed on checkId — same shape as the Windows-side
// dict — empty in Phase 1. Adding a Phase 2 handler is one entry +
// one function below.

import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

// Phase 1 — empty. Each Phase 2 entry will follow the
// shape: `(params) => Promise<RemediateResult>`.
type ReadCheckHandler = (params: any) => Promise<{
  state: any;
  isCompliant: boolean;
}>;

type RemediateHandler = (params: any) => Promise<{
  exitCode: number;
  stderrExcerpt?: string;
  durationMs: number;
  requiresReboot?: boolean;
  changesApplied?: string[];
}>;

const READ_HANDLERS: Record<string, ReadCheckHandler> = {
  // Phase 2 entries land here.
};

const REMEDIATE_HANDLERS: Record<string, RemediateHandler> = {
  // Phase 2 entries land here.
};

// ── pmp.read_check_state ─────────────────────────────────────────

export async function handlePmpReadCheckState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) {
    return fail(req.id, "bad_request", "checkId required");
  }

  const handler = READ_HANDLERS[checkId];
  if (!handler) {
    // The agent layer also whitelists per-OS via remediation-checks.ts
    // — this path only executes when something slipped past it
    // (e.g. backend dispatched a Windows checkId to a Mac due to
    // bad targeting). Surface the precise reason so the agent can
    // ack `outcome=rejected` with `reason=unsupported_check`.
    logger.info("pmp_read_check_state_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no read handler for checkId ${checkId} on macOS`);
  }

  try {
    const result = await handler(req.params || {});
    return success(req.id, {
      state: result.state,
      isCompliant: result.isCompliant === true,
      supported: true,
    });
  } catch (err: any) {
    logger.error("pmp_read_check_state_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "read_state_failed", err?.message || String(err));
  }
}

// ── pmp.remediate ────────────────────────────────────────────────

export async function handlePmpRemediate(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) {
    return fail(req.id, "bad_request", "checkId required");
  }

  const handler = REMEDIATE_HANDLERS[checkId];
  if (!handler) {
    logger.info("pmp_remediate_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no remediation handler for checkId ${checkId} on macOS`);
  }

  try {
    const result = await handler(req.params || {});
    return success(req.id, {
      exitCode: result.exitCode,
      stderrExcerpt: result.stderrExcerpt ?? null,
      durationMs: result.durationMs,
      requiresReboot: result.requiresReboot === true,
      changesApplied: Array.isArray(result.changesApplied) ? result.changesApplied : [],
    });
  } catch (err: any) {
    if (err?.code === "remediate_timeout") {
      return fail(req.id, "remediate_timeout", err?.message || "remediate timed out");
    }
    logger.error("pmp_remediate_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "remediate_failed", err?.message || String(err));
  }
}
