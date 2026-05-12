// src/plugins/pmp/remediation.ts
//
// Patch Management v2 — non-patch remediation orchestrator. Lives
// inside the existing PMP plugin (no new plugin) and rides the
// same per-host concurrency lock as patch_install.
//
// Pipeline mirrors the SDP plugin's runSoftwareInstall (P1-D):
//   1. Validate envelope (remediationId, checkId, mode).
//   2. Whitelist gate — checkId must be in remediation-checks.ts +
//      applicable to this host's OS. Catalog entries we don't
//      recognise → outcome=rejected. Avoids any IPC round-trip.
//   3. Plugin policy gate — pluginEnabled("pmp") must be true.
//      Defense in depth (backend already gates).
//   4. Concurrency lock — tryStartRemediate(ctx). Mutual exclusion
//      with patch_install via the shared lock helpers in state.ts.
//      If denied → ackStatus 1 (transient retry).
//   5. priv.call("pmp.read_check_state", { checkId }) → state_before.
//   6. Branch on mode:
//        dry_run → diff state_before vs target → outcome
//                  dryrun_already_compliant | dryrun_would_apply.
//                  No write at all.
//        apply   → priv.call("pmp.remediate", { checkId, params })
//                  → captures exitCode + stderrExcerpt + duration +
//                    requiresReboot + changesApplied[].
//                  Then priv.call("pmp.read_check_state") again →
//                  state_after.
//                  Outcome:
//                    pre-state already compliant + no change needed
//                      → already_compliant
//                    apply ok + state_after compliant + reboot flag
//                      → applied_reboot_required
//                    apply ok + state_after compliant
//                      → applied
//                    apply ok but state_after still non-compliant
//                      → failed (silent fix-fail; common with GPO
//                                 reverting a setting back)
//                    apply error
//                      → failed | timed_out depending on err.code
//   7. ACK with structured message:
//        patch_remediate:<outcome>;remediationId=N
//          [;checkId=...][;exit=N][;duration=ms][;reason=short]
//
// Function is non-throwing — any internal exception maps to
// outcome=failed + ackStatus 1 with reason=exception:<msg>.

import os from "os";
import type { AgentContext } from "../../core/agent-context";
import {
  tryStartRemediate,
  finishRemediate,
} from "./state";
import { isCheckRemediableHere } from "./remediation-checks";

// Outcomes the agent can EMIT. The full DB enum (server-side)
// includes 'pending' / 'cancelled' / 'running' which are server-
// only state transitions; we never report them from here.
export type RemediationOutcome =
  | "applied"
  | "already_compliant"
  | "applied_reboot_required"
  | "dryrun_would_apply"
  | "dryrun_already_compliant"
  | "failed"
  | "rejected"
  | "timed_out";

export type RemediationAck = {
  ackStatus: 0 | 1 | 2;
  ackMessage: string;
  outcome: RemediationOutcome;
};

type Mode = "apply" | "dry_run";

// Subset of the catalog entry we receive from the backend snapshot.
// Mirrors `CheckSnapshot` in remediation-types.ts on the backend.
type CheckSnapshot = {
  checkId: string;
  title?: string;
  category?: string;
  platform?: string;
  severity?: string;
  remediationType?: string;
  remediationSummary?: string;
};

// Sanitize a free-form value before stuffing it into the ack
// message — we split on `;` and `=` server-side, so values must
// not carry those.
function sanitize(v: unknown, max = 200): string {
  return String(v ?? "")
    .replace(/[;\n=]/g, " ")
    .slice(0, max);
}

function encodeAckMessage(
  outcome: RemediationOutcome,
  remediationId: number,
  extras: Record<string, string | number | undefined> = {}
): string {
  const parts = [`patch_remediate:${outcome}`, `remediationId=${remediationId}`];
  for (const [k, v] of Object.entries(extras)) {
    if (v === undefined || v === null || v === "") continue;
    parts.push(`${k}=${sanitize(v)}`);
  }
  return parts.join(";");
}

/**
 * Entry point — called from grpc-stream.ts case "patch_remediate".
 * Always returns a RemediationAck (non-throwing).
 */
export async function runRemediation(
  ctx: AgentContext,
  jobId: string,
  payload: any
): Promise<RemediationAck> {
  const remediationId = Number(payload?.remediationId);
  const checkId = String(payload?.checkId || "").trim();
  const mode = String(payload?.mode || "") as Mode;
  const snapshot = payload?.checkSnapshot as CheckSnapshot | undefined;

  // ── Validate envelope ─────────────────────────────────────────
  if (!Number.isInteger(remediationId) || remediationId <= 0 || !checkId) {
    return reject(0, "invalid_payload");
  }
  if (mode !== "apply" && mode !== "dry_run") {
    return reject(remediationId, "invalid_mode");
  }

  // ── Whitelist gate (agent-side) ───────────────────────────────
  const decision = isCheckRemediableHere(checkId);
  if (!decision.allowed) {
    return reject(remediationId, decision.reason, { checkId });
  }

  // ── Plugin-policy gate ────────────────────────────────────────
  // Defense in depth — the backend already gates on tenant policy
  // before dispatching. If a policy update lands AFTER the job was
  // queued, the agent enforces the freshest state.
  if (typeof ctx.policyRuntime?.pluginEnabled === "function"
      && ctx.policyRuntime.pluginEnabled("pmp") === false) {
    return reject(remediationId, "pmp_plugin_disabled_by_policy", { checkId });
  }

  // ── Platform sanity (defense alongside whitelist) ─────────────
  // The whitelist already checks OS applicability, but a platform
  // mismatch on the snapshot is a separate signal worth surfacing.
  if (snapshot?.platform && !snapshotMatchesLocal(snapshot.platform)) {
    return reject(remediationId, "platform_mismatch", { checkId });
  }

  // ── Concurrency lock ──────────────────────────────────────────
  // Mutual exclusion with patch_install via the lock helpers in
  // state.ts (which check ctx._patchInstallInProgress). Ack 1 →
  // orchestrator retries with backoff.
  const acquired = tryStartRemediate(ctx);
  if (!acquired) {
    return {
      ackStatus: 1,
      ackMessage: encodeAckMessage("failed", remediationId, {
        checkId,
        reason: "another_pmp_action_in_progress",
      }),
      outcome: "failed",
    };
  }

  let outcome: RemediationOutcome = "failed";
  let exitCode: number | undefined;
  let durationMs: number | undefined;
  let extraReason: string | undefined;

  try {
    // ── Read pre-state ─────────────────────────────────────────
    const preStart = Date.now();
    const preResp = await ctx.priv.call({
      v: 1,
      id: `pmp-read-${jobId}-${Date.now()}`,
      method: "pmp.read_check_state",
      params: { checkId },
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    });

    if (!preResp?.ok) {
      const code = (preResp as any)?.error?.code || "read_state_failed";
      outcome = code === "unsupported_check" ? "rejected" : "failed";
      extraReason = code;
      return ackFor(outcome, remediationId, {
        checkId,
        duration: Date.now() - preStart,
        reason: extraReason,
      });
    }

    const preResult = preResp.result || {};
    const preCompliant = preResult.isCompliant === true;

    // ── Dry-run branch ────────────────────────────────────────
    if (mode === "dry_run") {
      outcome = preCompliant ? "dryrun_already_compliant" : "dryrun_would_apply";
      durationMs = Date.now() - preStart;
      return ackFor(outcome, remediationId, {
        checkId,
        duration: durationMs,
      });
    }

    // ── Apply branch ──────────────────────────────────────────
    if (preCompliant) {
      // Already compliant — no write needed. Saves the registry-
      // edit round-trip + any reboot flag noise.
      outcome = "already_compliant";
      durationMs = Date.now() - preStart;
      return ackFor(outcome, remediationId, {
        checkId,
        duration: durationMs,
        reason: "pre_state_compliant",
      });
    }

    const applyStart = Date.now();
    const applyResp = await ctx.priv.call({
      v: 1,
      id: `pmp-remediate-${jobId}-${Date.now()}`,
      method: "pmp.remediate",
      params: {
        checkId,
        // Pass through any catalog-supplied params (Phase 1 has
        // none; Phase 2 might use them for things like "set min
        // password length to N"). Privsvc still ignores anything
        // not on its hardcoded handler signature.
        params: payload?.params ?? {},
        // Privsvc-side timeout: leave 60s headroom under the
        // orchestrator job timeout (default 600s for remediate).
        timeoutSeconds: 540,
      },
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    });

    if (!applyResp?.ok) {
      const code = (applyResp as any)?.error?.code || "remediate_failed";
      outcome = code === "remediate_timeout" ? "timed_out" : "failed";
      extraReason = code;
      return ackFor(outcome, remediationId, {
        checkId,
        duration: Date.now() - applyStart,
        reason: extraReason,
      });
    }

    const applyResult = applyResp.result || {};
    exitCode = Number(applyResult.exitCode);
    durationMs = Number(applyResult.durationMs ?? Date.now() - applyStart);
    const requiresReboot = applyResult.requiresReboot === true;

    // ── Verify with post-state read ───────────────────────────
    const postResp = await ctx.priv.call({
      v: 1,
      id: `pmp-read-${jobId}-${Date.now()}`,
      method: "pmp.read_check_state",
      params: { checkId },
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    });

    let postCompliant = false;
    if (postResp?.ok) {
      postCompliant = (postResp.result || {}).isCompliant === true;
    }

    if (!postCompliant && !requiresReboot) {
      // Fix exited 0, but the system says we're still non-
      // compliant. Common cause: GPO reverted the change between
      // our write and our re-read; or a setting is owned by
      // another process. Operator-visible failure.
      outcome = "failed";
      extraReason = "post_state_mismatch";
      return ackFor(outcome, remediationId, {
        checkId,
        exit: exitCode,
        duration: durationMs,
        reason: extraReason,
      });
    }

    outcome = requiresReboot ? "applied_reboot_required" : "applied";
    return ackFor(outcome, remediationId, {
      checkId,
      exit: exitCode,
      duration: durationMs,
    });
  } catch (err: any) {
    outcome = "failed";
    extraReason = `exception:${(err?.message || "unknown").slice(0, 120)}`;
    ctx.logger?.error?.("[pmp.remediate] unhandled exception", {
      jobId,
      checkId,
      error: err?.message || String(err),
    });
    return {
      ackStatus: 1, // transient — orchestrator may retry
      ackMessage: encodeAckMessage(outcome, remediationId, {
        checkId,
        reason: extraReason,
      }),
      outcome,
    };
  } finally {
    finishRemediate();
  }
}

// ── Helpers ───────────────────────────────────────────────────────

function snapshotMatchesLocal(snapshotPlatform: string): boolean {
  const p = os.platform();
  if (snapshotPlatform === "cross") return true;
  if (snapshotPlatform === "windows") return p === "win32";
  if (snapshotPlatform === "macos") return p === "darwin";
  if (snapshotPlatform === "linux") return p === "linux";
  return false;
}

function reject(
  remediationId: number,
  reason: string,
  extras: Record<string, string | number | undefined> = {}
): RemediationAck {
  return {
    ackStatus: 2,
    ackMessage: encodeAckMessage("rejected", remediationId, {
      ...extras,
      reason,
    }),
    outcome: "rejected",
  };
}

function ackFor(
  outcome: RemediationOutcome,
  remediationId: number,
  extras: Record<string, string | number | undefined>
): RemediationAck {
  // ackStatus mapping mirrors SDP:
  //   0 → success-shaped outcomes (applied / already_compliant /
  //       applied_reboot_required / dryrun_*).
  //   1 → transient (timed_out, exceptions handled in caller).
  //   2 → permanent (failed with post_state_mismatch, rejected).
  let ackStatus: 0 | 1 | 2 = 2;
  if (
    outcome === "applied" ||
    outcome === "already_compliant" ||
    outcome === "applied_reboot_required" ||
    outcome === "dryrun_would_apply" ||
    outcome === "dryrun_already_compliant"
  ) {
    ackStatus = 0;
  } else if (outcome === "timed_out") {
    ackStatus = 1;
  } else {
    ackStatus = 2;
  }
  return {
    ackStatus,
    ackMessage: encodeAckMessage(outcome, remediationId, extras),
    outcome,
  };
}
