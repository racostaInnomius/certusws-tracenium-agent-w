// src/security/enforcer.ts
//
// Reads the active security policy (the `security.*` block, Policy
// v2 Sprint 2) and, for each capability the operator has flagged as
// `mode === "auto"`, asks privsvc to read the current state and, on
// drift, to remediate.
//
// Design choices:
//
//   * The enforcer DELEGATES every state-changing call to the
//     existing `pmp.remediate` IPC method. We deliberately do NOT
//     invent new privsvc handlers in Sprint 2 — every capability
//     we treat as "functional" here MUST map to a checkId that
//     `pmp-remediation.ts` (Linux + Windows) already implements.
//     The mapping table is `SECURITY_CAPABILITY_REMEDIATORS` below.
//
//   * The enforcer COEXISTS with the existing Job-driven
//     `PATCH_REMEDIATE` flow by acquiring the same in-process lock
//     (`tryStartRemediate` from src/plugins/pmp/state.ts). Either
//     path grabs the lock first; the other becomes a no-op for that
//     pass. No state-changing call is ever made without the lock.
//
//   * Per-checkId cooldown: once we successfully run a remediation
//     for a checkId, we don't retry for COOLDOWN_MS even if the
//     post-state read still shows drift (could be a host that
//     genuinely needs a reboot — see e.g. Windows TLS legacy
//     disable, which writes registry but takes effect only after
//     LSA reload). The cooldown is in-memory; agent restart clears
//     it, which is the right behaviour because a fresh process has
//     a fresh view of state.
//
//   * Default mode is `report-only`. The enforcer NEVER modifies
//     the system unless the operator explicitly opts in by setting
//     mode=auto. Read-state runs unconditionally for any capability
//     that has a desired value set, so the dashboard always shows
//     drift even when remediation is paused.
//
//   * Capabilities WITHOUT a remediator entry in the table
//     (`passwordPolicy`, `bitlocker`, `usb`, `shares`) are treated
//     as policy-stored placeholders: the enforcer logs at debug
//     level and skips. The UI surfaces these as "coming soon" so
//     operators understand the policy field is persisted but no
//     enforcement is happening yet.
//
//   * OS gating: each remediator entry declares which `os.platform()`
//     it supports. A Linux-only checkId on a Windows host is a
//     silent skip (the SCP collector on Windows doesn't even emit
//     the corresponding `ssh.*` evidence, so the dashboard already
//     reflects "not applicable").

import os from "os";
import type { AgentContext } from "../core/agent-context";
import type { SecurityPolicy, SecurityMode } from "../core/policy-runtime";
import { tryStartRemediate, finishRemediate } from "../plugins/pmp/state";
import { outbox } from "../queue/sqlite-outbox";
import { buildDeviceFacts } from "../domain/device-facts-builder";

// How long to wait between successful remediation attempts for the
// SAME checkId. Prevents the case where a remediation that requires
// reboot writes the registry but stays non-compliant on the next
// read — without the cooldown the enforcer would keep re-writing
// the same value on every pass. 1 hour is a reasonable balance:
// long enough that a real reboot-pending state isn't hammered,
// short enough that operator action (e.g. flipping a setting back
// via GPO) gets caught.
const COOLDOWN_MS = 60 * 60 * 1000;

// Maximum wall-clock time we let the entire enforce pass take. Beyond
// this we bail — usually means a privsvc handler is hung. Defense in
// depth with the per-call timeoutSeconds.
const ENFORCE_PASS_TIMEOUT_MS = 5 * 60 * 1000;

// In-memory cooldown registry. checkId → last-applied wall clock.
// Survives across enforce passes within one agent process; cleared
// on restart.
const lastAppliedAt = new Map<string, number>();

// In-memory "last emitted audit outcome" per checkId. Used to
// suppress repeated audit events for the SAME outcome on consecutive
// enforce passes — e.g. a report-only host that's been in drift for
// 3 days shouldn't generate 9 identical "drift_report_only" events,
// one per compliance tick. We only emit when the outcome CHANGES.
//
// Trade-off vs persistent storage (sqlite agent_state): an agent
// restart will re-emit the current outcome once, which is fine —
// duplication on restart is preferable to dropping a real event
// because we crashed mid-emission.
const lastEmittedOutcome = new Map<string, EnforceOutcome>();

// Outcomes that DO produce an audit event. Everything else is
// noise (compliance ticks where nothing happened, OS mismatches,
// cooldowns) and stays inside the agent log.
const AUDITABLE_OUTCOMES = new Set<EnforceOutcome>([
  "drift_report_only",
  "drift_remediated",
  "drift_remediation_rebooting",
  "drift_remediation_failed",
  "skipped_unenforceable_desired",
  "error",
]);

// Audit-event types written to the backend `security_events` table.
// One-to-one mapping with the auditable enforcer outcomes — keeps
// the event_type column legible as a single-source-of-truth filter
// for the alerts feed without forcing the consumer to also know
// the outcome string.
const AUDIT_EVENT_TYPES: Record<EnforceOutcome, string | null> = {
  // Auditable
  drift_report_only:              "SECURITY_DRIFT_DETECTED",
  drift_remediated:               "SECURITY_DRIFT_REMEDIATED",
  drift_remediation_rebooting:    "SECURITY_DRIFT_REMEDIATION_REBOOTING",
  drift_remediation_failed:       "SECURITY_DRIFT_REMEDIATION_FAILED",
  skipped_unenforceable_desired:  "SECURITY_POLICY_UNENFORCEABLE",
  error:                          "SECURITY_ENFORCE_ERROR",
  // Non-auditable
  compliant:                      null,
  skipped_off:                    null,
  skipped_no_value:               null,
  skipped_wrong_os:               null,
  skipped_cooldown:               null,
  skipped_locked:                 null,
  skipped_no_remediator:          null,
};

// Mapping table from security policy fields → existing privsvc
// checkIds. The shape captures:
//   * `desiredEqual`: function that returns TRUE when the value the
//     operator set in the policy matches what the remediator
//     ENFORCES. Used because the remediator's "compliant" outcome is
//     fixed (e.g. `linux.ssh.root_login_disabled` always enforces
//     `PermitRootLogin no`), so if the operator set
//     `permitRootLogin: "yes"` we must NOT run that remediator — it
//     would impose the WRONG state.
//   * `oses`: which platforms the remediator works on.
//   * `policyHasValue`: does the policy actually carry a desired
//     state for this capability? Used to skip when the operator
//     hasn't set the field at all (mode might be auto but with no
//     value → no opinion → skip).
//
// Each entry corresponds to ONE checkId. Capabilities that expose
// multiple controls (e.g. `ssh` has permitRootLogin + passwordAuth
// + weakKex) appear as multiple entries.

type CapabilityKey =
  | "firewall"
  | "ssh"
  | "tls"
  | "smb";

type Platform = "linux" | "win32" | "darwin";

type RemediatorEntry = {
  capability: CapabilityKey;
  // Sub-field of the capability this entry targets. Lets us scope
  // the policyHasValue / desiredEqual checks tightly.
  subfield: string;
  checkId: string;
  oses: Platform[];
  policyHasValue: (cap: any) => boolean;
  // Returns true when the desired-state the operator authored is
  // the SAME state this remediator imposes. False means "operator
  // wants the opposite of what the remediator does" — we must skip
  // (and emit a warning, since the policy is unenforceable as
  // written).
  desiredEqual: (cap: any) => boolean;
};

const SECURITY_CAPABILITY_REMEDIATORS: RemediatorEntry[] = [
  // ── Firewall ──────────────────────────────────────────────────
  {
    capability: "firewall",
    subfield: "required",
    checkId: "linux.firewall.enabled",
    oses: ["linux"],
    policyHasValue: (cap) => typeof cap?.required === "boolean",
    desiredEqual: (cap) => cap?.required === true,
  },
  {
    capability: "firewall",
    subfield: "required",
    checkId: "windows.firewall.profiles_enabled",
    oses: ["win32"],
    policyHasValue: (cap) => typeof cap?.required === "boolean",
    desiredEqual: (cap) => cap?.required === true,
  },
  {
    // macOS handler lives in privsvc/macos/src/pmp-remediation.ts
    // (`macos.firewall.enabled`) — read state via socketfilterfw,
    // remediate via `socketfilterfw --setglobalstate on`. No reboot.
    capability: "firewall",
    subfield: "required",
    checkId: "macos.firewall.enabled",
    oses: ["darwin"],
    policyHasValue: (cap) => typeof cap?.required === "boolean",
    desiredEqual: (cap) => cap?.required === true,
  },

  // ── SSH (Linux only — Win/Mac don't have an SSH daemon in our
  //    target server posture; even when Windows runs OpenSSH Server,
  //    the SCP collector doesn't extract its config the way the
  //    Linux one does) ────────────────────────────────────────────
  {
    capability: "ssh",
    subfield: "permitRootLogin",
    checkId: "linux.ssh.root_login_disabled",
    oses: ["linux"],
    policyHasValue: (cap) => cap?.permitRootLogin !== undefined,
    desiredEqual: (cap) => cap?.permitRootLogin === "no",
  },
  {
    capability: "ssh",
    subfield: "passwordAuthentication",
    checkId: "linux.ssh.password_auth_disabled",
    oses: ["linux"],
    policyHasValue: (cap) => typeof cap?.passwordAuthentication === "boolean",
    desiredEqual: (cap) => cap?.passwordAuthentication === false,
  },
  {
    capability: "ssh",
    subfield: "weakKexDisabled",
    checkId: "linux.cryptography.weak_ssh_kex_disabled",
    oses: ["linux"],
    policyHasValue: (cap) => typeof cap?.weakKexDisabled === "boolean",
    desiredEqual: (cap) => cap?.weakKexDisabled === true,
  },

  // ── TLS (Windows only — SCHANNEL is Windows-specific) ──────────
  {
    capability: "tls",
    subfield: "legacyDisabled",
    checkId: "windows.cryptography.legacy_tls_disabled",
    oses: ["win32"],
    policyHasValue: (cap) => typeof cap?.legacyDisabled === "boolean",
    desiredEqual: (cap) => cap?.legacyDisabled === true,
  },
  {
    capability: "tls",
    subfield: "weakCiphersDisabled",
    checkId: "windows.cryptography.weak_ciphers_disabled",
    oses: ["win32"],
    policyHasValue: (cap) => typeof cap?.weakCiphersDisabled === "boolean",
    desiredEqual: (cap) => cap?.weakCiphersDisabled === true,
  },

  // ── SMB (Windows) ──────────────────────────────────────────────
  {
    capability: "smb",
    subfield: "smbv1Disabled",
    checkId: "windows.network_sharing.smbv1_disabled",
    oses: ["win32"],
    policyHasValue: (cap) => typeof cap?.smbv1Disabled === "boolean",
    desiredEqual: (cap) => cap?.smbv1Disabled === true,
  },
];

// Effective mode resolver. Cascade:
//   1. capability.mode if set
//   2. security.defaultMode if set
//   3. "report-only" as the hardcoded floor (= safest fallback).
function effectiveMode(cap: any, policy: SecurityPolicy): SecurityMode {
  if (cap?.mode === "auto" || cap?.mode === "report-only" || cap?.mode === "off") {
    return cap.mode;
  }
  if (policy.defaultMode) return policy.defaultMode;
  return "report-only";
}

type EnforceOutcome =
  | "skipped_off"
  | "skipped_no_value"
  | "skipped_wrong_os"
  | "skipped_unenforceable_desired"   // policy wants the opposite of what remediator does
  | "skipped_cooldown"
  | "skipped_locked"
  | "skipped_no_remediator"           // placeholder capability
  | "compliant"
  | "drift_report_only"
  | "drift_remediated"
  | "drift_remediation_failed"
  | "drift_remediation_rebooting"
  | "error";

export type EnforceResult = {
  checkId: string | null;
  capability: string;
  subfield: string;
  mode: SecurityMode;
  outcome: EnforceOutcome;
  durationMs: number;
  detail?: string;
};

// Top-level entry. Called from the scheduler after each compliance
// pass. Returns one result per (capability, subfield) entry it
// evaluated — the caller logs the summary and (future) emits
// security_events upstream.
export async function runSecurityEnforce(
  ctx: AgentContext
): Promise<EnforceResult[]> {
  const policy = ctx.policyRuntime.getSecurityPolicy?.();
  if (!policy) {
    ctx.logger?.debug?.("[security] no policy configured, skipping enforcer");
    return [];
  }

  const passStart = Date.now();
  const passDeadline = passStart + ENFORCE_PASS_TIMEOUT_MS;
  const platform = os.platform() as Platform;
  const results: EnforceResult[] = [];

  // Iterate every potential remediator. We do this serially because
  // (a) the privsvc lock makes parallelism a no-op anyway, and
  // (b) the per-pass deadline lets us cut a long pass short
  //     without complicating the loop with Promise.race.
  for (const entry of SECURITY_CAPABILITY_REMEDIATORS) {
    if (Date.now() > passDeadline) {
      ctx.logger?.warn?.("[security] enforce pass exceeded deadline, bailing", {
        completed: results.length,
        remaining: SECURITY_CAPABILITY_REMEDIATORS.length - results.length,
      });
      break;
    }

    const cap = (policy as any)[entry.capability];
    if (!cap) {
      // Capability not in the policy at all — no opinion.
      continue;
    }

    const mode = effectiveMode(cap, policy);

    if (mode === "off") {
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "skipped_off",
        durationMs: 0,
      });
      continue;
    }

    if (!entry.policyHasValue(cap)) {
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "skipped_no_value",
        durationMs: 0,
      });
      continue;
    }

    if (!entry.oses.includes(platform)) {
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "skipped_wrong_os",
        durationMs: 0,
      });
      continue;
    }

    if (!entry.desiredEqual(cap)) {
      // The policy is unenforceable as written: operator set the
      // capability to a value the remediator can't reach (e.g.
      // permitRootLogin: "yes" when the remediator only enforces
      // "no"). Surface so the dashboard can show "unenforceable"
      // rather than silently doing nothing.
      ctx.logger?.warn?.("[security] policy unenforceable by current remediator", {
        capability: entry.capability,
        subfield: entry.subfield,
        checkId: entry.checkId,
      });
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "skipped_unenforceable_desired",
        durationMs: 0,
        detail: `Remediator ${entry.checkId} cannot reach the requested state.`,
      });
      continue;
    }

    // Cooldown gate — only applies to auto mode (report-only reads
    // are cheap and never modify state, so we run them every pass
    // for an up-to-date drift signal in the dashboard).
    if (mode === "auto") {
      const last = lastAppliedAt.get(entry.checkId) ?? 0;
      if (Date.now() - last < COOLDOWN_MS) {
        results.push({
          checkId: entry.checkId,
          capability: entry.capability,
          subfield: entry.subfield,
          mode,
          outcome: "skipped_cooldown",
          durationMs: 0,
          detail: `Cooldown active (last applied ${Math.round(
            (Date.now() - last) / 1000
          )}s ago).`,
        });
        continue;
      }
    }

    // ── Read current state ──────────────────────────────────────
    const itemStart = Date.now();
    const readResp = await ctx.priv.call({
      v: 1,
      id: `security-enforce-read-${entry.checkId}-${Date.now()}`,
      method: "pmp.read_check_state",
      params: { checkId: entry.checkId },
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    });

    if (!readResp?.ok) {
      const code = (readResp as any)?.error?.code || "read_state_failed";
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "error",
        durationMs: Date.now() - itemStart,
        detail: `read_check_state failed: ${code}`,
      });
      continue;
    }

    const compliant = readResp.result?.isCompliant === true;
    if (compliant) {
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "compliant",
        durationMs: Date.now() - itemStart,
      });
      continue;
    }

    // Drift detected.
    if (mode === "report-only") {
      ctx.logger?.warn?.("[security] drift detected (report-only)", {
        capability: entry.capability,
        subfield: entry.subfield,
        checkId: entry.checkId,
        state: readResp.result?.state,
      });
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "drift_report_only",
        durationMs: Date.now() - itemStart,
      });
      continue;
    }

    // mode === "auto": remediate. Acquire the shared PMP lock so we
    // don't collide with a Job-driven remediation. If we can't get
    // it, log + skip this pass; next compliance tick retries.
    const acquired = tryStartRemediate(ctx);
    if (!acquired) {
      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: "skipped_locked",
        durationMs: Date.now() - itemStart,
        detail: "another remediation in progress",
      });
      continue;
    }

    try {
      const applyResp = await ctx.priv.call({
        v: 1,
        id: `security-enforce-apply-${entry.checkId}-${Date.now()}`,
        method: "pmp.remediate",
        params: {
          checkId: entry.checkId,
          params: {},
          timeoutSeconds: 540,
        },
        meta: {
          tenantId: ctx.enrollment.tenantId,
          deviceId: ctx.enrollment.deviceId,
        },
      });

      if (!applyResp?.ok) {
        const code = (applyResp as any)?.error?.code || "remediate_failed";
        results.push({
          checkId: entry.checkId,
          capability: entry.capability,
          subfield: entry.subfield,
          mode,
          outcome: "drift_remediation_failed",
          durationMs: Date.now() - itemStart,
          detail: code,
        });
        continue;
      }

      const requiresReboot = applyResp.result?.requiresReboot === true;
      // Stamp cooldown on success regardless of reboot status —
      // the registry write is done, repeating it before reboot
      // changes nothing useful.
      lastAppliedAt.set(entry.checkId, Date.now());

      results.push({
        checkId: entry.checkId,
        capability: entry.capability,
        subfield: entry.subfield,
        mode,
        outcome: requiresReboot ? "drift_remediation_rebooting" : "drift_remediated",
        durationMs: Date.now() - itemStart,
        detail: requiresReboot ? "reboot required to fully apply" : undefined,
      });
    } finally {
      finishRemediate();
    }
  }

  ctx.logger?.info?.("[security] enforce pass complete", {
    durationMs: Date.now() - passStart,
    items: results.length,
    summary: summarize(results),
  });

  // Emit audit events for outcomes that changed since the previous
  // pass. Failures here are swallowed — audit-event emission must
  // not break the enforcer's primary loop.
  try {
    await emitSecurityEnforceEvents(ctx, results);
  } catch (err: any) {
    ctx.logger?.warn?.("[security] audit emit failed (non-fatal)", {
      error: err?.message || String(err),
    });
  }

  return results;
}

function summarize(results: EnforceResult[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const r of results) {
    counts[r.outcome] = (counts[r.outcome] ?? 0) + 1;
  }
  return counts;
}

// ── Audit-event emission to backend security_events table ─────────
//
// After each enforce pass, ship one event per (checkId, outcome) that
// CHANGED since the previous pass. Events ride the existing FACTS
// pipeline via the new `security_enforce` namespace; the backend's
// controlplane.persistSecurityEnforceEvents handler reads
// `namespaces.security_enforce.events[]` and writes one row per
// entry to the control DB's `security_events` table.
//
// Suppression rule (lastEmittedOutcome map): if a checkId's outcome
// didn't change since the previous emit, skip it. This is how we
// avoid the "9 identical drift events for the same host over
// 24h" anti-pattern. The map is in-memory; agent restart resets it,
// which re-emits the current state once on first pass — acceptable.

type SecurityEnforceEvent = {
  occurredAtUtc: string;
  capability: string;
  subfield: string;
  checkId: string;
  mode: SecurityMode;
  outcome: EnforceOutcome;
  eventType: string;             // e.g. SECURITY_DRIFT_REMEDIATED
  durationMs: number;
  detail?: string;
};

async function emitSecurityEnforceEvents(
  ctx: AgentContext,
  results: EnforceResult[]
): Promise<void> {
  const events: SecurityEnforceEvent[] = [];
  const occurredAtUtc = new Date().toISOString();

  for (const r of results) {
    if (!AUDITABLE_OUTCOMES.has(r.outcome)) continue;
    if (!r.checkId) continue;

    const lastOutcome = lastEmittedOutcome.get(r.checkId);
    if (lastOutcome === r.outcome) continue;

    const eventType = AUDIT_EVENT_TYPES[r.outcome];
    if (!eventType) continue; // belt-and-braces

    events.push({
      occurredAtUtc,
      capability: r.capability,
      subfield: r.subfield,
      checkId: r.checkId,
      mode: r.mode,
      outcome: r.outcome,
      eventType,
      durationMs: r.durationMs,
      detail: r.detail,
    });

    // Also clear `compliant` from the map so the NEXT drift after
    // a compliant pass gets emitted. We do this by tracking
    // compliant alongside auditable outcomes, with the
    // lastEmittedOutcome map covering both. See the second pass
    // below.
  }

  // Second pass: record EVERY result (including compliant + skips)
  // in lastEmittedOutcome so the next pass diffs correctly. We do
  // this AFTER collecting events to keep the diff logic clean.
  for (const r of results) {
    if (r.checkId) lastEmittedOutcome.set(r.checkId, r.outcome);
  }

  if (events.length === 0) {
    ctx.logger?.debug?.("[security] no auditable outcome changes; nothing to emit");
    return;
  }

  ctx.logger?.info?.("[security] emitting audit events", {
    count: events.length,
    types: events.map((e) => e.eventType),
  });

  // Wrap into the standard device-facts envelope. The wire layer
  // (grpc-stream.ts:1331-1392) routes any FACTS_SNAPSHOT with a
  // `namespaces.<X>` block to the backend, which then dispatches by
  // namespace name. `security_enforce` is the new namespace handled
  // server-side by persistSecurityEnforceEvents.
  const namespaces: any = {
    security_enforce: {
      events,
    },
  };
  const facts = await buildDeviceFacts(ctx, namespaces);

  outbox.enqueue({
    type: "FACTS_SNAPSHOT",
    payload: facts,
  });
}
