// src/plugins/pmp/remediation-checks.ts
//
// Agent-side whitelist of checkIds the PMP plugin knows how to
// remediate. Mirror of the backend's `AGENT_REMEDIABLE_CHECK_IDS`
// (see modules/patch-management/findings.service.ts) AND the
// privsvc-side dispatch tables:
//
//   * privsvc/macos/src/pmp-remediation.ts (HANDLERS map)
//   * privsvc/windows/.../Ipc/PmpRemediation.cs (HANDLERS dict)
//
// Three sources of truth must stay in lockstep — adding a new
// remediation means editing this file + the matching privsvc impl
// + the backend whitelist + (optionally) updating the catalog seed
// migration if the checkId itself is new. The agent layer sits in
// the middle: it has to validate `payload.checkId` against this
// whitelist BEFORE bothering the privsvc, so a forgery from a
// compromised backend can't talk us into invoking arbitrary privsvc
// methods.
//
// Per-OS applicability is recorded here too so the agent can short-
// circuit a job that targets the wrong platform with a clean
// `outcome=rejected` instead of waiting for the privsvc to bounce
// it.

import os from "os";

export type CheckOsApplicability = "windows" | "macos" | "linux";

interface AgentCheckEntry {
  checkId: string;
  // Which OS this checkId applies to. For Phase 1 every entry is
  // single-platform; future cross-platform checks (e.g.
  // "core.audit_logs_enabled") would list multiple.
  applicableTo: ReadonlySet<CheckOsApplicability>;
}

// Phase 1 — 4 Windows checkIds. Names match the catalog seed
// (`windows.<category>.<spec>`) so backend → agent → privsvc share
// identical strings. Adding more in Phase 2 = a single new entry
// here per check + the matching privsvc handler.
const ENTRIES: AgentCheckEntry[] = [
  {
    checkId: "windows.cryptography.legacy_tls_disabled",
    applicableTo: new Set<CheckOsApplicability>(["windows"]),
  },
  {
    checkId: "windows.cryptography.weak_ciphers_disabled",
    applicableTo: new Set<CheckOsApplicability>(["windows"]),
  },
  {
    checkId: "windows.network_sharing.smbv1_disabled",
    applicableTo: new Set<CheckOsApplicability>(["windows"]),
  },
  {
    checkId: "windows.firewall.profiles_enabled",
    applicableTo: new Set<CheckOsApplicability>(["windows"]),
  },
];

const BY_CHECK_ID: ReadonlyMap<string, AgentCheckEntry> = new Map(
  ENTRIES.map((e) => [e.checkId, e])
);

/**
 * Map Node's os.platform() to the catalog's applicability vocab.
 * Linux is included for completeness even though no Phase 1 check
 * targets it.
 */
function localOs(): CheckOsApplicability | null {
  const p = os.platform();
  if (p === "win32") return "windows";
  if (p === "darwin") return "macos";
  if (p === "linux") return "linux";
  return null;
}

export type WhitelistDecision =
  | { allowed: true }
  | { allowed: false; reason: "unknown_check_id" | "not_applicable_to_os" };

/**
 * Validate that the agent on THIS host can act on `checkId`.
 * The privsvc has its own dispatch table — this is the cheaper
 * earlier gate that lets us reject jobs without crossing IPC.
 */
export function isCheckRemediableHere(checkId: string): WhitelistDecision {
  const entry = BY_CHECK_ID.get(checkId);
  if (!entry) return { allowed: false, reason: "unknown_check_id" };

  const here = localOs();
  if (!here || !entry.applicableTo.has(here)) {
    return { allowed: false, reason: "not_applicable_to_os" };
  }
  return { allowed: true };
}

/**
 * For diagnostics + future tray surface: full list of checkIds the
 * local agent knows about (any OS). Caller filters by os if needed.
 */
export function listKnownCheckIds(): string[] {
  return ENTRIES.map((e) => e.checkId);
}
