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

// Phase 1 — 4 Windows checkIds.
// Phase 2 — 1 more Windows checkId added (SMB share ACLs).
// Phase 8 — 4 Linux checkIds added (sshd hardening + firewall).
//
// ⚠️ These are HANDLER ids — the keys of the privsvc pmp-remediation
// registries on each platform — NOT catalog check_ids. A previous
// version of this comment claimed the names "match the catalog seed";
// audited 2026-08-14, 7 of 14 match nothing in the catalog
// (windows.cryptography.* vs the catalog's windows.crypto.*, linux.ssh.
// root_login_disabled vs permit_root_login_disabled, one Windows
// firewall handler vs three per-profile catalog checks, …). That false
// claim is why click-to-fix stayed dead for a whole release: the
// backend compared catalog ids against this list.
//
// The join now lives control-plane-side in the backend's
// modules/patch-management/remediation-crosswalk.ts (catalog id →
// handler id). The backend translates BEFORE dispatching, so what
// arrives here in a patch_remediate job is always a handler id from
// this list. Adding a check = new entry here + matching privsvc
// handler on each platform + a crosswalk row in the backend (its test
// reads this file and fails if a mapped handler is missing here).
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

  // ── Windows Phase 2 ─────────────────────────────────────────────
  {
    checkId: "windows.shares.no_everyone_full_control",
    applicableTo: new Set<CheckOsApplicability>(["windows"]),
  },

  // ── Linux Phase 8 ───────────────────────────────────────────────
  // These four checkIds are implemented in
  // privsvc/linux/src/pmp-remediation.ts. Each remediation writes a
  // directive to /etc/ssh/sshd_config.d/99-tracenium-hardening.conf
  // (the drop-in approach — never touches the operator's main
  // /etc/ssh/sshd_config). Drop-in changes are validated via
  // `sshd -t` BEFORE atomic rename so a syntactically broken edit
  // never lands. Pre-edit backup goes to <file>.tracenium.<ts>.bak.
  //
  // Catalog entries that drive these will live in the backend's
  // compliance_catalog_seed migration with `agent_remediable=true`.
  // Until those land, the dashboard's "Auto-fix" button stays
  // disabled and the check shows up in Findings as manual-only.
  {
    checkId: "linux.ssh.root_login_disabled",
    applicableTo: new Set<CheckOsApplicability>(["linux"]),
  },
  {
    checkId: "linux.ssh.password_auth_disabled",
    applicableTo: new Set<CheckOsApplicability>(["linux"]),
  },
  {
    checkId: "linux.cryptography.weak_ssh_kex_disabled",
    applicableTo: new Set<CheckOsApplicability>(["linux"]),
  },
  {
    checkId: "linux.firewall.enabled",
    applicableTo: new Set<CheckOsApplicability>(["linux"]),
  },

  // ── macOS (Sprint 3 — A1) ───────────────────────────────────────
  // Five checkIds implemented in privsvc/macos/src/pmp-remediation.ts.
  // Three are read+remediate (firewall, gatekeeper, remote_login);
  // two are read-only (sip, filevault) — sip can only be toggled
  // from Recovery, and filevault enabling requires interactive user
  // auth which a daemon can't safely provide. The agent still
  // whitelists all five here so the read-state path is reachable
  // (the dashboard's posture timeline calls it to show "sip
  // enabled / disabled" without invoking remediation).
  {
    checkId: "macos.firewall.enabled",
    applicableTo: new Set<CheckOsApplicability>(["macos"]),
  },
  {
    checkId: "macos.gatekeeper.enabled",
    applicableTo: new Set<CheckOsApplicability>(["macos"]),
  },
  {
    checkId: "macos.remote_login.disabled",
    applicableTo: new Set<CheckOsApplicability>(["macos"]),
  },
  {
    checkId: "macos.sip.enabled",
    applicableTo: new Set<CheckOsApplicability>(["macos"]),
  },
  {
    checkId: "macos.filevault.enabled",
    applicableTo: new Set<CheckOsApplicability>(["macos"]),
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
