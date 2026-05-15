// privsvc/macos/src/pmp-remediation.ts
//
// Patch Management v2 — privsvc handlers for non-patch posture
// remediation on macOS.
//
// Sprint 3 (A1) ships 5 checkIds, mirroring the four-checkId catalog
// that Linux and Windows already implement. Same return shape, same
// failure semantics, same router contract — the agent's PMP plugin
// (src/plugins/pmp/) doesn't need ANY macOS-specific code; the
// checkId list lives entirely server-side in
// compliance_check_catalog and is whitelisted on the agent via
// remediation-checks.ts.
//
// Catalog (Sprint 3):
//
//   macos.firewall.enabled            — READ + REMEDIATE
//     ALF (Application Layer Firewall). Single binary, no reboot.
//     Maps to security policy field `firewall.required`.
//
//   macos.gatekeeper.enabled          — READ + REMEDIATE
//     Code-signing assessment. Single `spctl` call, no reboot.
//
//   macos.remote_login.disabled       — READ + REMEDIATE
//     SSH server (sshd) enabled via System Settings → General → Sharing.
//     `systemsetup -setremotelogin off` with -f to skip the
//     interactive confirmation. No reboot.
//
//   macos.sip.enabled                 — READ ONLY
//     System Integrity Protection. Toggling SIP requires booting to
//     Recovery and running `csrutil enable` there — there is no
//     userland API. We READ via `csrutil status` so the dashboard
//     surfaces the state, but REMEDIATE returns unsupported_check.
//
//   macos.filevault.enabled           — READ ONLY
//     Disk encryption. `fdesetup enable` requires interactive user
//     auth (password) AND a Recovery Key prompt; can't be safely
//     scripted from a daemon without leaking the user's password.
//     READ only.
//
// Why these five (and not more):
//   * They map 1-1 to the existing macOS SCP collector evidence
//     blocks (firewall, gatekeeper, sip, filevault, services).
//   * Three of them are AUTO-remediable from a daemon (firewall,
//     gatekeeper, remote_login). The other two (sip, filevault)
//     have hard runtime limits.
//   * SCP `screenLock` and `smb.smb1` could be added but ship as
//     follow-ups: screen lock policy is a defaults-write that
//     touches user-domain prefs (need per-user iteration), and
//     macOS's SMB stack already disables SMBv1 by default since
//     macOS 12.

import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

// Per-handler exec timeout. macOS tools are predictable — `spctl`,
// `csrutil`, `socketfilterfw` return in ms; `systemsetup` is the
// outlier and can take a few seconds because it serialises through
// the System Events helper. 10s covers everything with margin.
const HANDLER_TIMEOUT_MS = 10_000;

type CmdResult = { stdout: string; stderr: string; code: number };

async function runCmd(bin: string, args: string[], timeoutMs = HANDLER_TIMEOUT_MS): Promise<CmdResult> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, { timeout: timeoutMs });
    return { stdout: stdout || "", stderr: stderr || "", code: 0 };
  } catch (err: any) {
    // execFile rejects on non-zero exit AND on timeout. Both cases
    // carry stdout/stderr; the caller decides how to interpret.
    // Timeout-killed children have err.killed === true + err.signal
    // === "SIGTERM"; we surface that via a synthetic exit code 124
    // (the GNU `timeout(1)` convention) so handlers don't need a
    // separate timeout-handling branch.
    const isTimeout = err?.killed === true && err?.signal === "SIGTERM";
    return {
      stdout: err?.stdout || "",
      stderr: err?.stderr || "",
      code: isTimeout ? 124 : (typeof err?.code === "number" ? err.code : 1),
    };
  }
}

function excerpt(s: string, max = 1024): string {
  if (!s) return "";
  const trimmed = s.trim();
  return trimmed.length > max ? trimmed.slice(0, max) + "...[truncated]" : trimmed;
}

// ── Firewall (ALF) ───────────────────────────────────────────────
//
// `socketfilterfw --getglobalstate` outputs one of:
//   "Firewall is disabled. (State = 0)"
//   "Firewall is enabled.  (State = 1)"
//   "Firewall is enabled and blocking all incoming. (State = 2)"
//
// State >= 1 means firewall is on (we treat both 1 and 2 as enabled
// because either fulfils the `firewall.required` policy).

const ALF_PATH = "/usr/libexec/ApplicationFirewall/socketfilterfw";

async function readMacFirewall(): Promise<{ state: any; isCompliant: boolean }> {
  const r = await runCmd(ALF_PATH, ["--getglobalstate"]);
  const match = r.stdout.match(/State\s*=\s*(\d+)/i);
  const stateNum = match ? Number(match[1]) : null;
  const enabled = stateNum !== null && stateNum >= 1;
  return {
    state: {
      enabled,
      stateValue: stateNum,
      raw: excerpt(r.stdout, 256),
    },
    isCompliant: enabled,
  };
}

async function remediateMacFirewall(): Promise<any> {
  const start = Date.now();
  const r = await runCmd(ALF_PATH, ["--setglobalstate", "on"]);
  return {
    exitCode: r.code,
    stderrExcerpt: r.code === 0 ? undefined : excerpt(r.stderr),
    durationMs: Date.now() - start,
    requiresReboot: false,
    changesApplied: r.code === 0 ? ["alf:globalstate=on"] : [],
  };
}

// ── Gatekeeper ───────────────────────────────────────────────────
//
// `spctl --status` outputs:
//   "assessments enabled"   → gatekeeper on
//   "assessments disabled"  → gatekeeper off
//
// `spctl --master-enable` re-enables. `--master-disable` is the
// inverse; we don't expose that direction (CIS / NIST want gatekeeper
// ON, and an admin who explicitly needs it off can run it manually).

async function readMacGatekeeper(): Promise<{ state: any; isCompliant: boolean }> {
  const r = await runCmd("/usr/sbin/spctl", ["--status"]);
  const enabled = /assessments\s+enabled/i.test(r.stdout);
  return {
    state: {
      enabled,
      raw: excerpt(r.stdout, 256),
    },
    isCompliant: enabled,
  };
}

async function remediateMacGatekeeper(): Promise<any> {
  const start = Date.now();
  const r = await runCmd("/usr/sbin/spctl", ["--master-enable"]);
  return {
    exitCode: r.code,
    stderrExcerpt: r.code === 0 ? undefined : excerpt(r.stderr),
    durationMs: Date.now() - start,
    requiresReboot: false,
    changesApplied: r.code === 0 ? ["spctl:--master-enable"] : [],
  };
}

// ── Remote Login (sshd) ──────────────────────────────────────────
//
// `systemsetup -getremotelogin` outputs:
//   "Remote Login: On"
//   "Remote Login: Off"
//
// To remediate (turn OFF), use:
//   systemsetup -f -setremotelogin off
//
// The `-f` skips the interactive confirmation prompt ("You are
// about to disable Remote Login. Confirm? [y/N]"). Without -f a
// daemon-spawned systemsetup would hang waiting on stdin.

async function readMacRemoteLogin(): Promise<{ state: any; isCompliant: boolean }> {
  const r = await runCmd("/usr/sbin/systemsetup", ["-getremotelogin"]);
  // "Remote Login: On" / "Remote Login: Off"
  const onMatch = /Remote\s+Login:\s*On\b/i.test(r.stdout);
  const offMatch = /Remote\s+Login:\s*Off\b/i.test(r.stdout);
  return {
    state: {
      enabled: onMatch ? true : offMatch ? false : null,
      raw: excerpt(r.stdout, 256),
    },
    isCompliant: offMatch, // policy is "remote login DISABLED"
  };
}

async function remediateMacRemoteLogin(): Promise<any> {
  const start = Date.now();
  const r = await runCmd("/usr/sbin/systemsetup", ["-f", "-setremotelogin", "off"]);
  return {
    exitCode: r.code,
    stderrExcerpt: r.code === 0 ? undefined : excerpt(r.stderr),
    durationMs: Date.now() - start,
    requiresReboot: false,
    changesApplied: r.code === 0 ? ["systemsetup:remotelogin=off"] : [],
  };
}

// ── SIP (read-only) ──────────────────────────────────────────────
//
// `csrutil status` outputs (varies slightly by macOS major):
//   "System Integrity Protection status: enabled."
//   "System Integrity Protection status: disabled."
//
// CANNOT be remediated from a running system — SIP is set in NVRAM
// by `csrutil enable` while booted to Recovery (`Cmd-R` at boot).
// We return unsupported_check from the remediate path.

async function readMacSip(): Promise<{ state: any; isCompliant: boolean }> {
  const r = await runCmd("/usr/bin/csrutil", ["status"]);
  const enabled = /enabled\.?/i.test(r.stdout) && !/disabled/i.test(r.stdout);
  return {
    state: {
      enabled,
      raw: excerpt(r.stdout, 256),
    },
    isCompliant: enabled,
  };
}

// ── FileVault (read-only) ────────────────────────────────────────
//
// `fdesetup status` outputs:
//   "FileVault is On."
//   "FileVault is Off."
//   "FileVault is Off, but will be enabled after the next restart..."
//
// Enabling FileVault from a daemon would require capturing the
// user's login password AND handling the recovery-key prompt — both
// outside what privsvc can safely do. Read-only.

async function readMacFileVault(): Promise<{ state: any; isCompliant: boolean }> {
  const r = await runCmd("/usr/bin/fdesetup", ["status"]);
  const on = /FileVault\s+is\s+On\b/i.test(r.stdout);
  const off = /FileVault\s+is\s+Off\b/i.test(r.stdout);
  return {
    state: {
      enabled: on ? true : off ? false : null,
      raw: excerpt(r.stdout, 256),
    },
    isCompliant: on,
  };
}

// ── Dispatch tables ──────────────────────────────────────────────

const READ_HANDLERS: Record<string, () => Promise<{ state: any; isCompliant: boolean }>> = {
  "macos.firewall.enabled":      readMacFirewall,
  "macos.gatekeeper.enabled":    readMacGatekeeper,
  "macos.remote_login.disabled": readMacRemoteLogin,
  "macos.sip.enabled":           readMacSip,
  "macos.filevault.enabled":     readMacFileVault,
};

const REMEDIATE_HANDLERS: Record<string, () => Promise<any>> = {
  "macos.firewall.enabled":      remediateMacFirewall,
  "macos.gatekeeper.enabled":    remediateMacGatekeeper,
  "macos.remote_login.disabled": remediateMacRemoteLogin,
  // sip / filevault intentionally omitted — see file header.
};

// ── pmp.read_check_state ─────────────────────────────────────────

export async function handlePmpReadCheckState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) {
    return fail(req.id, "bad_request", "checkId required");
  }

  const handler = READ_HANDLERS[checkId];
  if (!handler) {
    logger.info("pmp_read_check_state_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no read handler for checkId ${checkId} on macOS`);
  }

  try {
    const result = await handler();
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
    const result = await handler();
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
