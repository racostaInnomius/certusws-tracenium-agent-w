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
//
// pmp.revert: deshace un fix de los tres remediables devolviendo el
// `state` que `pmp.read_check_state` leyó ANTES del fix. sip/filevault
// no tienen revert (tampoco tienen fix).

import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
import fs from "fs";
import { applyGeneric, readGenericState, type MacGenericDeps } from "./generic-config";

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
// Excepción: `pmp.revert` sí lo usa, y sólo para devolver el estado
// que `pmp.read_check_state` registró antes del fix (ver más abajo).

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

// ── Genérico (generic-config.ts) ─────────────────────────────────
// Recibe `req.params.params` (las escrituras que pidió el backend); los
// dedicados lo ignoran.

/** Un payload inválido para el genérico es bad_request, no un fallo del equipo. */
class BadGenericParams extends Error {}

const genericDeps: MacGenericDeps = {
  exec: (bin, args, timeoutMs) => runCmd(bin, args, timeoutMs ?? 60_000),
  exists: (p) => fs.existsSync(p),
  copyFile: (src, dst) => fs.copyFileSync(src, dst),
};

async function readGeneric(params: unknown): Promise<{ state: any; isCompliant: boolean }> {
  const r = await readGenericState(params, genericDeps);
  if (!r.ok) throw new BadGenericParams(r.message);
  return r.value;
}

async function remediateGeneric(params: unknown): Promise<any> {
  const r = await applyGeneric(params, genericDeps);
  if (!r.ok) throw new BadGenericParams(r.message);
  return r.value;
}

const READ_HANDLERS: Record<string, (params: unknown) => Promise<{ state: any; isCompliant: boolean }>> = {
  "macos.firewall.enabled":      readMacFirewall,
  "macos.gatekeeper.enabled":    readMacGatekeeper,
  "macos.remote_login.disabled": readMacRemoteLogin,
  "macos.sip.enabled":           readMacSip,
  "macos.filevault.enabled":     readMacFileVault,
  "macos.config.set_value":      readGeneric,
};

const REMEDIATE_HANDLERS: Record<string, (params: unknown) => Promise<any>> = {
  "macos.firewall.enabled":      remediateMacFirewall,
  "macos.gatekeeper.enabled":    remediateMacGatekeeper,
  "macos.remote_login.disabled": remediateMacRemoteLogin,
  "macos.config.set_value":      remediateGeneric,
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
    const result = await handler(req.params?.params);
    return success(req.id, {
      state: result.state,
      isCompliant: result.isCompliant === true,
      supported: true,
    });
  } catch (err: any) {
    if (err instanceof BadGenericParams) return fail(req.id, "bad_request", err.message);
    logger.error("pmp_read_check_state_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "read_state_failed", err?.message || String(err));
  }
}

// ── pmp.remediate ────────────────────────────────────────────────

// Forma de respuesta compartida por remediate y revert: el agente Node
// parsea ambas con el mismo código.
function toRemediationResult(result: any) {
  return {
    exitCode: result.exitCode,
    stderrExcerpt: result.stderrExcerpt ?? null,
    durationMs: result.durationMs,
    requiresReboot: result.requiresReboot === true,
    changesApplied: Array.isArray(result.changesApplied) ? result.changesApplied : [],
  };
}

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
    const result = await handler(req.params?.params);
    return success(req.id, toRemediationResult(result));
  } catch (err: any) {
    if (err instanceof BadGenericParams) return fail(req.id, "bad_request", err.message);
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

// ── pmp.revert ───────────────────────────────────────────────────
//
// Contrato: params = { checkId, params: { stateBefore }, timeoutSeconds? }.
// `stateBefore` es EXACTAMENTE el `state` que devolvió read_check_state
// antes del fix. Tras un revert con éxito, read_check_state tiene que
// devolver ese mismo estado en cada clave: el agente Node lo verifica.
// Por eso sólo se deshace lo que el fix cambia, con el comando espejo
// del forward; si el estado previo ya era el que deja el fix, no-op.
//
// La planificación es pura (planMacRevert) para poder testear qué se
// ejecutaría sin tocar el sistema; handlePmpRevert sólo la ejecuta.

export type MacRevertStep = { bin: string; args: string[]; change: string };

export type MacRevertPlan =
  | {
      commands: MacRevertStep[];
      // Claves del state que read_check_state debe devolver tras los
      // comandos. Se comprueban aquí mismo para no dar por bueno un
      // comando que sale 0 sin aplicar (spctl en Sequoia, ver abajo).
      expect: Record<string, unknown>;
      // Aviso que se añade al stderrExcerpt si algo falla.
      failureHint?: string;
    }
  | { error: { code: "unsupported_check" | "bad_request"; message: string } };

// exitCode sintético cuando el comando sale 0 pero el estado no cambió.
// Cualquier no-cero sirve: el agente trata el revert como fallido.
const REVERT_POST_STATE_MISMATCH_EXIT = 1;

// timeoutSeconds acota el revert entero. Tope para que un valor absurdo
// del backend no deje un hijo colgado indefinidamente.
const REVERT_MAX_TIMEOUT_MS = 300_000;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function badRequest(message: string): MacRevertPlan {
  return { error: { code: "bad_request", message } };
}

// Validación estricta y común: sólo las claves que produce el read del
// checkId, y `raw` (si viene) tiene que ser string. Una clave extraña
// indica que el stateBefore no salió de este read → no adivinamos.
function checkKnownKeys(s: Record<string, unknown>, allowed: string[]): string | null {
  const extra = Object.keys(s).filter((k) => !allowed.includes(k));
  if (extra.length > 0) return `unexpected key(s) in stateBefore: ${extra.join(", ")}`;
  if ("raw" in s && typeof s.raw !== "string") return "stateBefore.raw must be a string";
  return null;
}

// Firewall: el fix sólo hace `--setglobalstate on`; no toca stealth
// mode ni block-all, y el state tampoco los registra (stateValue 2 ya
// cuenta como enabled y el fix no corre). Sólo hay que apagar si antes
// estaba apagado (State = 0).
function planFirewallRevert(s: Record<string, unknown>): MacRevertPlan {
  const keysErr = checkKnownKeys(s, ["enabled", "stateValue", "raw"]);
  if (keysErr) return badRequest(keysErr);
  if (typeof s.enabled !== "boolean") return badRequest("stateBefore.enabled must be a boolean");
  if (!("stateValue" in s)) return badRequest("stateBefore.stateValue is required");
  const sv = s.stateValue;
  if (sv !== null && !(typeof sv === "number" && Number.isInteger(sv) && sv >= 0 && sv <= 2)) {
    return badRequest("stateBefore.stateValue must be 0, 1, 2 or null");
  }
  // readMacFirewall deriva enabled de stateValue; si no cuadran, el
  // objeto no es un state de ese read.
  if (s.enabled !== (sv !== null && sv >= 1)) {
    return badRequest("stateBefore.enabled does not match stateBefore.stateValue");
  }
  if (s.enabled) return { commands: [], expect: {} };
  // stateValue null = el read no pudo parsear la salida: no sabemos a
  // qué volver, y apagar dejaría stateValue 0 ≠ null de todos modos.
  if (sv === null) {
    return badRequest("stateBefore records an unknown firewall state (stateValue is null); nothing to restore to");
  }
  return {
    commands: [{ bin: ALF_PATH, args: ["--setglobalstate", "off"], change: "alf:globalstate=off" }],
    expect: { enabled: false, stateValue: 0 },
  };
}

// Gatekeeper: espejo de `--master-enable`. En macOS 15+ `--master-disable`
// ya no desactiva por sí solo: sólo hace visible la opción "Anywhere" y
// pide confirmación en System Settings, y puede salir 0 sin cambiar nada.
// De ahí la verificación del estado posterior en vez de fiarse del exit.
const GATEKEEPER_DISABLE_HINT =
  "On recent macOS versions `spctl --master-disable` may only reveal the \"Anywhere\" option " +
  "and require the user to confirm it in System Settings > Privacy & Security.";

function planGatekeeperRevert(s: Record<string, unknown>): MacRevertPlan {
  const keysErr = checkKnownKeys(s, ["enabled", "raw"]);
  if (keysErr) return badRequest(keysErr);
  if (typeof s.enabled !== "boolean") return badRequest("stateBefore.enabled must be a boolean");
  if (s.enabled) return { commands: [], expect: {} };
  return {
    commands: [{ bin: "/usr/sbin/spctl", args: ["--master-disable"], change: "spctl:--master-disable" }],
    expect: { enabled: false },
    failureHint: GATEKEEPER_DISABLE_HINT,
  };
}

// Remote Login: espejo exacto del fix, incluido -f (sin él systemsetup
// espera confirmación por stdin y el daemon se cuelga). Desde macOS 13
// systemsetup exige Full Disk Access para esto, igual que el forward.
function planRemoteLoginRevert(s: Record<string, unknown>): MacRevertPlan {
  const keysErr = checkKnownKeys(s, ["enabled", "raw"]);
  if (keysErr) return badRequest(keysErr);
  if (s.enabled !== null && typeof s.enabled !== "boolean") {
    return badRequest("stateBefore.enabled must be a boolean or null");
  }
  // null = el read no reconoció la salida: no hay estado al que volver.
  if (s.enabled === null) {
    return badRequest("stateBefore records an unknown Remote Login state (enabled is null); nothing to restore to");
  }
  if (!s.enabled) return { commands: [], expect: {} };
  return {
    commands: [{ bin: "/usr/sbin/systemsetup", args: ["-f", "-setremotelogin", "on"], change: "systemsetup:remotelogin=on" }],
    expect: { enabled: true },
    failureHint: "systemsetup needs Full Disk Access for the privileged service to change Remote Login.",
  };
}

const REVERT_PLANNERS: Record<string, (s: Record<string, unknown>) => MacRevertPlan> = {
  "macos.firewall.enabled":      planFirewallRevert,
  "macos.gatekeeper.enabled":    planGatekeeperRevert,
  "macos.remote_login.disabled": planRemoteLoginRevert,
  // sip / filevault: sin fix no hay nada que deshacer.
};

export function planMacRevert(checkId: string, stateBefore: unknown): MacRevertPlan {
  const planner = REVERT_PLANNERS[checkId];
  if (!planner) {
    const readOnly = checkId in READ_HANDLERS;
    return {
      error: {
        code: "unsupported_check",
        message: readOnly
          ? `checkId ${checkId} is read-only on macOS; there is no fix to revert`
          : `no revert handler for checkId ${checkId} on macOS`,
      },
    };
  }
  if (!isPlainObject(stateBefore)) return badRequest("params.stateBefore must be an object");
  return planner(stateBefore);
}

function resolveRevertTimeoutMs(raw: unknown): number | null {
  if (raw === undefined || raw === null) return HANDLER_TIMEOUT_MS;
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) return null;
  return Math.min(Math.round(raw * 1000), REVERT_MAX_TIMEOUT_MS);
}

function revertTimeout(message: string): Error {
  return Object.assign(new Error(message), { code: "revert_timeout" });
}

function withHint(text: string, hint?: string): string {
  const base = text.trim();
  if (!hint) return base;
  return base ? `${base}\n${hint}` : hint;
}

async function executeMacRevert(
  checkId: string,
  plan: Extract<MacRevertPlan, { commands: MacRevertStep[] }>,
  timeoutMs: number,
): Promise<any> {
  const start = Date.now();
  const deadline = start + timeoutMs;
  const changesApplied: string[] = [];
  let lastOutput = "";

  for (const step of plan.commands) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw revertTimeout(`revert of ${checkId} timed out before ${step.change}`);
    const r = await runCmd(step.bin, step.args, remaining);
    // runCmd marca con 124 al hijo matado por timeout.
    if (r.code === 124) throw revertTimeout(`revert of ${checkId} timed out running ${step.change}`);
    lastOutput = `${r.stderr}\n${r.stdout}`.trim();
    if (r.code !== 0) {
      return {
        exitCode: r.code,
        stderrExcerpt: excerpt(withHint(r.stderr || r.stdout, plan.failureHint)),
        durationMs: Date.now() - start,
        requiresReboot: false,
        changesApplied,
      };
    }
    changesApplied.push(step.change);
  }

  // No-op (el estado previo ya era el que deja el fix): nada que verificar.
  if (plan.commands.length > 0) {
    const after = await READ_HANDLERS[checkId](undefined);
    const mismatched = Object.entries(plan.expect)
      .filter(([k, v]) => after.state?.[k] !== v)
      .map(([k, v]) => `${k}: expected ${JSON.stringify(v)}, got ${JSON.stringify(after.state?.[k])}`);
    if (mismatched.length > 0) {
      return {
        exitCode: REVERT_POST_STATE_MISMATCH_EXIT,
        stderrExcerpt: excerpt(withHint(
          `Command succeeded but the state was not restored (${mismatched.join("; ")}).` +
            (lastOutput ? `\n${lastOutput}` : ""),
          plan.failureHint,
        )),
        durationMs: Date.now() - start,
        requiresReboot: false,
        // No se anuncian cambios que el sistema no refleja.
        changesApplied: [],
      };
    }
  }

  return {
    exitCode: 0,
    stderrExcerpt: undefined,
    durationMs: Date.now() - start,
    requiresReboot: false,
    changesApplied,
  };
}

export async function handlePmpRevert(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) {
    return fail(req.id, "bad_request", "checkId required");
  }

  const plan = planMacRevert(checkId, req.params?.params?.stateBefore);
  if ("error" in plan) {
    logger.info("pmp_revert_rejected", { checkId, code: plan.error.code, message: plan.error.message });
    return fail(req.id, plan.error.code, plan.error.message);
  }

  const timeoutMs = resolveRevertTimeoutMs(req.params?.timeoutSeconds);
  if (timeoutMs === null) {
    return fail(req.id, "bad_request", "timeoutSeconds must be a positive number");
  }

  try {
    const result = await executeMacRevert(checkId, plan, timeoutMs);
    logger.info("pmp_revert_done", {
      checkId,
      exitCode: result.exitCode,
      changesApplied: result.changesApplied,
    });
    return success(req.id, toRemediationResult(result));
  } catch (err: any) {
    if (err?.code === "revert_timeout") {
      logger.warn("pmp_revert_timeout", { checkId, error: err?.message });
      return fail(req.id, "revert_timeout", err?.message || "revert timed out");
    }
    logger.error("pmp_revert_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "revert_failed", err?.message || String(err));
  }
}
