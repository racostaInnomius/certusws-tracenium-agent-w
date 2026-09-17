// src/plugins/pmp/reboot.ts
//
// PMP — whether a patch run should restart the machine, as PURE functions.
//
// WHY THIS EXISTS
// A Windows patch is not applied until the machine restarts. Until then the
// endpoint is in the worst of both states: the update is staged, the old code
// is still running, and the console shows it as patched. Automating a patch
// window without automating the restart leaves a fleet that is permanently
// "pending reboot" and never actually protected.
//
// OPT-IN, ALWAYS. The operator asks for it per run (`rebootIfRequired` in the
// job payload). Nothing here ever restarts a machine that was not explicitly
// enrolled in it — a surprise restart of a production server is a worse
// outcome than an unapplied patch.
//
// ⚠️ THE RACE THIS DESIGN IS SHAPED AROUND
// The restart kills the process that has to report the result. SDP already
// documents the failure mode: on exit code 1641 the installer restarts the
// machine, the ACK loses the race, the job sits in `sent`, and the orchestrator
// re-runs the whole thing ~32 minutes later. The pattern that fixes it is the
// one `agent_update` and the self-install path already use — ACK FIRST, act
// second, and never claim in the ACK something the agent has not observed.
//
// So the caller must: send the ACK (which reports the real patch result and
// says a restart was scheduled), and only then arm the restart, with a grace
// long enough for that ACK to leave the machine.

/** Grace between the ACK and the restart. Enough for the ACK to flush. */
export const DEFAULT_REBOOT_GRACE_MS = 60_000;

export type PatchRebootReason =
  /** The operator did not ask for it. */
  | "not_requested"
  /** Nothing needs a restart. */
  | "not_required"
  /** This run installed nothing, so there is nothing of ours to complete. */
  | "nothing_installed"
  /** Go. */
  | "reboot_required";

export interface PatchRebootDecision {
  reboot: boolean;
  reason: PatchRebootReason;
  graceMs: number;
}

export interface PatchRebootInput {
  /** The operator's explicit opt-in, from the job payload. */
  rebootIfRequired: boolean;
  /** What the patch run reported. */
  rebootRequired: boolean;
  installedCount: number;
  failedCount: number;
  graceMs?: number;
}

/**
 * Decide whether this patch run restarts the machine.
 *
 * A PARTIAL run still restarts (product decision, 2026-09-10): what did install
 * is not applied until the restart, so stopping half-way leaves the endpoint
 * neither patched nor restarted — the worst of the three outcomes. The failures
 * stay visible in the ACK's own counts, and a failed patch keeps its snapshot
 * by the retention rule, so nothing is hidden by restarting.
 *
 * A run that installed NOTHING never restarts, even when the machine reports a
 * pending reboot. That pending flag belongs to some earlier change, and
 * restarting a production server on the strength of somebody else's leftover —
 * when the operator's own action did nothing — is exactly the surprise this
 * feature must not produce. It stays visible as `rebootRequired` for whoever
 * owns that change.
 */
export function planPatchReboot(input: PatchRebootInput): PatchRebootDecision {
  const graceMs = Math.max(0, input.graceMs ?? DEFAULT_REBOOT_GRACE_MS);
  const no = (reason: PatchRebootReason): PatchRebootDecision => ({ reboot: false, reason, graceMs });

  if (!input.rebootIfRequired) return no("not_requested");
  if (!input.rebootRequired) return no("not_required");
  if (!(input.installedCount > 0)) return no("nothing_installed");

  return { reboot: true, reason: "reboot_required", graceMs };
}

/**
 * The platform's restart command.
 *
 * No PrivSvc hop: AgentCore runs as LocalSystem on Windows (see
 * `wix/AgentCoreFiles.wxs`) and as root on Linux/macOS, so it already holds the
 * privilege. Routing this through the IPC lane would put a restart behind the
 * same serial queue that a 95-minute patch install occupies.
 *
 * The delay is handed to the OS rather than slept in the agent on purpose: once
 * the command returns, the restart is the operating system's commitment, and it
 * survives the agent being stopped, updated or crashing in the meantime.
 */
export function rebootCommandFor(
  platform: NodeJS.Platform,
  delaySeconds: number,
  comment = "Tracenium: completing patch installation"
): { cmd: string; args: string[] } {
  const secs = Math.max(0, Math.trunc(delaySeconds));
  switch (platform) {
    case "win32":
      // /r restart, /t delay, /c comment (shown to signed-in users), /d planned.
      return { cmd: "shutdown", args: ["/r", "/t", String(secs), "/c", comment, "/d", "p:2:17"] };
    case "darwin":
      // macOS `shutdown -r` takes minutes or +N; seconds are not expressible,
      // so round UP to the next whole minute rather than restarting early.
      return { cmd: "shutdown", args: ["-r", `+${Math.ceil(secs / 60)}`] };
    default:
      // util-linux `shutdown -r +N` (minutes), same rounding.
      return { cmd: "shutdown", args: ["-r", `+${Math.ceil(secs / 60)}`, comment] };
  }
}

/** Cancel a restart the OS has already accepted. */
export function rebootCancelCommandFor(platform: NodeJS.Platform): { cmd: string; args: string[] } {
  return platform === "win32"
    ? { cmd: "shutdown", args: ["/a"] }
    : { cmd: "shutdown", args: ["-c"] };
}

/** The ACK suffix that tells the control plane a restart is on its way. */
export function rebootAckSuffix(d: PatchRebootDecision): string {
  return d.reboot ? `; rebootScheduled=true; rebootInSec=${Math.round(d.graceMs / 1000)}` : "";
}

// ── Reinicio bajo demanda (job `device_reboot`, 17-sep) ─────────────────────
//
// El CUÁNDO lo decidió el control plane: si el operador eligió «maintenance
// window», el job no llega hasta que la ventana abre (y el despachador vuelve a
// comprobarla al entregarlo). Aquí sólo se valida la forma y se arma el reinicio
// con la misma mecánica que tras un parche: temporizador del SO, aviso a los
// usuarios conectados, cancelable con `shutdown /a`.

export const DEVICE_REBOOT_DEFAULT_DELAY_S = 60;

export type DeviceRebootPlan =
  | { ok: true; graceMs: number; comment: string }
  | { ok: false; error: string };

/** Lo que ven los usuarios conectados en el aviso de Windows. Sin comillas ni controles. */
function sanitizeReason(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw.replace(/[\u0000-\u001f"]/g, " ").replace(/\s+/g, " ").trim().slice(0, 120);
}

export function planDeviceReboot(payload: unknown): DeviceRebootPlan {
  const p = payload as any;
  if (!p || typeof p !== "object" || Array.isArray(p)) return { ok: false, error: "invalid payload" };
  // Mismo contrato que el backend: `when` obligatorio. Un job sin él viene de
  // algo que no pasó por la puerta de la ventana, y no se ejecuta.
  if (p.when !== "maintenance_window" && p.when !== "now") return { ok: false, error: "missing when" };
  let delay = DEVICE_REBOOT_DEFAULT_DELAY_S;
  if (p.delaySeconds != null) {
    if (!Number.isInteger(p.delaySeconds) || p.delaySeconds < 30 || p.delaySeconds > 600) {
      return { ok: false, error: "invalid delaySeconds" };
    }
    delay = p.delaySeconds;
  }
  const reason = sanitizeReason(p.reason);
  return {
    ok: true,
    graceMs: delay * 1000,
    comment: `Tracenium: restart requested by your IT administrator${reason ? ` (${reason})` : ""}`,
  };
}
