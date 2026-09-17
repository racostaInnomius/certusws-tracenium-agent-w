// src/plugins/pmp/reboot-exec.ts
//
// The impure half of the patch restart: hands the delay to the operating
// system. The decision lives in ./reboot.ts and is pure.
//
// WHY THE OS HOLDS THE TIMER, NOT US
// A `setTimeout` in the agent is a promise only this process can keep, and this
// process is the one most likely to be stopped in the next minute — by its own
// watchdog, by an auto-update, or by the very patch that just landed. Once
// `shutdown /r /t 60` returns, the restart belongs to the OS and survives all
// of that. It also gives the ACK its window to leave the machine without the
// agent having to stay alive to honour it.
//
// Arming happens BEFORE the ACK is returned, deliberately. The grace is what
// protects the ACK, so the ordering that matters is "OS timer armed, then ACK
// sent, then machine goes down" — not "wait, then arm", which would lose the
// restart entirely if the agent died during the wait.

import { execFile } from "child_process";
import { rebootCommandFor, rebootCancelCommandFor, type PatchRebootDecision } from "./reboot";

export interface RebootExecDeps {
  platform?: NodeJS.Platform;
  run?: (cmd: string, args: string[]) => Promise<{ ok: boolean; error?: string }>;
  logger?: { info?: (m: string, x?: any) => void; warn?: (m: string, x?: any) => void };
}

function defaultRun(cmd: string, args: string[]): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 15_000, windowsHide: true }, (err) => {
      resolve(err ? { ok: false, error: err.message } : { ok: true });
    });
  });
}

/**
 * Arm the restart the decision asked for. Returns whether the OS accepted it.
 *
 * Never throws: a patch that installed correctly must not be reported as failed
 * because the restart could not be scheduled. The ACK says a restart was
 * scheduled, so a failure here is logged loudly and the endpoint stays visible
 * as `rebootRequired` for a human.
 */
export async function armPatchReboot(
  decision: PatchRebootDecision,
  deps: RebootExecDeps = {}
): Promise<boolean> {
  if (!decision.reboot) return false;
  return armReboot(decision.graceMs, undefined, "patch restart", deps);
}

/** Reinicio bajo demanda (`device_reboot`). Misma mecánica y mismas garantías. */
export async function armDeviceReboot(
  plan: { graceMs: number; comment: string },
  deps: RebootExecDeps = {}
): Promise<boolean> {
  return armReboot(plan.graceMs, plan.comment, "on-demand restart", deps);
}

async function armReboot(
  graceMs: number,
  comment: string | undefined,
  label: string,
  deps: RebootExecDeps
): Promise<boolean> {
  const platform = deps.platform ?? process.platform;
  const run = deps.run ?? defaultRun;
  const { cmd, args } = rebootCommandFor(platform, Math.round(graceMs / 1000), comment);

  try {
    const r = await run(cmd, args);
    if (r.ok) {
      deps.logger?.info?.(`${label} armed`, { cmd, args, graceMs });
      return true;
    }
    deps.logger?.warn?.(`${label} could NOT be armed — the endpoint stays pending reboot`, {
      cmd,
      args,
      error: r.error,
    });
    return false;
  } catch (e: any) {
    deps.logger?.warn?.(`${label} could NOT be armed — the endpoint stays pending reboot`, {
      error: e?.message ?? String(e),
    });
    return false;
  }
}

/** Best-effort cancel, for an operator or a caller that changed its mind. */
export async function cancelPatchReboot(deps: RebootExecDeps = {}): Promise<boolean> {
  const platform = deps.platform ?? process.platform;
  const run = deps.run ?? defaultRun;
  const { cmd, args } = rebootCancelCommandFor(platform);
  try {
    return (await run(cmd, args)).ok;
  } catch {
    return false;
  }
}
