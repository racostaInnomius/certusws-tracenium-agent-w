// src/plugins/sdp/reboot.ts
//
// SDP — reboot semantics, as PURE functions.
//
// Two independent facts can mean "this endpoint needs a reboot", and the
// orchestrator used to notice only one of them:
//
//   1. The installer said so, through its exit code.
//   2. The catalog said so, through `software_packages.requires_reboot`.
//
// (2) is edited in the UI, persisted, carried in `SoftwarePackageDto`, and
// shipped to the agent inside the package snapshot on every dispatch — and was
// read by nobody. (1) was recognised only as the literal 3010, on every
// platform, which had two consequences worth naming:
//
//   * `reboot_required` was structurally unreachable on macOS and Linux. 3010
//     is a Windows Installer code; on a .pkg or a .deb it is whatever number
//     the maintainer happened to pick.
//   * 1641 — "the reboot has already been started" — was either reported as a
//     plain `success` (when an operator listed it in expectedExitCodes, which
//     is what the AI intake generator suggests) or as `failed` with
//     `unexpected_exit_1641` (when they did not). Both are wrong, in opposite
//     directions, about a machine that is in the middle of going down.
//
// The whole downstream pipeline for `reboot_required` already exists and is
// correct — it is a valid outcome in the CHECK constraint, terminal in the
// result reducer, rolls up to a completed deployment, and has a column in the
// UI. It was simply almost never emitted.
//
// ⚠️ KNOWN LIMIT, not fixed here: on 1641 the machine is restarting, so the ACK
// carrying `reboot_required` races the shutdown. If it loses, the job stays in
// `sent` and the orchestrator's retry (~32 min) re-runs it; that run's
// pre-detect finds the software present and closes the row as
// `already_installed`. The install is correctly recorded either way, but the
// reboot signal is lost. Same shape as the self-install problem that
// SELF_INSTALL_ACK_REASON solves with an early ACK — the difference is that a
// self-install is knowable in advance and a 1641 is only knowable after the
// installer has already returned it. Closing it properly needs the backend to
// treat "job sent, device rebooted, software now present" as reboot evidence,
// which is a control-plane change, not an agent one.

import type { DeploymentMode } from "./mode";

/**
 * ERROR_SUCCESS_REBOOT_REQUIRED. The install finished; a reboot is needed to
 * complete it. Nothing is happening on its own — the machine stays up.
 */
export const EXIT_REBOOT_REQUIRED = 3010;

/**
 * ERROR_SUCCESS_REBOOT_INITIATED. The install finished AND the installer has
 * already started the restart. The machine is going down now.
 */
export const EXIT_REBOOT_INITIATED = 1641;

export type RebootReason =
  /** Installer returned 3010 — reboot needed, not started. */
  | "exit_reboot_required"
  /** Installer returned 1641 — reboot already under way. */
  | "exit_reboot_initiated"
  /** No exit-code evidence; the catalog declares this package needs one. */
  | "package_requires_reboot";

export interface RebootDecision {
  rebootRequired: boolean;
  reason?: RebootReason;
  /**
   * True only for 1641: the endpoint is actively restarting, so anything the
   * orchestrator does after this point races the shutdown. Used to skip
   * post-run detection — see shouldSkipPostDetect.
   */
  rebootInProgress: boolean;
}

/**
 * The exit codes that carry reboot meaning on this platform.
 *
 * Gated on Windows rather than on `format === "msi"` because EXE installers
 * built with WiX Burn, InnoSetup and friends wrap Windows Installer and return
 * the same codes; gating on the format would miss them. On macOS and Linux the
 * list is empty on purpose: there is no cross-vendor convention there, and
 * treating 3010 from a postinst script as "reboot required" would be inventing
 * a meaning the package never assigned it.
 */
export function rebootExitCodesFor(platform: "windows" | "macos" | "linux"): number[] {
  return platform === "windows" ? [EXIT_REBOOT_REQUIRED, EXIT_REBOOT_INITIATED] : [];
}

/**
 * Widen the operator's expected exit codes with the platform's reboot codes.
 *
 * Without this, 1641 falls outside `expectedExitCodes` (whose default is
 * [0, 3010]) and a successful install that restarted the machine is reported as
 * `failed` — permanently, since an unexpected exit code is ackStatus 2 and the
 * orchestrator does not retry it. Both codes are documented Windows Installer
 * SUCCESS codes, so recognising them is not second-guessing the operator: there
 * is no configuration under which "the install worked and asked for a reboot"
 * should read as a failure.
 *
 * Returns the input unchanged on non-Windows platforms and preserves order and
 * uniqueness so the value stays comparable to what the catalog holds.
 */
export function withRebootExitCodes(
  expected: number[],
  platform: "windows" | "macos" | "linux"
): number[] {
  const extra = rebootExitCodesFor(platform).filter((c) => !expected.includes(c));
  return extra.length === 0 ? expected : [...expected, ...extra];
}

/**
 * Decide whether this run leaves the endpoint needing a reboot.
 *
 * Precedence is observed-beats-declared: an exit code is something the
 * installer reported about THIS run, while the catalog flag is a claim someone
 * typed about the package in general. When the installer speaks, we believe it.
 *
 * The catalog flag is honoured only for install/reinstall. `requires_reboot`
 * means "installing this needs a reboot"; it is not evidence about removing it.
 * Applying it to uninstalls would mark every removal of that package as
 * reboot-pending whether or not one is actually needed — and the exit-code path
 * still catches the Windows uninstalls that genuinely do (msiexec /x returns
 * 3010 the same way /i does).
 */
export function decideReboot(input: {
  platform: "windows" | "macos" | "linux";
  /** Installer exit code. NaN/undefined when the runner reported none. */
  exitCode: number | undefined;
  /** `requiresReboot` from the package snapshot. Unknown shapes are falsy. */
  packageRequiresReboot: unknown;
  mode: DeploymentMode;
}): RebootDecision {
  const { platform, exitCode, packageRequiresReboot, mode } = input;
  const codes = rebootExitCodesFor(platform);
  const code = Number(exitCode);

  if (Number.isFinite(code) && codes.includes(code)) {
    return code === EXIT_REBOOT_INITIATED
      ? { rebootRequired: true, reason: "exit_reboot_initiated", rebootInProgress: true }
      : { rebootRequired: true, reason: "exit_reboot_required", rebootInProgress: false };
  }

  if (packageRequiresReboot === true && mode !== "uninstall") {
    return { rebootRequired: true, reason: "package_requires_reboot", rebootInProgress: false };
  }

  return { rebootRequired: false, rebootInProgress: false };
}

/**
 * Should post-run detection be skipped?
 *
 * Only when the installer has already initiated the restart. Detection is an
 * IPC round-trip into privsvc that shells out to the OS; running it against a
 * machine that is tearing down services returns whatever it happens to catch,
 * and a spurious non-match would be graded `post_detect_mismatch` — turning a
 * successful install into a permanent `failed`. Declining to probe is the
 * honest option: we report what the installer told us and let the device's next
 * inventory pass, after the reboot, establish the truth.
 *
 * A 3010 does NOT skip it. There the install is complete and the machine is
 * still up, so the silent-no-op check that post-detection exists for is exactly
 * as valuable as on any other install.
 */
export function shouldSkipPostDetect(decision: RebootDecision): boolean {
  return decision.rebootInProgress;
}
