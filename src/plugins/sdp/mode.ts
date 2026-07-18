// src/plugins/sdp/mode.ts
//
// SDP — Phase 2. Deployment-mode decisions, factored out as PURE functions so
// the mode-specific branching in index.ts (which is otherwise wall-to-wall IPC)
// stays unit-testable.
//
// The backend (certusws-tracenium, deployments.service) sends `mode` in the
// job payload: install (default), reinstall, or uninstall. Each changes three
// decisions in the install pipeline:
//
//   1. pre-detect short-circuit — should we skip the work because the device is
//      already in the desired state?
//   2. which args to run — silentInstallArgs vs silentUninstallArgs.
//   3. post-detect expectation — after running, should the detection rule MATCH
//      (software present) or NOT match (software gone)?
//
// An unknown/absent mode falls back to "install" — the safest default and what
// an older backend that doesn't send `mode` implies.

export type DeploymentMode = "install" | "reinstall" | "uninstall";

export function parseMode(raw: unknown): DeploymentMode {
  return raw === "uninstall" || raw === "reinstall" ? raw : "install";
}

export interface PreDetectDecision {
  /** Skip download+run and ACK immediately (already in desired state). */
  shortCircuit: boolean;
  /** Outcome to report when short-circuiting. */
  outcome?: "already_installed";
  /** Short reason tag for the ACK. */
  reason?: string;
}

/**
 * Decide whether pre-detection lets us short-circuit.
 *   install:   already present (matched)  → already_installed, skip.
 *   reinstall: never short-circuit — the whole point is to re-run.
 *   uninstall: already absent (not matched) → already in desired state, skip.
 *              (We reuse the `already_installed` outcome to mean "already in the
 *              target state" so the backend enum/reducer need no new value.)
 */
export function preDetectDecision(mode: DeploymentMode, matched: boolean): PreDetectDecision {
  if (mode === "reinstall") return { shortCircuit: false };
  if (mode === "uninstall") {
    return matched
      ? { shortCircuit: false }
      : { shortCircuit: true, outcome: "already_installed", reason: "pre_detect_absent" };
  }
  // install
  return matched
    ? { shortCircuit: true, outcome: "already_installed", reason: "pre_detect_matched" }
    : { shortCircuit: false };
}

/** The args the runner should execute for this mode (undefined → runner default). */
export function argsForMode(
  mode: DeploymentMode,
  snapshot: { silentInstallArgs?: string | null; silentUninstallArgs?: string | null }
): string | undefined {
  const raw = mode === "uninstall" ? snapshot.silentUninstallArgs : snapshot.silentInstallArgs;
  return raw ?? undefined;
}

/**
 * Given the post-run detection result, is it a FAILURE?
 *   install/reinstall: the rule must MATCH afterwards (software present). A
 *                      non-match means the installer silently no-op'd.
 *   uninstall:         the rule must NOT match afterwards (software gone). A
 *                      match means the uninstall didn't take.
 */
export function postDetectIsFailure(mode: DeploymentMode, matched: boolean): boolean {
  return mode === "uninstall" ? matched : !matched;
}

/** The short reason tag for a post-detect failure, per mode. */
export function postDetectFailureReason(mode: DeploymentMode): string {
  return mode === "uninstall" ? "post_detect_still_present" : "post_detect_mismatch";
}

// ── Uninstall identity ────────────────────────────────────────────
//
// Uninstall is NOT a binary operation — you don't run the installer bytes in
// reverse. Each OS removes software by IDENTITY: Windows by MSI ProductCode or
// the registered UninstallString; macOS by bundle path / pkg receipt id; Linux
// by package name. That identity is exactly what the detection rule already
// encodes, so we derive it from the rule (falling back to snapshot fields).
//
// Returns null when the rule carries no removable identity (file_exists /
// command_exit — a presence probe with nothing to uninstall). The orchestrator
// treats null as a permanent `rejected` rather than guessing.

export interface UninstallIdentity {
  /** Windows MSI — `msiexec /x <productCode>`. */
  productCode?: string;
  /** Windows — ILIKE pattern to find the registered UninstallString. */
  displayNameLike?: string;
  /** macOS app bundle id — locate + remove /Applications/<App>.app. */
  bundleId?: string;
  /** macOS pkg receipt — `pkgutil --forget <pkgId>` (+ file cleanup). */
  pkgId?: string;
  /** Linux — `apt-get remove <name>` / `dnf remove <name>`. */
  packageName?: string;
}

export function identityForUninstall(rule: unknown): UninstallIdentity | null {
  if (!rule || typeof rule !== "object") return null;
  const r = rule as Record<string, any>;
  switch (r.type) {
    case "registry_uninstall": {
      const id: UninstallIdentity = {};
      if (typeof r.productCode === "string" && r.productCode.trim()) id.productCode = r.productCode.trim();
      if (typeof r.displayNameLike === "string" && r.displayNameLike.trim()) id.displayNameLike = r.displayNameLike.trim();
      return id.productCode || id.displayNameLike ? id : null;
    }
    case "bundle_version":
      return typeof r.bundleId === "string" && r.bundleId.trim() ? { bundleId: r.bundleId.trim() } : null;
    case "pkg_receipt":
      return typeof r.pkgId === "string" && r.pkgId.trim() ? { pkgId: r.pkgId.trim() } : null;
    case "dpkg_installed":
    case "rpm_installed":
      return typeof r.packageName === "string" && r.packageName.trim()
        ? { packageName: r.packageName.trim() }
        : null;
    // file_exists / command_exit: a presence probe with no removable identity.
    default:
      return null;
  }
}
