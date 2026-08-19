// test/plugins/sdp-mode.test.ts

import { describe, expect, it } from "vitest";
import {
  parseMode,
  preDetectDecision,
  argsForMode,
  postDetectIsFailure,
  postDetectFailureReason,
  identityForUninstall,
  skipIsTransient,
} from "../../src/plugins/sdp/mode";

describe("parseMode", () => {
  it("passes through reinstall and uninstall", () => {
    expect(parseMode("reinstall")).toBe("reinstall");
    expect(parseMode("uninstall")).toBe("uninstall");
  });
  it("defaults unknown / absent to install", () => {
    expect(parseMode("install")).toBe("install");
    expect(parseMode(undefined)).toBe("install");
    expect(parseMode(null)).toBe("install");
    expect(parseMode("delete")).toBe("install");
    expect(parseMode(42)).toBe("install");
  });
});

describe("preDetectDecision", () => {
  it("install: short-circuits when already present", () => {
    expect(preDetectDecision("install", true)).toEqual({
      shortCircuit: true,
      outcome: "already_installed",
      reason: "pre_detect_matched",
    });
    expect(preDetectDecision("install", false)).toEqual({ shortCircuit: false });
  });

  it("uninstall: short-circuits when already absent", () => {
    expect(preDetectDecision("uninstall", false)).toEqual({
      shortCircuit: true,
      outcome: "already_installed",
      reason: "pre_detect_absent",
    });
    // still present → must proceed to uninstall
    expect(preDetectDecision("uninstall", true)).toEqual({ shortCircuit: false });
  });

  // "we did not look" is not "it is absent". detection.ts returns
  // {matched:false, skipped:true} when it could not evaluate, and reading that
  // as absence made an uninstall report the desired end state for a machine it
  // never probed — leaving the software installed and the deployment green.
  it("uninstall: a rule that cannot apply here is a permanent rejection", () => {
    expect(
      preDetectDecision("uninstall", false, true, "rule_type_not_applicable_on_darwin")
    ).toEqual({
      shortCircuit: true,
      outcome: "rejected",
      reason: "pre_detect_inconclusive",
    });
    // The skip dominates whatever `matched` happens to carry.
    expect(
      preDetectDecision("uninstall", true, true, "rule_type_not_applicable_on_darwin").outcome
    ).toBe("rejected");
  });

  // The likelier trigger in this agent: privsvc timing out or erroring during
  // pre-detect. That is a statement about the IPC lane, not about the software,
  // so it must stay retryable.
  it("uninstall: a privsvc failure is transient, not a rejection", () => {
    expect(preDetectDecision("uninstall", false, true, "privsvc_error:timeout")).toEqual({
      shortCircuit: true,
      outcome: "failed",
      reason: "pre_detect_unavailable",
    });
    expect(
      preDetectDecision("uninstall", false, true, "privsvc_threw:socket hang up").outcome
    ).toBe("failed");
  });

  // No reason at all → treat as permanent. Guessing "retryable" on an unknown
  // cause is how a job loops forever.
  it("uninstall: an unattributed skip is permanent", () => {
    expect(preDetectDecision("uninstall", false, true).outcome).toBe("rejected");
    expect(preDetectDecision("uninstall", false, true, "no_rule").outcome).toBe("rejected");
  });

  it("install/reinstall: an inconclusive pre-detect falls through to doing the work", () => {
    // Safe direction — the install runs and its exit code is graded as usual.
    expect(preDetectDecision("install", false, true, "privsvc_error:timeout")).toEqual({
      shortCircuit: false,
    });
    expect(preDetectDecision("reinstall", false, true, "privsvc_error:timeout")).toEqual({
      shortCircuit: false,
    });
  });

  it("uninstall: a real (non-skipped) evaluation is unaffected", () => {
    expect(preDetectDecision("uninstall", false, false).outcome).toBe("already_installed");
    expect(preDetectDecision("uninstall", true, false).shortCircuit).toBe(false);
  });
});

describe("skipIsTransient", () => {
  it("treats privsvc failures as transient and everything else as permanent", () => {
    expect(skipIsTransient("privsvc_error:ipc_timeout")).toBe(true);
    expect(skipIsTransient("privsvc_threw:EPIPE")).toBe(true);
    expect(skipIsTransient("rule_type_not_applicable_on_win32")).toBe(false);
    expect(skipIsTransient("no_rule")).toBe(false);
    expect(skipIsTransient(undefined)).toBe(false);
    expect(skipIsTransient("")).toBe(false);
  });

  it("reinstall: never short-circuits", () => {
    expect(preDetectDecision("reinstall", true)).toEqual({ shortCircuit: false });
    expect(preDetectDecision("reinstall", false)).toEqual({ shortCircuit: false });
  });
});

describe("argsForMode", () => {
  const snap = { silentInstallArgs: "/qn", silentUninstallArgs: "/qn /x" };
  it("uses install args for install/reinstall", () => {
    expect(argsForMode("install", snap)).toBe("/qn");
    expect(argsForMode("reinstall", snap)).toBe("/qn");
  });
  it("uses uninstall args for uninstall", () => {
    expect(argsForMode("uninstall", snap)).toBe("/qn /x");
  });
  it("maps null/missing to undefined (runner default)", () => {
    expect(argsForMode("install", { silentInstallArgs: null })).toBeUndefined();
    expect(argsForMode("uninstall", {})).toBeUndefined();
  });
});

describe("postDetectIsFailure", () => {
  it("install/reinstall: failure when the rule does NOT match afterwards", () => {
    expect(postDetectIsFailure("install", false)).toBe(true); // absent → install failed
    expect(postDetectIsFailure("install", true)).toBe(false);
    expect(postDetectIsFailure("reinstall", false)).toBe(true);
    expect(postDetectIsFailure("reinstall", true)).toBe(false);
  });
  it("uninstall: failure when the rule STILL matches afterwards", () => {
    expect(postDetectIsFailure("uninstall", true)).toBe(true); // still present → uninstall failed
    expect(postDetectIsFailure("uninstall", false)).toBe(false); // gone → success
  });
});

describe("postDetectFailureReason", () => {
  it("distinguishes the two failure directions", () => {
    expect(postDetectFailureReason("install")).toBe("post_detect_mismatch");
    expect(postDetectFailureReason("uninstall")).toBe("post_detect_still_present");
  });
});

describe("identityForUninstall", () => {
  it("derives MSI productCode + displayNameLike from registry_uninstall", () => {
    expect(
      identityForUninstall({ type: "registry_uninstall", displayNameLike: "7-Zip%", productCode: "{GUID}" })
    ).toEqual({ productCode: "{GUID}", displayNameLike: "7-Zip%" });
  });
  it("keeps displayNameLike alone when no productCode (EXE uninstall path)", () => {
    expect(identityForUninstall({ type: "registry_uninstall", displayNameLike: "Foo%" })).toEqual({
      displayNameLike: "Foo%",
    });
  });
  it("derives bundleId (macOS) and pkgId (macOS)", () => {
    expect(identityForUninstall({ type: "bundle_version", bundleId: "com.x.app" })).toEqual({
      bundleId: "com.x.app",
    });
    expect(identityForUninstall({ type: "pkg_receipt", pkgId: "com.x.pkg" })).toEqual({ pkgId: "com.x.pkg" });
  });
  it("derives packageName from dpkg_installed / rpm_installed (Linux)", () => {
    expect(identityForUninstall({ type: "dpkg_installed", packageName: "nginx" })).toEqual({ packageName: "nginx" });
    expect(identityForUninstall({ type: "rpm_installed", packageName: "httpd" })).toEqual({ packageName: "httpd" });
  });
  it("returns null for rules with no removable identity", () => {
    expect(identityForUninstall({ type: "file_exists", path: "/opt/x" })).toBeNull();
    expect(identityForUninstall({ type: "command_exit", cmd: "/bin/x" })).toBeNull();
    expect(identityForUninstall(null)).toBeNull();
    expect(identityForUninstall(undefined)).toBeNull();
    // registry_uninstall with neither productCode nor displayNameLike
    expect(identityForUninstall({ type: "registry_uninstall" })).toBeNull();
  });
});
