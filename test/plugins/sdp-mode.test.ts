// test/plugins/sdp-mode.test.ts

import { describe, expect, it } from "vitest";
import {
  parseMode,
  preDetectDecision,
  argsForMode,
  postDetectIsFailure,
  postDetectFailureReason,
  identityForUninstall,
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
