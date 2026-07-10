// test/plugins/sdp-mode.test.ts

import { describe, expect, it } from "vitest";
import {
  parseMode,
  preDetectDecision,
  argsForMode,
  postDetectIsFailure,
  postDetectFailureReason,
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
