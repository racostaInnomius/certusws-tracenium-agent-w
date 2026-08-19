// test/plugins/sdp-reboot.test.ts
//
// Reboot semantics for SDP. These are pure functions precisely so the Windows
// exit codes can be exercised from any host — the orchestrator's platform-fit
// check makes an end-to-end Windows install untestable on a macOS/Linux dev box
// or CI runner, and the codes that matter most (3010/1641) are Windows-only.

import { describe, expect, it } from "vitest";
import {
  EXIT_REBOOT_INITIATED,
  EXIT_REBOOT_REQUIRED,
  decideReboot,
  rebootExitCodesFor,
  shouldSkipPostDetect,
  withRebootExitCodes,
} from "../../src/plugins/sdp/reboot";

const base = {
  platform: "windows" as const,
  exitCode: 0 as number | undefined,
  packageRequiresReboot: false as unknown,
  mode: "install" as const,
};

describe("decideReboot — exit-code evidence", () => {
  it("treats 3010 as reboot required, not yet started", () => {
    const d = decideReboot({ ...base, exitCode: EXIT_REBOOT_REQUIRED });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("exit_reboot_required");
    expect(d.rebootInProgress).toBe(false);
  });

  it("treats 1641 as reboot already under way", () => {
    const d = decideReboot({ ...base, exitCode: EXIT_REBOOT_INITIATED });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("exit_reboot_initiated");
    expect(d.rebootInProgress).toBe(true);
  });

  it("reports no reboot for a plain success", () => {
    expect(decideReboot({ ...base, exitCode: 0 })).toEqual({
      rebootRequired: false,
      rebootInProgress: false,
    });
  });

  // The regression this module exists to fix: 3010 is a Windows Installer code.
  // On a .pkg or a .deb it is an arbitrary number the maintainer chose, and
  // reading reboot intent into it invents a meaning the package never assigned.
  it.each(["macos", "linux"] as const)("does not read 3010 as reboot on %s", (platform) => {
    const d = decideReboot({ ...base, platform, exitCode: EXIT_REBOOT_REQUIRED });
    expect(d.rebootRequired).toBe(false);
  });

  it.each(["macos", "linux"] as const)("does not read 1641 as reboot on %s", (platform) => {
    expect(decideReboot({ ...base, platform, exitCode: EXIT_REBOOT_INITIATED }).rebootRequired).toBe(
      false
    );
  });
});

describe("decideReboot — catalog declaration", () => {
  // The whole point of the change: requires_reboot was shipped to the agent on
  // every dispatch and read by nobody.
  it("honours requiresReboot when the exit code carries no reboot meaning", () => {
    const d = decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("package_requires_reboot");
    expect(d.rebootInProgress).toBe(false);
  });

  it.each(["windows", "macos", "linux"] as const)(
    "honours requiresReboot on %s — the flag is platform-independent",
    (platform) => {
      const d = decideReboot({ ...base, platform, exitCode: 0, packageRequiresReboot: true });
      expect(d.rebootRequired).toBe(true);
      expect(d.reason).toBe("package_requires_reboot");
    }
  );

  it("still honours requiresReboot when the runner reported no exit code", () => {
    const d = decideReboot({ ...base, exitCode: undefined, packageRequiresReboot: true });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("package_requires_reboot");
  });

  // Strict === true. The flag arrives as untyped JSON from the job payload; a
  // truthy-but-wrong value means the sender is confused, and guessing on its
  // behalf would silently mark installs reboot-pending.
  it.each([["true"], [1], ["yes"], [{}]])("ignores a non-boolean %p", (value) => {
    expect(
      decideReboot({ ...base, exitCode: 0, packageRequiresReboot: value }).rebootRequired
    ).toBe(false);
  });

  it("does not apply the flag to an uninstall — it is a claim about installing", () => {
    const d = decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true, mode: "uninstall" });
    expect(d.rebootRequired).toBe(false);
  });

  it("still applies exit-code evidence to an uninstall (msiexec /x returns 3010 too)", () => {
    const d = decideReboot({
      ...base,
      exitCode: EXIT_REBOOT_REQUIRED,
      packageRequiresReboot: false,
      mode: "uninstall",
    });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("exit_reboot_required");
  });

  it("applies the flag to a reinstall", () => {
    const d = decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true, mode: "reinstall" });
    expect(d.rebootRequired).toBe(true);
  });
});

describe("decideReboot — precedence", () => {
  // Observed beats declared: the exit code describes THIS run, the flag is a
  // claim someone typed. The reason field has to say which one spoke.
  it("prefers the exit code over the catalog flag", () => {
    const d = decideReboot({
      ...base,
      exitCode: EXIT_REBOOT_INITIATED,
      packageRequiresReboot: true,
    });
    expect(d.reason).toBe("exit_reboot_initiated");
    expect(d.rebootInProgress).toBe(true);
  });
});

describe("withRebootExitCodes", () => {
  it("adds both Windows reboot codes to an operator list that omits them", () => {
    expect(withRebootExitCodes([0], "windows")).toEqual([0, 3010, 1641]);
  });

  // The catalog default is [0, 3010], so in practice the widening usually adds
  // only 1641 — the code that made a successful reboot-initiating install read
  // as a permanent failure.
  it("adds only what is missing, without duplicating", () => {
    expect(withRebootExitCodes([0, 3010], "windows")).toEqual([0, 3010, 1641]);
  });

  it("leaves a list that already covers both untouched", () => {
    const input = [0, 1641, 3010];
    expect(withRebootExitCodes(input, "windows")).toBe(input);
  });

  it.each(["macos", "linux"] as const)("does not widen on %s", (platform) => {
    const input = [0, 3010];
    expect(withRebootExitCodes(input, platform)).toBe(input);
  });

  it("preserves the operator's other codes", () => {
    expect(withRebootExitCodes([0, 1605, 3010], "windows")).toEqual([0, 1605, 3010, 1641]);
  });
});

describe("rebootExitCodesFor", () => {
  it("covers Windows only", () => {
    expect(rebootExitCodesFor("windows")).toEqual([3010, 1641]);
    expect(rebootExitCodesFor("macos")).toEqual([]);
    expect(rebootExitCodesFor("linux")).toEqual([]);
  });
});

describe("shouldSkipPostDetect", () => {
  // Probing a machine that is tearing down services would grade a shutdown
  // artifact as post_detect_mismatch and turn a success into a permanent
  // failure. A 3010 machine is still up, so the silent-no-op check stays.
  it("skips only when the reboot has already started", () => {
    expect(
      shouldSkipPostDetect(decideReboot({ ...base, exitCode: EXIT_REBOOT_INITIATED }))
    ).toBe(true);
    expect(
      shouldSkipPostDetect(decideReboot({ ...base, exitCode: EXIT_REBOOT_REQUIRED }))
    ).toBe(false);
    expect(shouldSkipPostDetect(decideReboot({ ...base, exitCode: 0 }))).toBe(false);
    expect(
      shouldSkipPostDetect(
        decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true })
      )
    ).toBe(false);
  });
});
