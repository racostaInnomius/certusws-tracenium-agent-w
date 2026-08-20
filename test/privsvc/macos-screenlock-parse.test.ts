// test/privsvc/macos-screenlock-parse.test.ts
//
// macOS screen-lock via `sysadminctl -screenLock status` — the primary
// source since the field finding of 2026-08-19: modern macOS no longer
// writes `askForPassword`, so the defaults chain was structurally
// not_applicable on every unmanaged Mac. Pins the three real output
// shapes (which arrive on STDERR with a syslog prefix) and the
// absent≠compliant rule for anything unrecognized.

import { describe, it, expect } from "vitest";
import { parseSysadminctlScreenLock } from "../../privsvc/macos/src/screenlock-parse";

// Verbatim from the field (JPR-MacBookPro, macOS 2026-08-19). Note the
// syslog-style prefix and that this line arrives on stderr.
const IMMEDIATE = "2026-08-19 22:17:55.934 sysadminctl[55361:106849336] screenLock delay is immediate";
const DELAYED = "2026-08-19 22:18:01.101 sysadminctl[55402:106849400] screenLock delay is 300 seconds";
const OFF = "2026-08-19 22:18:05.500 sysadminctl[55440:106849455] screenLock is off";

describe("parseSysadminctlScreenLock", () => {
  it("'delay is immediate' → required, delay 0", () => {
    expect(parseSysadminctlScreenLock(IMMEDIATE)).toEqual({ passwordRequired: true, delaySeconds: 0 });
  });

  it("'delay is N seconds' → required, with the grace period", () => {
    expect(parseSysadminctlScreenLock(DELAYED)).toEqual({ passwordRequired: true, delaySeconds: 300 });
    expect(parseSysadminctlScreenLock("screenLock delay is 1 second")).toEqual({
      passwordRequired: true,
      delaySeconds: 1,
    });
  });

  it("'screenLock is off' → not required", () => {
    expect(parseSysadminctlScreenLock(OFF)).toEqual({ passwordRequired: false, delaySeconds: undefined });
  });

  it("anything unrecognized is undefined — never a verdict (absent ≠ compliant)", () => {
    for (const v of [
      "",
      null,
      undefined,
      "sysadminctl: unknown command",
      "usage: sysadminctl …",
      // sudo -n failing inside launchctl asuser must not read as 'off'.
      "sudo: a password is required",
    ]) {
      expect(parseSysadminctlScreenLock(v as any), String(v)).toBeUndefined();
    }
  });
});
