// test/privsvc/macos-pwpolicy-parse.test.ts
//
// macOS password policy via `pwpolicy -getaccountpolicies` (platform
// parity — Linux has login.defs/pwquality, Windows gets secedit).
// Pins both real-world forms of minimumLength, strictest-wins when
// several policies apply, and absent≠compliant for anything we don't
// positively recognize.

import { describe, it, expect } from "vitest";
import { parsePwpolicyMinimumLength } from "../../privsvc/macos/src/pwpolicy-parse";

// Verbatim from the field (JPR-MacBookPro, 2026-08-19) — the OS-default
// regex policy every unmanaged Mac carries.
const DEFAULT_POLICY = `Getting global account policies
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>policyCategoryPasswordContent</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '.{4,}+'</string>
		</dict>
	</array>
</dict>
</plist>`;

// The parameterized form MDM / pwpolicy -setaccountpolicies writes.
const MDM_POLICY = `<dict>
	<key>policyContent</key>
	<string>policyAttributePassword matches '^.{12,}$'</string>
	<key>policyParameters</key>
	<dict>
		<key>minimumLength</key>
		<integer>12</integer>
	</dict>
</dict>`;

describe("parsePwpolicyMinimumLength", () => {
  it("OS-default regex form → its lower bound (4)", () => {
    expect(parsePwpolicyMinimumLength(DEFAULT_POLICY)).toBe(4);
  });

  it("MDM policyParameters integer form", () => {
    expect(parsePwpolicyMinimumLength("<key>minimumLength</key>\n<integer>14</integer>")).toBe(14);
  });

  it("both forms present → strictest (max) wins, like loginwindow enforcement", () => {
    expect(parsePwpolicyMinimumLength(DEFAULT_POLICY + MDM_POLICY)).toBe(12);
  });

  it("regex variants: with and without the trailing +, anchored", () => {
    expect(parsePwpolicyMinimumLength("policyAttributePassword matches '.{8,}'")).toBe(8);
    expect(parsePwpolicyMinimumLength("policyAttributePassword matches '^.{15,}$'")).toBe(15);
  });

  it("the blank-allowed default ('^$|.{4,}+', field 2026-08-23) is minimum 0, not 4", () => {
    // `^$` as an alternative means the empty password satisfies the
    // policy — the effective minimum is zero. Two Macs in the fleet
    // carry exactly this shape.
    expect(parsePwpolicyMinimumLength("<string>policyAttributePassword matches '^$|.{4,}+'</string>")).toBe(0);
    // …and it stays 0 even when a looser-looking bound follows; the
    // MDM integer still wins when present (strictest = max).
    expect(
      parsePwpolicyMinimumLength(
        "policyAttributePassword matches '^$|.{4,}+'\n<key>minimumLength</key><integer>12</integer>"
      )
    ).toBe(12);
  });

  it("unrecognized policies → undefined, never a guess (absent ≠ compliant)", () => {
    for (const v of [
      "",
      null,
      undefined,
      "Getting global account policies",
      // A policy regex we don't understand must not mint a verdict.
      "policyAttributePassword matches '[A-Z]+[0-9]+'",
      "pwpolicy: unable to get policies",
    ]) {
      expect(parsePwpolicyMinimumLength(v as any), String(v)).toBeUndefined();
    }
  });
});
