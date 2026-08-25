// test/privsvc/macos-patch-security-like.test.ts
//
// Which pending softwareupdate items count as SECURITY updates on
// macOS. Feeds macos.updates.no_pending_security_updates — a miss is
// a false PASS. Field finding 2026-08-23: "macOS Tahoe 26.6.2" pending
// on every Mac, all counted as non-security → check passed.

import { describe, it, expect } from "vitest";
import { isSecurityLike } from "../../privsvc/macos/src/patch-management";

const item = (label: string, title?: string) => ({ label, title });

describe("macOS isSecurityLike", () => {
  it("OS point releases are security updates (that's how Apple ships CVE fixes now)", () => {
    expect(isSecurityLike(item("macOS Tahoe 26.6.2-26G5049", "macOS Tahoe 26.6.2"))).toBe(true);
    expect(isSecurityLike(item("macOS Ventura 13.6.7-22G720", "macOS Ventura 13.6.7"))).toBe(true);
    expect(isSecurityLike(item("macOS 15.1", "macOS 15.1"))).toBe(true);
  });

  it("explicit security content still matches", () => {
    expect(isSecurityLike(item("Security Update 2023-004", "Security Update 2023-004"))).toBe(true);
    expect(isSecurityLike(item("XProtectPlistConfigData_10_15-2188", "XProtect"))).toBe(true);
    expect(isSecurityLike(item("MRTConfigData_10_15-1.93", "MRT"))).toBe(true);
  });

  it("developer tooling and third-party items are not security updates", () => {
    expect(isSecurityLike(item("Command Line Tools for Xcode-26.6", "Command Line Tools for Xcode 26.6"))).toBe(false);
    expect(isSecurityLike(item("Xcode-26.5", "Xcode 26.5"))).toBe(false);
    // "macOS" as a platform tag inside a third-party title must not match.
    expect(isSecurityLike(item("Pro Video Formats 2.3", "Pro Video Formats for macOS 2.3"))).toBe(false);
  });
});
