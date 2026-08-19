// test/privsvc/screen-lock-parse.test.ts
//
// Linux screen-lock evidence (Sprint 4 — platform parity): dconf system
// policy fragments + locks. Pins keyfile merge order, GVariant literal
// parsing, the locked-key semantics CIS wants, and absent≠compliant.

import { describe, it, expect } from "vitest";
import {
  parseDconfKeyfiles,
  parseDconfLocks,
  parseGVariantBool,
  parseGVariantUint,
  buildScreenLockEvidence,
} from "../../privsvc/linux/src/screen-lock-parse";

const CIS_FRAGMENT = `
# CIS Ubuntu 22.04 §1.8.4 / §1.8.5
[org/gnome/desktop/session]
idle-delay=uint32 900

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 5
`;

const CIS_LOCKS = `
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
`;

describe("GVariant literals", () => {
  it("bool", () => {
    expect(parseGVariantBool("true")).toBe(true);
    expect(parseGVariantBool("False")).toBe(false);
    expect(parseGVariantBool("yes")).toBeUndefined();
    expect(parseGVariantBool(undefined)).toBeUndefined();
  });
  it("uint32 with and without the type prefix", () => {
    expect(parseGVariantUint("uint32 900")).toBe(900);
    expect(parseGVariantUint("900")).toBe(900);
    expect(parseGVariantUint("'900'")).toBeUndefined();
  });
});

describe("parseDconfKeyfiles", () => {
  it("flattens sections to section/key and ignores comments", () => {
    const kv = parseDconfKeyfiles([{ name: "00-screensaver", text: CIS_FRAGMENT }]);
    expect(kv.get("org/gnome/desktop/screensaver/lock-enabled")).toBe("true");
    expect(kv.get("org/gnome/desktop/session/idle-delay")).toBe("uint32 900");
  });
  it("later fragments (alphabetical) win, like dconf's merge", () => {
    const kv = parseDconfKeyfiles([
      { name: "99-override", text: "[org/gnome/desktop/screensaver]\nlock-enabled=false\n" },
      { name: "00-base", text: "[org/gnome/desktop/screensaver]\nlock-enabled=true\n" },
    ]);
    expect(kv.get("org/gnome/desktop/screensaver/lock-enabled")).toBe("false");
  });
});

describe("buildScreenLockEvidence", () => {
  it("full CIS setup → all facts present, locked flags reflect the locks/ fragment", () => {
    const ev = buildScreenLockEvidence({
      dconfDbExists: true,
      keyfiles: [{ name: "/etc/dconf/db/local.d/00-screensaver", text: CIS_FRAGMENT }],
      lockfiles: [{ name: "/etc/dconf/db/local.d/locks/screensaver", text: CIS_LOCKS }],
    });
    expect(ev).toMatchObject({
      available: true,
      lockEnabled: true,
      lockDelaySecs: 5,
      idleDelaySecs: 900,
      lockEnabledLocked: true,
      idleDelayLocked: true,
      lockDelayLocked: false, // set but not locked → user could change it
    });
    expect(ev.sourceFiles).toHaveLength(2);
  });

  it("policy present but no locks/ → locked flags omitted (not false)", () => {
    const ev = buildScreenLockEvidence({
      dconfDbExists: true,
      keyfiles: [{ name: "x", text: CIS_FRAGMENT }],
      lockfiles: [],
    });
    expect(ev.lockEnabled).toBe(true);
    expect(ev.lockEnabledLocked).toBeUndefined();
  });

  it("dconf present but no screen-lock policy → available, no facts (per-user config invisible to root)", () => {
    const ev = buildScreenLockEvidence({ dconfDbExists: true, keyfiles: [], lockfiles: [] });
    expect(ev).toEqual({ available: true });
  });

  it("no dconf at all (headless / non-GNOME) → available:false", () => {
    const ev = buildScreenLockEvidence({ dconfDbExists: false, keyfiles: [], lockfiles: [] });
    expect(ev).toEqual({ available: false });
  });

  it("explicit lock-enabled=false is a real fact, not an omission", () => {
    const ev = buildScreenLockEvidence({
      dconfDbExists: true,
      keyfiles: [{ name: "x", text: "[org/gnome/desktop/screensaver]\nlock-enabled=false\n" }],
      lockfiles: [],
    });
    expect(ev.lockEnabled).toBe(false);
  });
});

describe("parseDconfLocks", () => {
  it("strips the leading slash and skips comments/blank lines", () => {
    expect([...parseDconfLocks([{ name: "l", text: CIS_LOCKS }])]).toEqual([
      "org/gnome/desktop/session/idle-delay",
      "org/gnome/desktop/screensaver/lock-enabled",
    ]);
  });
});
