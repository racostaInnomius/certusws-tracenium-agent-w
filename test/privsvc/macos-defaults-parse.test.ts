// test/privsvc/macos-defaults-parse.test.ts
//
// macOS hardening (Sprint 4 item 9) — the shared `defaults read` parser.
// Pins the bug that silently killed screen_lock + all softwareUpdate
// checks on MDM-managed Macs (bool forms not accepted) and the
// absent-vs-failed distinction that closes the guest/smb1 fail-open.

import { describe, it, expect } from "vitest";
import {
  parseDefaultsBool,
  parseDefaultsInt,
  classifyDefaultsRead,
  boolFromDefaultsRead,
} from "../../privsvc/macos/src/defaults-parse";

describe("parseDefaultsBool", () => {
  it("accepts GUI ints, MDM/-bool booleans and legacy YES/NO, any case", () => {
    for (const v of ["1", "true", "TRUE", "yes", "YES", " True \n"]) expect(parseDefaultsBool(v), v).toBe(true);
    for (const v of ["0", "false", "False", "no", "NO"]) expect(parseDefaultsBool(v), v).toBe(false);
  });
  it("anything else is undefined (never a guess)", () => {
    for (const v of ["", "2", "on", "enabled", "(1)", null, undefined]) expect(parseDefaultsBool(v as any)).toBeUndefined();
  });
});

describe("parseDefaultsInt", () => {
  it("parses plain integers only", () => {
    expect(parseDefaultsInt("900")).toBe(900);
    expect(parseDefaultsInt("-1")).toBe(-1);
    expect(parseDefaultsInt("1.5")).toBeUndefined();
    expect(parseDefaultsInt("uint32 5")).toBeUndefined();
  });
});

describe("classifyDefaultsRead", () => {
  it("ok → value", () => {
    expect(classifyDefaultsRead({ ok: true, output: "1" })).toBe("value");
  });
  it("non-zero with 'does not exist' → absent (both Apple phrasings)", () => {
    expect(classifyDefaultsRead({ ok: false, output: "2026-08-16 defaults[1]: The domain/default pair of (/Library/Preferences/com.apple.loginwindow, GuestEnabled) does not exist" })).toBe("absent");
    expect(classifyDefaultsRead({ ok: false, output: "Domain com.apple.screensaver does not exist" })).toBe("absent");
  });
  it("non-zero with anything else → failed", () => {
    expect(classifyDefaultsRead({ ok: false, output: "Operation not permitted" })).toBe("failed");
    expect(classifyDefaultsRead({ ok: false, output: "" })).toBe("failed");
  });
});

describe("boolFromDefaultsRead — the fail-open fix", () => {
  it("value → parsed", () => {
    expect(boolFromDefaultsRead({ ok: true, output: "true", stdout: "true" }, false)).toBe(true);
  });
  it("absent → whenAbsent (false for GuestEnabled, undefined for screensaver)", () => {
    const absent = { ok: false, output: "… does not exist" };
    expect(boolFromDefaultsRead(absent, false)).toBe(false);
    expect(boolFromDefaultsRead(absent, undefined)).toBeUndefined();
  });
  it("FAILED read → undefined, never the whenAbsent default (no false PASS)", () => {
    const failed = { ok: false, output: "Operation not permitted" };
    expect(boolFromDefaultsRead(failed, false)).toBeUndefined();
  });
  it("prefers stdout over the combined stream when both exist", () => {
    expect(boolFromDefaultsRead({ ok: true, output: "1\nsome warning", stdout: "1" }, undefined)).toBe(true);
  });
});
