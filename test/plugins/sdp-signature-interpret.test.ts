// test/plugins/sdp-signature-interpret.test.ts
//
// The macOS/Linux signature verifiers shell out to pkgutil / codesign / rpm /
// dpkg-sig, but the trust DECISION is factored into pure functions so it can be
// tested without a real signed artifact. These are the fail-closed gate's brain:
// anything but an explicit "signed + trusted" must return trusted:false.

import { describe, expect, it } from "vitest";
import { interpretPkgutilSignature } from "../../privsvc/macos/src/sdp";
import { interpretRpmVerify, interpretDpkgSig } from "../../privsvc/linux/src/sdp";

describe("interpretPkgutilSignature (macOS pkg)", () => {
  it("trusts an Apple Developer ID installer signature", () => {
    const out = "Package Signature:\n   Status: signed by a developer certificate issued by Apple for distribution\n";
    expect(interpretPkgutilSignature(0, out)).toEqual({ trusted: true, reason: "pkgutil_signed" });
  });
  it("rejects an unsigned package", () => {
    expect(interpretPkgutilSignature(1, "   Status: no signature\n").trusted).toBe(false);
  });
  it("rejects an ad-hoc signature (not a trusted chain)", () => {
    const r = interpretPkgutilSignature(0, "   Status: signed Ad-hoc\n");
    expect(r.trusted).toBe(false);
  });
  it("rejects empty / garbled output fail-closed", () => {
    expect(interpretPkgutilSignature(1, "").trusted).toBe(false);
  });
});

describe("interpretRpmVerify (Linux rpm)", () => {
  it("trusts a good pgp signature", () => {
    expect(interpretRpmVerify(0, "pkg.rpm: digests signatures OK").trusted).toBe(true);
  });
  it("rejects NOKEY (signed but key not imported)", () => {
    expect(interpretRpmVerify(1, "pkg.rpm: digests SIGNATURES NOKEY")).toEqual({
      trusted: false,
      reason: "rpm_nokey",
    });
  });
  it("rejects a digest-only OK with no signature token", () => {
    expect(interpretRpmVerify(0, "pkg.rpm: digests OK").trusted).toBe(false);
  });
  it("rejects a bad signature", () => {
    expect(interpretRpmVerify(1, "pkg.rpm: digests SIGNATURES NOT OK").trusted).toBe(false);
  });
});

describe("interpretDpkgSig (Linux deb)", () => {
  it("trusts a GOODSIG", () => {
    expect(interpretDpkgSig(0, "Processing pkg.deb...\nGOODSIG _gpgbuilder ABC 12345")).toEqual({
      trusted: true,
      reason: "deb_goodsig",
    });
  });
  it("rejects BADSIG", () => {
    expect(interpretDpkgSig(1, "BADSIG _gpgbuilder").trusted).toBe(false);
  });
  it("rejects an unsigned deb", () => {
    expect(interpretDpkgSig(0, "No signatures").trusted).toBe(false);
  });
});
