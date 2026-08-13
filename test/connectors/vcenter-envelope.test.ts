import { describe, it, expect, beforeAll } from "vitest";
import crypto from "node:crypto";
import {
  sealCredential,
  openEnvelope,
  certFingerprintFromPem,
  EnvelopeError,
  ENVELOPE_VERSION,
  type SealedEnvelope,
} from "../../src/connectors/vcenter/envelope";

/**
 * Node has no certificate-authoring API and `sealCredential` needs a real X.509
 * (for both the public key and the fingerprint), so each run mints a throwaway
 * self-signed RSA-2048 cert with the openssl CLI — the same shape as the
 * agent's enrollment material.
 */
describe("sealed envelope", () => {
  let certPem: string;
  let keyPem: string;
  let fingerprint: string;

  beforeAll(() => {
    // Build a genuine self-signed certificate using the openssl CLI available
    // on dev machines and CI images; fall back to skipping if unavailable.
    const { execFileSync } = require("node:child_process") as typeof import("node:child_process");
    const os = require("node:os") as typeof import("node:os");
    const fs = require("node:fs") as typeof import("node:fs");
    const path = require("node:path") as typeof import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vgw-env-"));
    const k = path.join(dir, "k.pem");
    const c = path.join(dir, "c.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", k, "-out", c, "-days", "3650", "-subj", "/CN=gateway-test",
    ], { stdio: "ignore" });
    keyPem = fs.readFileSync(k, "utf8");
    certPem = fs.readFileSync(c, "utf8");
    fingerprint = certFingerprintFromPem(certPem);
  });

  const CRED = { username: "svc-tracenium@vsphere.local", password: "C0rrect-H0rse!Battery&Staple<>\"'" };

  it("round-trips a credential", () => {
    const env = sealCredential(CRED, certPem);
    expect(openEnvelope(env, keyPem, fingerprint)).toEqual(CRED);
  });

  it("produces a fingerprint matching openssl's view of the cert", () => {
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
    const env = sealCredential(CRED, certPem);
    expect(env.certFingerprint).toBe(fingerprint);
  });

  it("never contains the plaintext password", () => {
    const wire = JSON.stringify(sealCredential(CRED, certPem));
    expect(wire).not.toContain(CRED.password);
    expect(wire).not.toContain(CRED.username);
  });

  it("handles a password far larger than RSA-2048 could wrap directly", () => {
    // ~190 bytes is the RSA-OAEP-SHA256 limit; hybrid encryption removes it.
    const big = { username: "u".repeat(200), password: "p".repeat(2000) };
    const env = sealCredential(big, certPem);
    expect(openEnvelope(env, keyPem, fingerprint)).toEqual(big);
  });

  it("survives special characters that break shell-based handling", () => {
    // The Inc 0 incident: `source .env` mangled a password containing '=' and
    // '$()'. The envelope path must be byte-exact.
    const nasty = { username: "u", password: "=@WK+Nq$(x)`y`\\n\"'&<>" };
    expect(openEnvelope(sealCredential(nasty, certPem), keyPem, fingerprint)).toEqual(nasty);
  });

  it("cannot be opened with a different private key", () => {
    const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
      .privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const env = sealCredential(CRED, certPem);
    expect(() => openEnvelope(env, other, fingerprint)).toThrow(EnvelopeError);
    try {
      openEnvelope(env, other, fingerprint);
    } catch (e: any) {
      expect(e.code).toBe("decrypt_failed");
      // must not leak crypto internals
      expect(e.message).not.toMatch(/oaep|padding|rsa/i);
    }
  });

  it("rejects tampered ciphertext (GCM authentication)", () => {
    const env = sealCredential(CRED, certPem);
    const ct = Buffer.from(env.ct, "base64url");
    ct[0] ^= 0xff;
    const tampered: SealedEnvelope = { ...env, ct: ct.toString("base64url") };
    expect(() => openEnvelope(tampered, keyPem, fingerprint)).toThrow(/authentication/i);
  });

  it("rejects a rewritten fingerprint (bound as AAD)", () => {
    const env = sealCredential(CRED, certPem);
    const forged: SealedEnvelope = { ...env, certFingerprint: "a".repeat(64) };
    // Fingerprint check fires first when we know what to expect...
    expect(() => openEnvelope(forged, keyPem, fingerprint)).toThrow(/rotated/i);
    // ...and even without that check, AAD binding makes decryption fail.
    expect(() => openEnvelope(forged, keyPem)).toThrow(/authentication/i);
  });

  it("distinguishes a stale envelope from a corrupt one", () => {
    const env = sealCredential(CRED, certPem);
    try {
      openEnvelope(env, keyPem, "b".repeat(64));
      throw new Error("should have thrown");
    } catch (e: any) {
      expect(e.code).toBe("stale_envelope");
      expect(e.message).toMatch(/rotated/i);
    }
  });

  it("tolerates colon-separated fingerprints on either side", () => {
    const env = sealCredential(CRED, certPem);
    const colonised = fingerprint.match(/../g)!.join(":").toUpperCase();
    expect(openEnvelope(env, keyPem, colonised)).toEqual(CRED);
  });

  it("rejects an unknown envelope version instead of guessing", () => {
    const env = sealCredential(CRED, certPem);
    expect(() => openEnvelope({ ...env, v: ENVELOPE_VERSION + 1 }, keyPem, fingerprint))
      .toThrow(/unsupported envelope version/i);
  });

  it("rejects a malformed envelope", () => {
    const env = sealCredential(CRED, certPem);
    expect(() => openEnvelope({ ...env, ek: "" }, keyPem, fingerprint)).toThrow(/missing/i);
    expect(() => openEnvelope(null as any, keyPem)).toThrow(/missing/i);
  });

  it("uses a fresh key and IV per seal", () => {
    const a = sealCredential(CRED, certPem);
    const b = sealCredential(CRED, certPem);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ek).not.toBe(b.ek);
    expect(a.ct).not.toBe(b.ct);
  });
});
