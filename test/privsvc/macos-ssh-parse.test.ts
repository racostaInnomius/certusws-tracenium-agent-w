// test/privsvc/macos-ssh-parse.test.ts
//
// Unit coverage for the macOS sshd -T parser. Same evidence shape as the Linux
// ssh collector (that's the point — shared catalog rules), so we verify the
// crypto-relevant lists parse into arrays and empty/noise output → unknown.

import { describe, it, expect } from "vitest";
import { parseSshdConfig } from "../../privsvc/macos/src/ssh-parse";

// A representative subset of `sshd -T` output (key value, space-separated).
const SSHD_T = [
  "port 22",
  "permitrootlogin no",
  "passwordauthentication no",
  "pubkeyauthentication yes",
  "permitemptypasswords no",
  "kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512",
  "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr",
  "macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
  "logingracetime 120",
  "maxauthtries 6",
  "x11forwarding no",
].join("\n");

describe("parseSshdConfig", () => {
  it("parses the crypto lists into arrays and the scalar fields", () => {
    const ev = parseSshdConfig(SSHD_T);
    expect(ev.enabled).toBe(true);
    expect(ev.permitRootLogin).toBe("no");
    expect(ev.passwordAuthentication).toBe(false);
    expect(ev.ciphers).toEqual(["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"]);
    expect(ev.macs).toHaveLength(2);
    expect(ev.kexAlgorithms?.[0]).toBe("curve25519-sha256");
    expect(ev.loginGraceTime).toBe(120);
    expect(ev.maxAuthTries).toBe(6);
    expect(ev.x11Forwarding).toBe(false);
  });

  it("returns unknown for empty or non-config output", () => {
    expect(parseSshdConfig("").enabled).toBe("unknown");
    expect(parseSshdConfig("sshd: no hostkeys available -- exiting.").enabled).toBe("unknown");
  });
});
