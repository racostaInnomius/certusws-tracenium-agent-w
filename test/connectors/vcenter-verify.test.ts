import { describe, it, expect } from "vitest";
import {
  runVerification,
  classifyLoginError,
  isRetryable,
  normalizeThumbprint,
  REQUIRED_PRIVILEGES,
  type VerifyDeps,
  type VerifyConfig,
} from "../../src/connectors/vcenter/verify";

// Real lab values (ADR-0001 Inc 0).
const FP = "62A20AE2D752FC78934A1134F3B4ECC31914899A6B9CD8CE72279808E15C337D";
const CFG: VerifyConfig = { host: "10.130.130.3", port: 443, tlsThumbprintSha256: FP };
const SECRET = "sup3r-s3cret-vcenter-pw";

function deps(over: Partial<VerifyDeps> = {}): VerifyDeps {
  return {
    probeReachability: async () => 313,
    serverFingerprint: async () => FP.toLowerCase(),
    login: async () => ({ sessionKey: "sess-1", userName: "VSPHERE.LOCAL\\Administrator" }),
    listPrivileges: async () => [...REQUIRED_PRIVILEGES, "System.View", "System.Read"],
    checkPrivileges: async (_s, ids) => ids.map(() => true),
    countVmsInScope: async () => 19,
    logout: async () => {},
    now: () => new Date("2026-07-08T12:00:00.000Z"),
    ...over,
  };
}

describe("runVerification — happy path", () => {
  it("passes every rung and reports verified", async () => {
    const r = await runVerification(deps(), CFG);
    expect(r.ok).toBe(true);
    expect(r.failedStage).toBeNull();
    expect(r.classify).toBeNull();
    expect(r.stages.map((s) => s.stage)).toEqual([
      "reachability",
      "tls_pin",
      "authentication",
      "privileges",
      "scope",
    ]);
    expect(r.verifiedAtUtc).toBe("2026-07-08T12:00:00.000Z");
  });

  it("always logs out, even on success", async () => {
    let out = 0;
    await runVerification(deps({ logout: async () => { out++; } }), CFG);
    expect(out).toBe(1);
  });
});

describe("rung ordering — a failure stops the ladder", () => {
  it("does not attempt login when the TLS pin does not match", async () => {
    let loggedIn = false;
    const r = await runVerification(
      deps({
        serverFingerprint: async () => "00".repeat(32),
        login: async () => { loggedIn = true; return { sessionKey: "x", userName: "y" }; },
      }),
      CFG
    );
    expect(r.ok).toBe(false);
    expect(r.failedStage).toBe("tls_pin");
    expect(r.classify).toBe("tls_pin_mismatch");
    expect(loggedIn).toBe(false); // never sent credentials to an unverified server
  });

  it("stops at reachability without touching TLS or auth", async () => {
    const r = await runVerification(
      deps({ probeReachability: async () => { throw new Error("ETIMEDOUT"); } }),
      CFG
    );
    expect(r.failedStage).toBe("reachability");
    expect(r.classify).toBe("network");
    expect(r.stages).toHaveLength(1);
  });

  it("still logs out when a later rung fails", async () => {
    let out = 0;
    await runVerification(
      deps({ countVmsInScope: async () => 0, logout: async () => { out++; } }),
      CFG
    );
    expect(out).toBe(1);
  });
});

describe("credential failures are never auto-retried (vSphere lockout safety)", () => {
  it("classifies a bad password as terminal", async () => {
    const r = await runVerification(
      deps({
        login: async () => {
          throw new Error("Cannot complete login due to an incorrect user name or password.");
        },
      }),
      CFG
    );
    expect(r.failedStage).toBe("authentication");
    expect(r.classify).toBe("bad_credentials");
    expect(r.retryable).toBe(false);
    expect(r.remediation).toMatch(/Do NOT retry automatically/i);
  });

  it("treats an unrecognised auth error as terminal, not retryable", async () => {
    const r = await runVerification(deps({ login: async () => { throw new Error("weird vcenter burp"); } }), CFG);
    expect(r.classify).toBe("unknown");
    expect(r.retryable).toBe(false);
  });

  it("only network problems are retryable", () => {
    expect(isRetryable("network")).toBe(true);
    for (const c of ["bad_credentials", "account_locked", "password_expired", "insufficient_privileges", "tls_pin_mismatch", "unknown"] as const) {
      expect(isRetryable(c)).toBe(false);
    }
  });

  it("recognises expired and locked accounts distinctly", () => {
    expect(classifyLoginError("The password has expired")).toBe("password_expired");
    expect(classifyLoginError("Account is locked out")).toBe("account_locked");
    expect(classifyLoginError("ECONNREFUSED")).toBe("network");
  });
});

describe("privilege rung", () => {
  it("reports exactly which privileges are missing", async () => {
    const r = await runVerification(
      deps({ checkPrivileges: async (_s, ids) => ids.map((p) => p !== "VirtualMachine.State.RemoveSnapshot") }),
      CFG
    );
    expect(r.ok).toBe(false);
    expect(r.failedStage).toBe("privileges");
    expect(r.classify).toBe("insufficient_privileges");
    expect(r.stages.at(-1)!.error).toContain("VirtualMachine.State.RemoveSnapshot");
    const rows = r.stages.at(-1)!.privileges!;
    expect(rows.find((x) => x.priv === "VirtualMachine.State.RemoveSnapshot")!.granted).toBe(false);
    expect(rows.find((x) => x.priv === "VirtualMachine.State.CreateSnapshot")!.granted).toBe(true);
  });

  it("never queries a privilege id the server does not advertise", async () => {
    // Regression: an unknown privId makes vCenter throw "Authorize Exception"
    // and poisons the whole batch, which would report a good credential as
    // unprivileged. Only ask about ids present in privilegeList.
    let asked: string[] = [];
    const r = await runVerification(
      deps({
        listPrivileges: async () => ["VirtualMachine.State.CreateSnapshot", "VirtualMachine.State.RemoveSnapshot"],
        checkPrivileges: async (_s, ids) => { asked = ids; return ids.map(() => true); },
      }),
      CFG
    );
    expect(asked).not.toContain("VirtualMachine.State.RevertToSnapshot");
    // Not advertised => reported as unsupported, NOT as denied.
    expect(r.ok).toBe(true);
    const rows = r.stages.find((s) => s.stage === "privileges")!.privileges!;
    const revert = rows.find((x) => x.priv === "VirtualMachine.State.RevertToSnapshot")!;
    expect(revert.supported).toBe(false);
    expect(r.stages.find((s) => s.stage === "privileges")!.warn).toBe(true);
  });

  it("surfaces an Authorize Exception as unknown rather than 'denied'", async () => {
    const r = await runVerification(
      deps({ checkPrivileges: async () => { throw new Error("A general system error occurred: Authorize Exception"); } }),
      CFG
    );
    expect(r.failedStage).toBe("privileges");
    expect(r.classify).toBe("unknown");
    expect(r.classify).not.toBe("insufficient_privileges");
  });
});

describe("scope rung", () => {
  it("fails when the account sees no VMs", async () => {
    const r = await runVerification(deps({ countVmsInScope: async () => 0 }), CFG);
    expect(r.failedStage).toBe("scope");
    expect(r.classify).toBe("empty_scope");
    expect(r.remediation).toMatch(/propagate/i);
  });
});

describe("thumbprint handling", () => {
  it("normalises separators and case on both sides", () => {
    expect(normalizeThumbprint("AB:CD:ef")).toBe("abcdef");
    expect(normalizeThumbprint("ab cd-EF")).toBe("abcdef");
    expect(normalizeThumbprint(undefined)).toBe("");
  });

  it("matches a colon-separated pin against a bare hex fingerprint", async () => {
    const colonised = FP.match(/../g)!.join(":");
    const r = await runVerification(deps(), { ...CFG, tlsThumbprintSha256: colonised });
    expect(r.ok).toBe(true);
  });

  it("warns but continues when no pin is configured", async () => {
    const r = await runVerification(deps(), { ...CFG, tlsThumbprintSha256: undefined });
    expect(r.ok).toBe(true);
    expect(r.stages.find((s) => s.stage === "tls_pin")!.warn).toBe(true);
  });
});

describe("the report is safe to send to a backend that must not learn the secret", () => {
  it("never contains the credential in any form", async () => {
    const r = await runVerification(
      deps({
        login: async () => { throw new Error(`login failed for user svc@vsphere.local`); },
      }),
      CFG
    );
    const wire = JSON.stringify(r);
    expect(wire).not.toContain(SECRET);
    expect(wire.toLowerCase()).not.toContain("password=");
  });

  it("serialises to a compact structure suitable for a base64url ACK", async () => {
    const r = await runVerification(deps(), CFG);
    const encoded = Buffer.from(JSON.stringify(r)).toString("base64url");
    expect(encoded.length).toBeLessThan(4096);
    expect(JSON.parse(Buffer.from(encoded, "base64url").toString()).ok).toBe(true);
  });
});
