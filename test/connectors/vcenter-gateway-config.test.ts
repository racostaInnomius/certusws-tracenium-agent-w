import { describe, it, expect } from "vitest";
import {
  parseGatewayConfig,
  isGatewayEnabled,
  normalizeThumbprint,
  SNAPSHOT_DEFAULTS,
} from "../../src/connectors/vcenter/gateway-config";

const FP = "62a20ae2d752fc78934a1134f3b4ecc31914899a6b9cd8ce72279808e15c337d";

const VALID = {
  vcenter: { url: "https://10.130.130.3", tlsThumbprintSha256: FP },
  scope: { datacenter: "DC1", folders: ["/DC1/vm/Prod"] },
  snapshot: { quiesce: true, memory: false, retentionHours: 24 },
};

describe("parseGatewayConfig — presence of config is the enablement", () => {
  it("parses a valid block", () => {
    const cfg = parseGatewayConfig(VALID)!;
    expect(isGatewayEnabled(cfg)).toBe(true);
    expect(cfg.vcenter).toEqual({
      url: "https://10.130.130.3",
      host: "10.130.130.3",
      port: 443,
      tlsThumbprintSha256: FP,
      credentialRef: "vcenter/default",
    });
  });

  it("treats an absent block as 'not a gateway'", () => {
    for (const v of [undefined, null, {}, "", 0, [], { vcenter: undefined }]) {
      expect(parseGatewayConfig(v)).toBeNull();
    }
  });

  it("never returns a partially configured gateway", () => {
    // A half-valid block must not look enabled.
    expect(parseGatewayConfig({ vcenter: { url: "https://vc.local" } })).toBeNull(); // no pin
    expect(parseGatewayConfig({ vcenter: { tlsThumbprintSha256: FP } })).toBeNull(); // no url
  });
});

describe("TLS pin is mandatory for the operational connector", () => {
  it("refuses to enable without a thumbprint", () => {
    expect(parseGatewayConfig({ vcenter: { url: "https://10.130.130.3" } })).toBeNull();
  });

  it("refuses a malformed thumbprint rather than ignoring it", () => {
    for (const bad of ["nope", "ab", FP.slice(0, 63), FP + "ff", 12345, null]) {
      expect(parseGatewayConfig({ vcenter: { url: "https://vc.local", tlsThumbprintSha256: bad } })).toBeNull();
    }
  });

  it("accepts colon-separated and uppercase pins", () => {
    const colonised = FP.match(/../g)!.join(":").toUpperCase();
    const cfg = parseGatewayConfig({ vcenter: { url: "https://vc.local", tlsThumbprintSha256: colonised } })!;
    expect(cfg.vcenter.tlsThumbprintSha256).toBe(FP);
  });

  it("normalizeThumbprint rejects non-sha256 input", () => {
    expect(normalizeThumbprint(FP.toUpperCase())).toBe(FP);
    expect(normalizeThumbprint("zz")).toBe("");
    expect(normalizeThumbprint(undefined)).toBe("");
  });
});

describe("transport safety", () => {
  it("rejects non-https endpoints — a vSphere credential never crosses plaintext", () => {
    expect(parseGatewayConfig({ vcenter: { url: "http://10.130.130.3", tlsThumbprintSha256: FP } })).toBeNull();
    expect(parseGatewayConfig({ vcenter: { url: "ftp://x", tlsThumbprintSha256: FP } })).toBeNull();
  });

  it("rejects an unparseable url", () => {
    expect(parseGatewayConfig({ vcenter: { url: "not a url", tlsThumbprintSha256: FP } })).toBeNull();
  });

  it("honours an explicit port and clamps nonsense", () => {
    const p = (port: unknown) =>
      parseGatewayConfig({ vcenter: { url: "https://vc.local", port, tlsThumbprintSha256: FP } })!.vcenter.port;
    expect(p(8443)).toBe(8443);
    expect(p(0)).toBe(1);
    expect(p(999999)).toBe(65535);
    expect(p("nope")).toBe(443);
  });

  it("takes the port from the url when not given explicitly", () => {
    const cfg = parseGatewayConfig({ vcenter: { url: "https://vc.local:8443", tlsThumbprintSha256: FP } })!;
    expect(cfg.vcenter.port).toBe(8443);
  });
});

describe("credentialRef points at the OS store, never at a secret", () => {
  it("defaults when absent", () => {
    expect(parseGatewayConfig(VALID)!.vcenter.credentialRef).toBe("vcenter/default");
  });

  it("honours an explicit ref", () => {
    const cfg = parseGatewayConfig({
      vcenter: { ...VALID.vcenter, credentialRef: "  vcenter/site-b  " },
    })!;
    expect(cfg.vcenter.credentialRef).toBe("vcenter/site-b");
  });
});

describe("scope", () => {
  it("keeps folders, de-duplicated and trimmed", () => {
    const cfg = parseGatewayConfig({
      ...VALID,
      scope: { folders: [" /DC1/vm/A ", "/DC1/vm/A", "/DC1/vm/B", "", 42] },
    })!;
    expect(cfg.scope.folders).toEqual(["/DC1/vm/A", "/DC1/vm/B"]);
  });

  it("defaults to whole-inventory when absent", () => {
    const cfg = parseGatewayConfig({ vcenter: VALID.vcenter })!;
    expect(cfg.scope.folders).toEqual([]);
    expect(cfg.scope.datacenter).toBeUndefined();
  });

  it("caps the folder list", () => {
    const many = Array.from({ length: 200 }, (_, i) => `/DC1/vm/f${i}`);
    expect(parseGatewayConfig({ ...VALID, scope: { folders: many } })!.scope.folders).toHaveLength(64);
  });
});

describe("snapshot tuning is bounded on both ends", () => {
  it("applies defaults when absent", () => {
    expect(parseGatewayConfig({ vcenter: VALID.vcenter })!.snapshot).toEqual(SNAPSHOT_DEFAULTS);
  });

  it("clamps retention so the safety net cannot be deleted instantly or kept forever", () => {
    const r = (retentionHours: unknown) =>
      parseGatewayConfig({ ...VALID, snapshot: { retentionHours } })!.snapshot.retentionHours;
    expect(r(0)).toBe(1);      // never "delete immediately"
    expect(r(-5)).toBe(1);
    expect(r(99999)).toBe(720); // never unbounded sprawl
    expect(r(48)).toBe(48);
  });

  it("clamps concurrency so a cluster-wide run cannot stun vCenter", () => {
    const c = (maxConcurrent: unknown) =>
      parseGatewayConfig({ ...VALID, snapshot: { maxConcurrent } })!.snapshot.maxConcurrent;
    expect(c(1000)).toBe(32);
    expect(c(0)).toBe(1);
    expect(c(8)).toBe(8);
  });

  it("clamps the per-VM timeout", () => {
    const t = (perVmTimeoutSec: unknown) =>
      parseGatewayConfig({ ...VALID, snapshot: { perVmTimeoutSec } })!.snapshot.perVmTimeoutSec;
    expect(t(1)).toBe(60);
    expect(t(99999)).toBe(3600);
  });

  it("keeps memory off and quiesce on by default", () => {
    const s = parseGatewayConfig({ vcenter: VALID.vcenter })!.snapshot;
    expect(s.memory).toBe(false);
    expect(s.quiesce).toBe(true);
  });

  it("ignores non-boolean flags instead of coercing them", () => {
    const s = parseGatewayConfig({ ...VALID, snapshot: { memory: "yes", quiesce: 0 } })!.snapshot;
    expect(s.memory).toBe(false);
    expect(s.quiesce).toBe(true);
  });
});
