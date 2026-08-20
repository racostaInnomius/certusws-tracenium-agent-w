// test/core/policy-dp-base-urls.test.ts
//
// The DP addresses the control plane injects per device when it delivers the
// policy. They exist so the agent's OWN periodic update check can prefer the
// LAN — that check has no job behind it, so before this it always pulled the
// installer from the internet even on a site whose DP held those exact bytes.

import { describe, expect, it } from "vitest";
import { PolicyRuntime } from "../../src/core/policy-runtime";

function runtimeWith(policy: any): any {
  const rt: any = Object.create(PolicyRuntime.prototype);
  rt.policy = policy;
  return rt;
}

describe("policyRuntime.dpBaseUrls", () => {
  it("returns the injected LAN addresses", () => {
    const rt = runtimeWith({ sdp: { dpBaseUrls: ["https://10.1.2.3:47821"] } });
    expect(rt.dpBaseUrls()).toEqual(["https://10.1.2.3:47821"]);
  });

  it("is empty for a device with no distribution point", () => {
    expect(runtimeWith({}).dpBaseUrls()).toEqual([]);
    expect(runtimeWith({ sdp: {} }).dpBaseUrls()).toEqual([]);
  });

  // The value arrives over the wire, so it is validated rather than trusted: a
  // malformed policy must degrade to "no DP" — download from the internet, as
  // before — not hand a junk URL to the downloader.
  it("drops anything that is not an https URL", () => {
    const rt = runtimeWith({
      sdp: {
        dpBaseUrls: [
          "https://10.1.2.3:47821",
          "http://10.1.2.4:47821",
          "file:///etc/passwd",
          42,
          null,
          "",
        ],
      },
    });
    expect(rt.dpBaseUrls()).toEqual(["https://10.1.2.3:47821"]);
  });

  it("survives a non-array value instead of throwing mid-update", () => {
    expect(runtimeWith({ sdp: { dpBaseUrls: "https://10.1.2.3:47821" } }).dpBaseUrls()).toEqual([]);
    expect(runtimeWith({ sdp: { dpBaseUrls: null } }).dpBaseUrls()).toEqual([]);
  });

  it("caps the list so a bad policy cannot make the updater try forever", () => {
    const many = Array.from({ length: 40 }, (_, i) => `https://10.1.2.${i}:47821`);
    expect(runtimeWith({ sdp: { dpBaseUrls: many } }).dpBaseUrls()).toHaveLength(8);
  });
});
