// test/plugins/rcp-consent.test.ts

import { describe, expect, it, vi } from "vitest";
import {
  failClosedConsentPrompter,
  consentCloseReason,
  type ConsentPrompter,
} from "../../src/plugins/rcp/consent-prompt";
import { SessionManager } from "../../src/plugins/rcp/session-manager";

describe("consent-prompt helpers", () => {
  it("fail-closed prompter cannot prompt and denies", async () => {
    expect(failClosedConsentPrompter.available()).toBe(false);
    expect(await failClosedConsentPrompter.request({
      sessionId: "s", capability: "rcp.shell", operator: null, timeoutSeconds: 60,
    })).toBe("denied");
  });

  it("maps decision → close reason (null on approval)", () => {
    expect(consentCloseReason("denied")).toBe("consent_denied");
    expect(consentCloseReason("timeout")).toBe("consent_timeout");
    expect(consentCloseReason("approved")).toBeNull();
  });
});

// ── onOffer consent gate ─────────────────────────────────────────
// We exercise the DENY/TIMEOUT paths, which return BEFORE any PeerSession
// (native node-datachannel) is constructed — so no native module is touched.

function makeCtx(opts: {
  requireConsent: boolean;
  prompter?: ConsentPrompter;
}) {
  const sendControl = vi.fn();
  const ctx: any = {
    logger: {},
    sendControl,
    consentPrompter: opts.prompter,
    policyRuntime: {
      isFeatureEnabled: (f: string) =>
        f === "remoteShell" ? true : f === "remoteRequireConsent" ? opts.requireConsent : false,
    },
  };
  return { ctx, sendControl };
}

const OFFER = { sessionId: "sess-1", sdp: "v=0", capability: "rcp.shell", operatorUserId: "op@x" };

describe("SessionManager.onOffer — consent gate", () => {
  it("denies the session and closes with consent_denied when the user declines", async () => {
    const request = vi.fn(async () => "denied" as const);
    const { ctx, sendControl } = makeCtx({
      requireConsent: true,
      prompter: { available: () => true, request },
    });
    const mgr = new SessionManager(ctx);

    await mgr.onOffer(OFFER);

    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: "sess-1", capability: "rcp.shell", operator: "op@x" })
    );
    expect(sendControl).toHaveBeenCalledWith({
      remoteSessionClose: { sessionId: "sess-1", reason: "consent_denied" },
    });
  });

  it("closes with consent_timeout when the prompt times out", async () => {
    const { ctx, sendControl } = makeCtx({
      requireConsent: true,
      prompter: { available: () => true, request: async () => "timeout" },
    });
    await new SessionManager(ctx).onOffer(OFFER);
    expect(sendControl).toHaveBeenCalledWith({
      remoteSessionClose: { sessionId: "sess-1", reason: "consent_timeout" },
    });
  });

  it("fails closed (deny) when the prompter throws", async () => {
    const { ctx, sendControl } = makeCtx({
      requireConsent: true,
      prompter: { available: () => true, request: async () => { throw new Error("boom"); } },
    });
    await new SessionManager(ctx).onOffer(OFFER);
    expect(sendControl).toHaveBeenCalledWith({
      remoteSessionClose: { sessionId: "sess-1", reason: "consent_denied" },
    });
  });

  it("falls back to the fail-closed default prompter when none is wired", async () => {
    const { ctx, sendControl } = makeCtx({ requireConsent: true, prompter: undefined });
    await new SessionManager(ctx).onOffer(OFFER);
    // No prompter → default denies → session closed, never opened.
    expect(sendControl).toHaveBeenCalledWith({
      remoteSessionClose: { sessionId: "sess-1", reason: "consent_denied" },
    });
  });
});
