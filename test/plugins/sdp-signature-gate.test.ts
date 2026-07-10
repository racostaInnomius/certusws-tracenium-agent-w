// test/plugins/sdp-signature-gate.test.ts

import { describe, expect, it } from "vitest";
import { evaluateSignatureGate } from "../../src/plugins/sdp/signature-gate";

describe("evaluateSignatureGate", () => {
  it("proceeds when signing is not required (gate off), whatever the verify result", () => {
    expect(evaluateSignatureGate(false, null)).toEqual({ proceed: true });
    expect(evaluateSignatureGate(false, { ok: false, trusted: false })).toEqual({ proceed: true });
  });

  it("proceeds when required AND the OS reports trusted", () => {
    expect(evaluateSignatureGate(true, { ok: true, trusted: true, reason: "trusted" })).toEqual({
      proceed: true,
    });
  });

  it("blocks (signature_invalid) when required but NOT trusted", () => {
    expect(evaluateSignatureGate(true, { ok: true, trusted: false, reason: "untrusted_root" })).toEqual({
      proceed: false,
      outcome: "signature_invalid",
      reason: "untrusted_root",
    });
  });

  it("blocks when required and the verify call itself failed (fail-closed)", () => {
    expect(evaluateSignatureGate(true, { ok: false, trusted: false, reason: "verify_failed" })).toEqual({
      proceed: false,
      outcome: "signature_invalid",
      reason: "verify_failed",
    });
    // Missing/absent verify result → still blocks with a default reason.
    expect(evaluateSignatureGate(true, null)).toEqual({
      proceed: false,
      outcome: "signature_invalid",
      reason: "signature_untrusted",
    });
  });
});
