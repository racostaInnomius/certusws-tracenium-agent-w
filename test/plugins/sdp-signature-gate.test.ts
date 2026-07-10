// test/plugins/sdp-signature-gate.test.ts

import { describe, expect, it } from "vitest";
import { evaluateSignatureGate, normalizeVerifyResponse } from "../../src/plugins/sdp/signature-gate";

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

describe("normalizeVerifyResponse", () => {
  it("maps a successful privsvc response with a trusted verdict", () => {
    expect(normalizeVerifyResponse({ ok: true, result: { trusted: true, reason: "trusted" } })).toEqual({
      ok: true,
      trusted: true,
      reason: "trusted",
    });
  });

  it("maps a successful response reporting NOT trusted (fails closed downstream)", () => {
    expect(normalizeVerifyResponse({ ok: true, result: { trusted: false, reason: "untrusted_root" } })).toEqual({
      ok: true,
      trusted: false,
      reason: "untrusted_root",
    });
  });

  it("maps a failed privsvc call to ok:false with the error code", () => {
    expect(normalizeVerifyResponse({ ok: false, error: { code: "verify_error" } })).toEqual({
      ok: false,
      trusted: false,
      reason: "verify_error",
    });
  });

  it("treats a missing/garbled response as not-ok, not-trusted", () => {
    expect(normalizeVerifyResponse(undefined)).toEqual({ ok: false, trusted: false, reason: "verify_failed" });
    expect(normalizeVerifyResponse(null)).toEqual({ ok: false, trusted: false, reason: "verify_failed" });
    expect(normalizeVerifyResponse({ ok: true })).toEqual({ ok: true, trusted: false, reason: null });
  });
});
