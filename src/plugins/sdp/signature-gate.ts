// src/plugins/sdp/signature-gate.ts
//
// SDP pre-install signature gate — pure decision logic, split out of index.ts
// so the security-critical branching is unit-testable.
//
// When a package has `signingRequired`, the agent must NOT run the installer
// until the downloaded bytes pass full Authenticode verification via the OS
// (WinVerifyTrust in the Windows privsvc — the authoritative check the backend
// can't do: file digest + cert chain to the Windows trust store + revocation).
// This is where the "staple a legit signature onto other bytes" gap the backend
// chain-trust check can't close is actually closed — at the point of execution.
//
// Fail-closed: anything other than an explicit "trusted" verdict blocks the
// install with outcome `signature_invalid` (a permanent, no-retry terminal).

export interface SignatureVerifyResult {
  /** True only if the privsvc call succeeded AND the OS reported the file trusted. */
  ok: boolean;
  trusted: boolean;
  /** Short reason tag (WinVerifyTrust status / error code) for the ACK. */
  reason?: string | null;
}

export interface SignatureGateDecision {
  proceed: boolean;
  outcome?: "signature_invalid";
  reason?: string;
}

/**
 * Decide whether to proceed to install.
 *   - signingRequired false → gate off, always proceed.
 *   - signingRequired true  → proceed ONLY on an explicit trusted verdict;
 *     any failure / untrusted / missing signature blocks (fail-closed).
 */
export function evaluateSignatureGate(
  signingRequired: boolean,
  verify: SignatureVerifyResult | null | undefined
): SignatureGateDecision {
  if (!signingRequired) return { proceed: true };
  if (verify && verify.ok === true && verify.trusted === true) return { proceed: true };
  return {
    proceed: false,
    outcome: "signature_invalid",
    reason: (verify && verify.reason) || "signature_untrusted",
  };
}
