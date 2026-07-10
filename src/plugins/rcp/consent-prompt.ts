// src/plugins/rcp/consent-prompt.ts
//
// User-attended approval (RCP) — the endpoint-side consent prompt seam.
//
// When the tenant policy sets `features.remoteRequireConsent`, the agent must
// ask the logged-in user to approve a remote-control session BEFORE it opens.
// The actual prompt is platform-specific and privileged (on Windows the agent
// runs in session 0 and must surface a dialog in the interactive user's session
// via WTSSendMessage / a user-session helper; macOS/Linux differ), so it lives
// behind an injectable `ConsentPrompter` on the AgentContext and is exercised
// here through a small, pure contract:
//
//   * `available()` — can this host actually prompt right now? Gates whether the
//     agent advertises the `rcp.consent` capability. If it can't prompt, it must
//     NOT advertise, so the backend fail-closes the session rather than opening
//     one the user never approved.
//   * `request()` — show the prompt, resolve to the user's decision (or timeout).
//
// The DEFAULT prompter fails closed: no native UI wired ⇒ it can't prompt ⇒ it
// denies. This keeps the security invariant intact on platforms/builds where the
// native dialog isn't implemented yet; wiring a real prompter (registered on
// ctx.consentPrompter) is what turns the feature on.

export type ConsentDecision = "approved" | "denied" | "timeout";

export interface ConsentRequest {
  sessionId: string;
  capability: string; // rcp.shell | rcp.file | rcp.screen
  operator: string | null; // who is asking, for the prompt text
  timeoutSeconds: number; // auto-deny after this
}

export interface ConsentPrompter {
  /** True when this host can surface a prompt to the interactive user now. */
  available(): boolean;
  /** Show the prompt; resolve to the user's decision. Must never reject. */
  request(req: ConsentRequest): Promise<ConsentDecision>;
}

/**
 * Default prompter: no native dialog is wired, so it cannot obtain consent and
 * therefore denies. `available()` returns false so the agent does not advertise
 * `rcp.consent` and the backend fail-closes consent-required sessions with a
 * clear "device cannot obtain consent" error instead of silently proceeding.
 */
export const failClosedConsentPrompter: ConsentPrompter = {
  available: () => false,
  request: async () => "denied",
};

/** Map a decision to the RemoteSessionClose.reason the backend audits. Returns
 * null on approval (no close — the session proceeds). Kept in lockstep with the
 * backend's consent-gate.ts (CONSENT_DENIED_REASON / CONSENT_TIMEOUT_REASON). */
export function consentCloseReason(decision: ConsentDecision): string | null {
  if (decision === "denied") return "consent_denied";
  if (decision === "timeout") return "consent_timeout";
  return null; // approved
}
