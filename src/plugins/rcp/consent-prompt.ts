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

// ── How long a person gets to answer ─────────────────────────────────
//
// ⚠️ These are NOT the session timeout, and the difference mattered: the
// session-open gate used to be handed `sessionTimeoutSeconds`, the agent's
// 4-hour hard cap on the session itself. A dialog asking somebody whether a
// stranger may see their screen was therefore told to wait four hours for an
// answer. Two different questions had been given the same number because both
// happened to be "a timeout on this session".
//
// They live together here because the IPC budget for `rcp.consent.request`
// has to outlast the LONGER of the two (see getTimeoutForMethod in
// src/priv/privsvc-client-*.ts, and the invariant test that pins it). Split
// across two modules, raising one of them would silently break that.
export const SESSION_CONSENT_TIMEOUT_S = 60;

// Longer than opening the session: there the person has just asked for help
// and is looking at the screen. This second prompt can arrive ten minutes
// into explaining the problem on the phone, and a short window would turn a
// normal hesitation into a refusal.
export const CONTROL_CONSENT_TIMEOUT_S = 90;

/** The longest any consent prompt may block for. What the IPC budget is built on. */
export const MAX_CONSENT_TIMEOUT_S = Math.max(
  SESSION_CONSENT_TIMEOUT_S,
  CONTROL_CONSENT_TIMEOUT_S
);

/**
 * `unavailable` = no había NADIE a quien preguntar.
 *
 * 🔴 De dónde sale (25-sep-2026, TNS-OPER-SNOC04, T1): cuatro intentos de
 * `rcp.screen` contra un Windows Server, los cuatro muertos a los 61 s con
 * `consent_timeout`. El portal decía «The prompt appeared and expired with no
 * answer. They may be away from the machine» — y eso AFIRMA que el aviso
 * apareció, que es justo lo que no sabíamos. Ese servidor no tiene usuario en
 * consola (`last_logon_user` vacío, mientras los otros Windows del tenant sí
 * lo reportan): el aviso no apareció nunca porque no hay bandeja donde
 * aparecer. El mensaje mandó a buscar el fallo en la política de aprobación,
 * que no tenía nada que ver.
 *
 * Distinguirlo cuesta una variante y ahorra la búsqueda: el backend ya conoce
 * `consent_required` (`rcp-metrics.ts`) y la UI ya tiene el texto correcto
 * («This device can't ask for consent… nobody is logged in»).
 */
export type ConsentDecision = "approved" | "denied" | "timeout" | "unavailable";

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
  // ⚠️ NO es un timeout: nadie dejó pasar el plazo porque no había nadie. El
  // operador tiene que leer «este equipo no puede preguntar», no «no te
  // contestaron», que sugiere que alguien decidió ignorarte.
  if (decision === "unavailable") return "consent_required";
  return null; // approved
}
