// test/plugins/rcp-consent.test.ts
//
// ⚠️ El gate de consentimiento del agente, que decide POR SU CUENTA.
//
// El control plane también lo evalúa, y el agente vuelve a hacerlo como
// defensa en profundidad. El 2026-09-08 eso salió caro: el backend ya estaba
// arreglado —su evento `requested` decía `consentRequired: false`— y una
// sesión de ficheros del tenant 1 murió igual a los 61 s con
// `consent_timeout` y `source: agent`. Dos gates, la misma ceguera: ninguno
// miraba la capacidad.
//
// Por eso estos casos usan `rcp.screen`: es de lo que siempre hablaron. A una
// shell o a una transferencia no se les pregunta, porque en un servidor
// virtual no hay nadie que conteste.

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
        f === "remoteShell" || f === "remoteScreen" || f === "remoteFile"
          ? true
          : f === "remoteRequireConsent"
            ? opts.requireConsent
            : false,
    },
  };
  return { ctx, sendControl };
}

const OFFER = { sessionId: "sess-1", sdp: "v=0", capability: "rcp.screen", operatorUserId: "op@x" };
/** La misma oferta para una capacidad a la que NO se le pregunta. */
const OFFER_SHELL = { ...OFFER, capability: "rcp.shell" };

describe("⚠️ a qué capacidades pregunta el agente", () => {
  // El caso de producción del 2026-09-08 (tenant 1): sesión de ficheros,
  // `consentRequired: false` en el backend, y aun así `consent_timeout` a los
  // 61 s con `source: agent`. La UI se quedaba en "Establishing file transfer
  // session…" hasta que vencía el plazo de un aviso que nadie iba a ver.

  it("⚠️ una sesión de ficheros NO pregunta, ni con la política encendida", async () => {
    const request = vi.fn(async () => "denied" as const);
    const { ctx, sendControl } = makeCtx({
      requireConsent: true,
      prompter: { available: () => true, request },
    });
    await new SessionManager(ctx).onOffer({ ...OFFER_SHELL, capability: "rcp.file" });

    expect(request).not.toHaveBeenCalled();
    // Y no se cierra por consentimiento: la sesión sigue su curso.
    const cierres = sendControl.mock.calls
      .map((c: any[]) => c[0]?.remoteSessionClose?.reason)
      .filter(Boolean);
    expect(cierres).not.toContain("consent_timeout");
    expect(cierres).not.toContain("consent_denied");
  });

  it("⚠️ una shell tampoco", async () => {
    const request = vi.fn(async () => "timeout" as const);
    const { ctx } = makeCtx({
      requireConsent: true,
      prompter: { available: () => true, request },
    });
    await new SessionManager(ctx).onOffer(OFFER_SHELL);
    expect(request).not.toHaveBeenCalled();
  });

  it("la pantalla sí sigue preguntando", async () => {
    // La mitad que NO puede romperse arreglando lo de arriba: si esto deja de
    // preguntar, se mira la pantalla de alguien sin pedirle permiso.
    const request = vi.fn(async () => "approved" as const);
    const { ctx } = makeCtx({
      requireConsent: true,
      prompter: { available: () => true, request },
    });
    await new SessionManager(ctx).onOffer(OFFER);
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("⚠️ y sin prompter, una shell no cae en el denegar por defecto", async () => {
    // El fallo cerrado existe para la pantalla: sin nadie a quien preguntar,
    // no se mira. Aplicado a la shell dejaba el equipo INACCESIBLE en cuanto
    // el tenant encendía el consentimiento.
    const { ctx, sendControl } = makeCtx({ requireConsent: true });
    await new SessionManager(ctx).onOffer(OFFER_SHELL);

    const cierres = sendControl.mock.calls
      .map((c: any[]) => c[0]?.remoteSessionClose?.reason)
      .filter(Boolean);
    expect(cierres).not.toContain("consent_denied");
  });
});

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
      expect.objectContaining({ sessionId: "sess-1", capability: "rcp.screen", operator: "op@x" })
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
