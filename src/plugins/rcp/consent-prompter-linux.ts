// src/plugins/rcp/consent-prompter-linux.ts
//
// ConsentPrompter de Linux (ADR-0012). Delega en PrivSvc, que lanza el
// diálogo dentro de la sesión gráfica — ver privsvc/linux/src/consent-dialog.ts.
//
// ── available() es lo que apaga la función, no lo que la rompe ───────
//
//   El agente solo anuncia la capacidad `rcp.consent` si el prompter dice que
//   puede preguntar. Si dijera que sí sin poder, el backend abriría sesiones
//   que requieren consentimiento y el agente las denegaría todas: la persona
//   nunca vería un diálogo y el operador solo vería sesiones que mueren sin
//   explicación.
//
//   Aquí devolvemos true si hay canal con PrivSvc. No comprobamos que exista
//   escritorio X11 —eso cambia mientras el agente corre, y una comprobación
//   hecha al arrancar mentiría el resto del día—; esa decisión la toma
//   consent-dialog.ts en el momento de preguntar, que es cuando se sabe.

import type { AgentContext } from "../../core/agent-context";
import type {
  ConsentDecision,
  ConsentPrompter,
  ConsentRequest
} from "./consent-prompt";
import {
  consentButtons,
  consentLines,
  kindForCapability
} from "./consent-text";
import { recordingEnabled } from "./recording-policy";

export function createLinuxConsentPrompter(ctx: AgentContext): ConsentPrompter {
  return {
    available(): boolean {
      return typeof (ctx.priv as any)?.call === "function";
    },

    async request(req: ConsentRequest): Promise<ConsentDecision> {
      const kind = kindForCapability(req.capability);
      const buttons = consentButtons(kind);

      try {
        const res: any = await (ctx.priv as any).call({
          v: 1,
          id: `rcp.consent.${req.sessionId}.${kind}`,
          method: "rcp.consent.request",
          params: {
            text: consentLines({
              kind,
              operator: req.operator,
              recording: recordingEnabled(ctx)
            }).join("\n"),
            allow: buttons.allow,
            deny: buttons.deny,
            timeoutSeconds: req.timeoutSeconds
          }
        });

        const d = res?.result?.decision ?? res?.decision;
        if (d === "approved" || d === "denied" || d === "timeout") return d;

        // Respuesta que no entendemos: denegar. Un canal que devuelve algo
        // inesperado no puede conceder acceso al equipo de nadie.
        ctx.logger?.warn?.("[rcp] respuesta de consentimiento ininteligible; se deniega", {
          sessionId: req.sessionId
        });
        return "denied";
      } catch (err: any) {
        ctx.logger?.error?.("[rcp] el IPC de consentimiento falló; se deniega", {
          sessionId: req.sessionId,
          err: err?.message || String(err)
        });
        return "denied";
      }
    }
  };
}
