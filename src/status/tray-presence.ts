// src/status/tray-presence.ts
//
// Vigila que el icono de bandeja siga vivo en la sesión del usuario (Windows).
//
// ── Por qué hace falta vigilarlo ─────────────────────────────────────
//
//   El MSI cierra la bandeja para poder actualizarla: su .exe es single-file
//   self-contained y reemplazarlo bajo un proceso vivo lo rompe. Pero nadie la
//   vuelve a abrir — la Run key solo dispara en el siguiente inicio de sesión.
//   Así que tras CADA auto-actualización el usuario se queda sin bandeja
//   durante días, hasta que reinicia.
//
//   Eso era un icono ausente. Desde ADR-0012 es otra cosa: la bandeja es donde
//   vive el INDICADOR de "te están viendo la pantalla" y donde se enseña el
//   DIÁLOGO de consentimiento. Sin ella:
//
//     · el indicador no aparece — alguien mira sin que se note;
//     · la petición de consentimiento no la lee nadie, vence, y eso cuenta
//       como negativa: todas las sesiones rechazadas, en silencio.
//
//   O sea, la función de privacidad se apagaría sola después de cada
//   actualización. Por eso esto no es cosmético.
//
// ── Por qué se comprueba periódicamente y no solo al arrancar ────────
//
//   El arranque del agente NO coincide con el momento en que hace falta. El
//   caso típico es: el agente lleva horas corriendo, se actualiza, el MSI mata
//   la bandeja, y el servicio se reinicia DESPUÉS o ni siquiera. Y hay otros
//   caminos —el usuario la cierra, o entra en sesión más tarde que el
//   servicio— en los que un único intento al inicio llega demasiado pronto.
//
//   El coste de mirar es un enumerado de procesos cada pocos minutos, y solo
//   se actúa cuando falta.

import type { AgentContext } from "../core/agent-context";

/**
 * Cada cuánto se comprueba. Cinco minutos: la bandeja no es urgente al
 * segundo, y un intervalo corto solo añadiría ruido en el log de PrivSvc.
 */
export const TRAY_CHECK_INTERVAL_MS = 5 * 60 * 1000;

let timer: NodeJS.Timeout | null = null;

/** Una comprobación. Nunca lanza. */
export async function ensureTrayOnce(ctx: AgentContext): Promise<void> {
  if (process.platform !== "win32") return;
  try {
    const res: any = await (ctx.priv as any)?.call?.({
      v: 1,
      id: `tray.ensure.${Date.now()}`,
      method: "tray.ensure",
      params: {}
    });
    const action = res?.result?.action ?? res?.action;
    // Solo se registra cuando PASA algo. "already_running" es el caso normal y
    // llenaría el log a razón de doce líneas por hora sin decir nada.
    if (action && action !== "already_running" && action !== "no_console_session") {
      ctx.logger?.info?.("[tray] presencia", { action });
    }
  } catch (err: any) {
    // Un PrivSvc que no responde ya se registra en su propio camino; aquí no
    // se puede hacer nada y desde luego no tumbar el agente.
    ctx.logger?.debug?.("[tray] no se pudo comprobar la presencia", {
      err: err?.message || String(err)
    });
  }
}

/** Arranca la vigilancia. Idempotente. */
export function startTrayPresenceWatch(ctx: AgentContext): void {
  if (process.platform !== "win32" || timer) return;
  // Una primera pasada en cuanto haya IPC, y luego el ritmo lento.
  void ensureTrayOnce(ctx);
  timer = setInterval(() => void ensureTrayOnce(ctx), TRAY_CHECK_INTERVAL_MS);
  timer.unref?.();
}

export function stopTrayPresenceWatch(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}
