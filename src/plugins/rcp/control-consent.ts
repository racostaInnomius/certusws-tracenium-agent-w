// src/plugins/rcp/control-consent.ts
//
// Segunda puerta de consentimiento: CONTROLAR (ADR-0012, decisión 1).
//
// ── Por qué son dos puertas y no una ─────────────────────────────────
//
//   Ver y controlar son daños distintos, y la gente los razona distinto.
//
//   Ver es donde ocurre la brecha de CONFIDENCIALIDAD: en cuanto el técnico
//   mira, ya vio el correo abierto y el documento que hubiera. Controlar añade
//   otra cosa — que alguien ACTÚE EN TU NOMBRE, con tu sesión y tus permisos.
//   Eso es integridad y atribución, no confidencialidad.
//
//   De ahí que consentir solo al tomar el control esté al revés: bloquea el
//   daño menor y deja pasar el mayor. La intuición contraria es común porque
//   controlar *se siente* más invasivo, pero el daño ya está hecho al mirar.
//   La primera puerta (ver) vive en session-manager.ts; esta es la segunda.
//
// ── Por qué denegar el control NO cierra la sesión ───────────────────
//
//   La persona consintió que la vieran. Que rechace además el control no
//   retira ese primer consentimiento: tumbar la sesión entera castigaría un
//   "no" perfectamente razonable y empujaría a la gente a decir que sí a todo
//   para que el técnico pueda seguir ayudando. Un consentimiento que se cobra
//   algo por decir que no no es un consentimiento.
//
//   Así que al denegar: se sigue viendo, y la entrada deja de pasar.
//
// ── Por qué es una máquina de estados y no un booleano ───────────────
//
//   El aviso tarda: hay que enseñárselo a una persona y esperar a que decida.
//   Mientras tanto siguen llegando eventos —el ratón manda decenas por
//   segundo—, y cada uno NO puede lanzar otro aviso. `pending` existe para
//   eso: lanzar uno, y tirar todo lo que llegue hasta que haya respuesta.

export type ControlConsentState =
  | "not_asked"
  | "pending"
  | "granted"
  | "denied";

export type ControlGateAction =
  /** Reenviar el evento a la inyección de entrada. */
  | { kind: "forward" }
  /** Tirar el evento y LANZAR el aviso (una sola vez). */
  | { kind: "ask" }
  /** Tirar el evento en silencio: ya hay un aviso en curso, o ya dijeron que no. */
  | { kind: "drop" };

/**
 * Qué hacer con un evento de entrada, dado el estado del consentimiento.
 *
 * `required` es la política del tenant (`remoteRequireConsent`). Con la
 * política apagada esto no se interpone: es el caso de las sesiones
 * desatendidas —servidores, quioscos— que el ADR mantiene a propósito como
 * decisión consciente del tenant, registrada y visible en auditoría.
 */
export function controlGate(
  required: boolean,
  state: ControlConsentState
): ControlGateAction {
  if (!required) return { kind: "forward" };

  switch (state) {
    case "granted":
      return { kind: "forward" };
    case "not_asked":
      return { kind: "ask" };
    case "pending":
    case "denied":
      return { kind: "drop" };
  }
}

/**
 * Estado tras una decisión del usuario.
 *
 * `timeout` cuenta como negativa. No es una tecnicidad: si nadie contestó, la
 * persona no está delante, y actuar en el equipo de alguien que no está es
 * exactamente lo que la puerta existe para impedir. El silencio no es un sí.
 */
export function stateAfterDecision(
  decision: "approved" | "denied" | "timeout"
): ControlConsentState {
  return decision === "approved" ? "granted" : "denied";
}

/**
 * ¿Hay que avisar al operador de que su control fue rechazado?
 *
 * Solo en el momento del cambio a "denied". Si se avisara en cada evento
 * tirado, un ratón moviéndose llenaría el canal de errores y la UI del
 * operador parpadearía sin parar — el mensaje que importa se perdería entre
 * cientos iguales.
 */
export function shouldNotifyOperator(
  prev: ControlConsentState,
  next: ControlConsentState
): boolean {
  return prev !== "denied" && next === "denied";
}
