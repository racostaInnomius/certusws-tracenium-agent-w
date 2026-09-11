// src/core/inventory-send-gate.ts
//
// ¿Hay que mandar el snapshot de inventario en este tick?
//
// Sacado del scheduler a una función pura para poder probarlo: el gate vivía
// dentro de un método privado de 600 líneas, y el cambio de ADR-0020 F2 —el
// tercer disparador— es justo el tipo de condición que se rompe en silencio.

/**
 * Silencio máximo antes de mandar un no-op aunque nada haya cambiado.
 *
 * ⚠️ POR QUÉ EXISTE. Sin cambios, sin reinicio y sin cambio de versión, el
 * agente no mandaba NADA. En T111 (21 días) el hueco máximo entre envíos por
 * equipo era p50 3,6 d, y el servidor no podía distinguir un portátil estable
 * de uno apagado. La regla de software requerido/prohibido (ADR-0020) necesita
 * saber si el inventario que mira está fresco.
 *
 * 24 h y no menos: el no-op cuesta un mensaje pequeño. El gate sólo se evalúa
 * cuando corre el tick de inventario, que por defecto es cada SEIS horas, así
 * que el hueco de un equipo ENCENDIDO queda en ~24 h + 6 h = ~30 h como mucho.
 * El umbral de «no se sabe» del backend (3 días) se apoya en esta cuenta: con
 * 30 h de hueco máximo, pasar de 3 días significa de verdad «apagado o roto».
 * Si alguien sube el intervalo del ciclo por política, rehaz la cuenta.
 */
export const MAX_INVENTORY_SILENCE_MS = 24 * 60 * 60 * 1000;

export type FactsSendReason = "changes" | "initial" | "version" | "silence";

export function decideFactsSend(input: {
  hasAnyChanges: boolean;
  forceInitialSnapshot: boolean;
  versionChanged: boolean;
  /** `lastSentFactsAt:inventory` del outbox; null/NaN/0 si nunca se estampó. */
  lastSentAtMs: number | null | undefined;
  nowMs: number;
}): { send: boolean; reasons: FactsSendReason[] } {
  const reasons: FactsSendReason[] = [];
  if (input.hasAnyChanges) reasons.push("changes");
  if (input.forceInitialSnapshot) reasons.push("initial");
  if (input.versionChanged) reasons.push("version");

  const last = Number(input.lastSentAtMs);
  // Sin marca previa cuenta como vencido: un envío de más una vez es mejor que
  // no saber. Una marca en el FUTURO (reloj que saltó hacia atrás) también:
  // esperar a que el reloj la alcance podría ser días de silencio.
  const silenceExceeded =
    !Number.isFinite(last) || last <= 0 || last > input.nowMs || input.nowMs - last > MAX_INVENTORY_SILENCE_MS;
  if (silenceExceeded) reasons.push("silence");

  return { send: reasons.length > 0, reasons };
}
