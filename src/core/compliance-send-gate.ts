// src/core/compliance-send-gate.ts
//
// ¿Hay que mandar el snapshot de cumplimiento (SCP) en este tick?
//
// P3-11 de SCP-VALIDACION-PROD-2026-09-16.md. SCP sólo se enviaba si cambiaba
// el hash del namespace. Un equipo estable no mandaba nada durante días, y el
// servidor no tenía snapshot con el que decir "este equipo estuvo evaluado
// ese día": la evidencia de operación continua dependía de que algo cambiara.
// Medido el 16-sep en 14 días: T111 con snapshot en 9,1 de 10,7 días activos
// y 3 de 55 equipos por debajo de la mitad.
//
// Ahora, sin cambios, se manda igual si el último envío de cumplimiento tiene
// más de MAX_COMPLIANCE_SILENCE_MS. Mismo patrón que el latido de inventario
// (inventory-send-gate.ts). El backend evalúa el SCP sin mirar `hasChanges`,
// así que el latido deja un snapshot con fecha.
//
// 24 h: el ciclo de cumplimiento corre por defecto cada 8 h, así que un equipo
// encendido queda con un snapshot al menos cada ~32 h, y como mucho uno extra
// al día sobre lo que ya mandaba.

export const MAX_COMPLIANCE_SILENCE_MS = 24 * 60 * 60 * 1000;

export type ComplianceSendReason = "changes" | "silence";

export function decideComplianceSend(input: {
  hasChanges: boolean;
  /** `lastSentFactsAt:compliance` del outbox; null/NaN/0 si nunca se estampó. */
  lastSentAtMs: number | null | undefined;
  nowMs: number;
}): { send: boolean; reasons: ComplianceSendReason[] } {
  const reasons: ComplianceSendReason[] = [];
  if (input.hasChanges) reasons.push("changes");
  const last = Number(input.lastSentAtMs);
  // Sin marca, o una marca en el futuro (reloj que saltó atrás): vencido.
  const silenceExceeded =
    !Number.isFinite(last) || last <= 0 || last > input.nowMs || input.nowMs - last > MAX_COMPLIANCE_SILENCE_MS;
  if (silenceExceeded) reasons.push("silence");
  return { send: reasons.length > 0, reasons };
}
