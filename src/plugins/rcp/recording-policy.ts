// src/plugins/rcp/recording-policy.ts
//
// ¿Está activada la grabación de sesiones de pantalla? (ADR-0012, decisión 2)
//
// Una línea de código en su propio fichero, y hay un motivo: la respuesta la
// consumen DOS sitios que no pueden discrepar —el texto del consentimiento y
// el indicador permanente— y discrepar significaría enseñarle a alguien un
// diálogo que no menciona la grabación y luego grabarle, o al revés.
//
// Leerlo en cada uso, y no cachearlo al arrancar, es deliberado: la política
// llega por push y un tenant puede activar o desactivar la grabación mientras
// el agente lleva semanas corriendo. Un valor leído una vez mentiría el resto
// del tiempo, y aquí mentir tiene consecuencias legales.

import type { AgentContext } from "../../core/agent-context";

export function recordingEnabled(ctx: AgentContext): boolean {
  try {
    return Boolean(ctx.policyRuntime?.isFeatureEnabled?.("remoteRecordScreen"));
  } catch {
    // Sin política legible no se graba. Es la dirección segura: la alternativa
    // sería guardar vídeo de la pantalla de alguien por no haber podido leer
    // un fichero.
    return false;
  }
}
