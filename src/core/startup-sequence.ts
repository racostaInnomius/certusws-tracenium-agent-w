// src/core/startup-sequence.ts
//
// En qué orden y cuándo corren los escaneos al ARRANCAR el servicio. Puro.
//
// ⚠️ POR QUÉ (prod, 16-sep)
// Al arrancar, `startPipelines` lanzaba compliance, CDP y el escaneo de parches
// a la vez. En Windows los tres van por el MISMO carril serial del PrivSvc, y el
// escaneo de Windows Update recién encendida la máquina es lento de por sí:
//   · TNS-OPER-SNOC04: arranque 18:20, escaneo 18:27 «Windows Update scan
//     exceeded 150s»; el de 38 s después, bien.
//   · MarisolCorona: arranque 10:15, escaneo 10:31 «PrivSvc timeout … waited
//     390178ms for the IPC slow lane behind security.compliance».
// De 42 «exceeded 150s» fuera del equipo crónico, 29 fueron el primer escaneo
// tras más de 8 h sin escanear: el equipo recién encendido.
//
// Ahora, al arrancar:
//   · compliance → CDP → parches, EN SERIE: cada uno espera a que acabe el
//     anterior, así ninguno hace cola detrás de otro en el carril.
//   · el de parches, además, espera a que la MÁQUINA lleve encendida
//     STARTUP_PATCH_MIN_UPTIME_MS. Uptime de la máquina, no del proceso: un
//     reinicio del agente en un servidor que lleva semanas arriba no espera.
// Un paso colgado no bloquea a los siguientes más de STARTUP_STEP_CAP_MS.

import type { PipelineKey } from "./pipeline-plan";

/** Los que van por el carril del PrivSvc, en este orden. */
export const STARTUP_SERIAL_ORDER: readonly PipelineKey[] = ["compliance", "cdp", "patch"];

/** SNOC04 escaneó bien a los ~8 min de arrancar; 10 deja margen. */
export const STARTUP_PATCH_MIN_UPTIME_MS = 10 * 60_000;

/**
 * Techo por paso. Por encima del escaneo más largo legítimo en arranque
 * (patch.scan: cliente IPC 240 s), por debajo de lo que tolera un arranque:
 * un paso colgado no puede dejar sin compliance ni parches al equipo hasta el
 * ciclo siguiente.
 */
export const STARTUP_STEP_CAP_MS = 10 * 60_000;

/**
 * Cuánto esperar antes del escaneo de parches de arranque.
 * Uptime ilegible → no se espera: un dato raro no puede retrasar el escaneo.
 */
export function startupPatchDelayMs(
  machineUptimeSeconds: number,
  minUptimeMs: number = STARTUP_PATCH_MIN_UPTIME_MS
): number {
  if (!Number.isFinite(machineUptimeSeconds) || machineUptimeSeconds < 0) return 0;
  return Math.max(0, Math.ceil(minUptimeMs - machineUptimeSeconds * 1000));
}
