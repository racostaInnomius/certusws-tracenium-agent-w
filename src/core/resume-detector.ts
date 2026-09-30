// src/core/resume-detector.ts
//
// ¿El equipo estuvo suspendido desde la última comprobación?
//
// 🔴 AquilesF (T111, Surface Pro con Modern Standby), 29-sep: el supervisor de
// conectividad midió "reconnect loop stalled for 14245s" y mató el agente con
// process.exit(1) en un despertar de un momento a las 05:32Z. Esos 14245 s eran
// el portátil DORMIDO desde las 01:34:46: nadie iteraba porque no había CPU, no
// porque la maquinaria de reconexión estuviera colgada. El watchdog de liveness
// hizo la misma cuenta ("tray-status was stale for 14245s").
//
// Los dos vigilantes son un setInterval que compara Date.now() con una marca
// anterior, y el reloj de pared sigue corriendo con la máquina suspendida. La
// firma de la suspensión es que el propio intervalo llega tardísimo: si entre
// dos ticks pasan varias veces el periodo, al proceso no le tocó CPU, y lo que
// haya "tardado" cualquier cosa en ese hueco no es culpa de nadie.
//
// No esconde lo que los vigilantes buscan:
//   - el supervisor de conectividad caza un loop VIVO cuyos reintentos no
//     avanzan (un priv.call que nunca vuelve): ahí los ticks llegan puntuales;
//   - un event loop bloqueado de verdad no ejecuta los ticks en absoluto, así
//     que ningún vigilante JS lo rescataba antes tampoco.
// Un bloqueo SÍNCRONO largo (una llamada nativa de 20 min) también llega como
// hueco, y se trata igual que una suspensión: el watchdog de liveness ya decidía
// no matar en ese caso (v2, sonda de escritura).

/** Un hueco entre ticks mayor que `intervalMs × RESUME_GAP_FACTOR` es una suspensión. */
export const RESUME_GAP_FACTOR = 3;

export type ResumeDetector = {
  /**
   * Llamar al principio de cada tick. Devuelve los ms del hueco si desde el
   * tick anterior pasó bastante más que el intervalo (el equipo estuvo
   * suspendido o sin CPU), o null si el tick llegó a su hora.
   */
  check(): number | null;
};

export function createResumeDetector(intervalMs: number, now: () => number = Date.now): ResumeDetector {
  let lastTickAtMs = now();
  return {
    check() {
      const t = now();
      const gap = t - lastTickAtMs;
      lastTickAtMs = t;
      return gap > intervalMs * RESUME_GAP_FACTOR ? gap : null;
    }
  };
}
