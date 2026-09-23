// src/core/shutdown.ts
//
// Parar el agente SIN que Windows lo cuente como una caída.
//
// ⚠️ POR QUÉ EXISTE (23-sep-2026, FTP-SPS de Mountainside). Cada vez que el
// agente se actualizaba solo, el visor de eventos del servidor se quedaba con
// esto:
//
//   22:34:12  TraceniumAgentCore  Child process [23100 - node.exe ...]
//                                 finished with -1073741510
//   22:34:13  SCM (7031, Error)   The Tracenium Agent Core service terminated
//                                 unexpectedly. It has done this 1 time(s).
//
// `-1073741510` es `0xC000013A` = STATUS_CONTROL_C_EXIT: el proceso murió por
// el manejador POR DEFECTO de un evento de consola. WinSW para al hijo
// mandándole un evento CTRL, y Node lo entrega como señal: CTRL_C → `SIGINT`,
// **CTRL_BREAK → `SIGBREAK`**, cierre de consola → `SIGHUP`. Sólo teníamos
// manejadores de `SIGINT` y `SIGTERM`, así que el CTRL_BREAK caía en el
// manejador por defecto de Windows, que MATA el proceso con ese código. WinSW
// veía una salida distinta de cero, el SCM escribía un 7031 rojo, y la parada
// más ordinaria del mundo —la de nuestro propio instalador— quedaba registrada
// como un fallo del servicio.
//
// El coste no fue técnico sino de confianza: cuando ese servidor se quedó sin
// dar sesión a los usuarios, el 7031 de la noche anterior era la única línea en
// rojo del log, y soporte concluyó que Tracenium había tumbado la máquina. No
// lo había hecho —el agente estuvo muestreando cada minuto durante toda la
// incidencia— pero nosotros habíamos dejado la prueba falsa en su visor.
//
// Salir con 0 ante CUALQUIERA de las señales de parada arregla las dos cosas:
// el servicio se para limpio y el SCM no escribe nada.

/**
 * Todo lo que significa «te están parando» en las dos plataformas.
 *
 * ⚠️ `SIGBREAK` es el que faltaba y es el que manda un servicio de Windows al
 * pararse; en Linux/macOS no existe y `process.on` lo ignora sin quejarse.
 * `SIGHUP` cubre el cierre de la consola (CTRL_CLOSE_EVENT), que mata igual.
 */
export const SHUTDOWN_SIGNALS = ["SIGTERM", "SIGINT", "SIGBREAK", "SIGHUP"] as const;

export type ShutdownSignal = (typeof SHUTDOWN_SIGNALS)[number];

/** Lo mínimo de `process` que esto necesita — así el test no usa el real. */
export interface ShutdownTarget {
  on(signal: string, handler: () => void): unknown;
  exit(code: number): never | void;
}

/**
 * Registra la parada ordenada. Devuelve las señales atendidas, que es lo que
 * un test puede comprobar sin matar al corredor de pruebas.
 *
 * El código de salida es SIEMPRE 0: lo contrario es lo que el SCM lee como
 * «terminó inesperadamente». Una parada pedida por el sistema no es un fallo.
 */
export function registerShutdownHandlers(
  target: ShutdownTarget,
  log: (message: string) => void = console.log
): readonly ShutdownSignal[] {
  for (const signal of SHUTDOWN_SIGNALS) {
    target.on(signal, () => {
      log(`[INFO] ${signal} received. Shutting down...`);
      target.exit(0);
    });
  }
  return SHUTDOWN_SIGNALS;
}
