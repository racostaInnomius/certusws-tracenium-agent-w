// src/bootstrap/token-wait.ts
//
// Qué hacer cuando no hay token de enrollment.
//
// ⚠️ Lo que hacía antes: `throw`. El proceso moría, el gestor de servicios lo
// volvía a levantar cinco segundos después, y el ciclo se repetía. En campo eso
// produjo 3722 arranques en cinco días, 18610 renglones de log con un solo
// error distinto, y —lo peor— un servicio que parecía estar fallando
// intermitentemente cuando en realidad no había arrancado nunca. Quien lo
// levantaba a mano lo veía "arriba" un segundo y "abajo" al volver a mirar.
//
// Un fallo que se repite idéntico 3722 veces no es un reintento: es un bucle.
// Y reiniciar el proceso no puede arreglarlo, porque la causa no está en el
// proceso — está en una credencial que alguien tiene que poner.
//
// Así que el agente ya no muere: espera. Con espera creciente, con el log
// racionado, y volviendo a preguntar por el token en cada vuelta, de modo que
// cuando alguien lo escribe (registro, archivo) el agente lo toma solo. Ese es
// el caso real: en DANIELA-PC el token terminó estando presente. Con este
// cambio el equipo se habría enrolado sin que nadie tocara el servicio.

import fs from "fs";
import path from "path";
import { agentDataDir } from "./paths";
import {
  describeTokenLookup,
  resolveEnrollmentToken,
  type TokenLookup,
} from "./token-source";

/** Primera reespera. Corta: el caso frecuente es una carrera con el instalador. */
export const FIRST_RETRY_MS = 15_000;

/**
 * Tope de la espera.
 *
 * 15 minutos es el compromiso: bastante largo para que cinco días sean ~480
 * vueltas en vez de 3722 arranques, y bastante corto para que un operador que
 * acaba de escribir el token no se quede mirando la pantalla.
 */
export const MAX_RETRY_MS = 15 * 60_000;

/** El archivo que explica, en la máquina, por qué el agente no arrancó. */
export const BLOCKED_MARKER_NAME = "enrollment-blocked.txt";

/**
 * Espera creciente: 15 s, 30 s, 1 m, 2 m, 4 m, 8 m, y de ahí 15 m fijo.
 *
 * Sin jitter a propósito. Esto no es tráfico contra el control plane —no hay
 * nadie a quien saturar— y una cadencia predecible es más fácil de reconocer
 * en un log que una aleatoria.
 */
export function nextTokenWaitDelayMs(attempt: number): number {
  const n = Math.max(1, Math.floor(attempt));
  const delay = FIRST_RETRY_MS * Math.pow(2, n - 1);
  return Math.min(delay, MAX_RETRY_MS);
}

/**
 * Cuándo escribir en el log.
 *
 * Los tres primeros intentos siempre —es cuando alguien está mirando— y
 * después uno de cada ocho, que en el tope son ~2 horas. Cinco días caídos
 * pasan de 18610 renglones a unas 60.
 */
export function shouldLogAttempt(attempt: number): boolean {
  const n = Math.max(1, Math.floor(attempt));
  return n <= 3 || n % 8 === 0;
}

export interface TokenWaitLogger {
  info: (...args: any[]) => void;
  warn: (...args: any[]) => void;
  error: (...args: any[]) => void;
}

export interface TokenWaitDeps {
  read?: () => TokenLookup;
  sleep?: (ms: number) => Promise<void>;
  logger?: TokenWaitLogger;
  onBlocked?: (diagnosis: string) => void;
  onRecovered?: () => void;
  /** Sólo para pruebas: sin esto la espera no termina hasta que haya token. */
  maxAttempts?: number;
}

const defaultSleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Deja el motivo escrito en la máquina, junto a los logs.
 *
 * El log rotado ya lo dice, pero está enterrado entre miles de renglones y hay
 * que saber buscarlo. Un archivo con una sola cosa adentro es lo que encuentra
 * quien está frente al equipo sin conocer el producto.
 */
export function writeBlockedMarker(diagnosis: string, at: Date): void {
  try {
    const file = path.join(agentDataDir(), BLOCKED_MARKER_NAME);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(
      file,
      `Tracenium Agent — NOT ENROLLED\n${at.toISOString()}\n\n` +
        `The agent is running but cannot enroll: it has no enrollment token.\n` +
        `It is retrying on its own and will continue as soon as a token exists.\n\n` +
        `${diagnosis}\n`,
      "utf8"
    );
  } catch {
    // Un diagnóstico que no se pudo escribir no puede impedir el diagnóstico.
  }
}

export function clearBlockedMarker(): void {
  try {
    fs.rmSync(path.join(agentDataDir(), BLOCKED_MARKER_NAME), { force: true });
  } catch {}
}

/**
 * Espera a que exista un token y lo devuelve.
 *
 * Devuelve null sólo cuando se agotó un `maxAttempts` de prueba: en producción
 * no hay salida sin token, que es exactamente la intención — el proceso queda
 * vivo, silencioso y listo para continuar, en vez de morir y renacer.
 */
export async function waitForEnrollmentToken(
  deps: TokenWaitDeps = {}
): Promise<string | null> {
  const read = deps.read ?? resolveEnrollmentToken;
  const sleep = deps.sleep ?? defaultSleep;
  const log = deps.logger ?? console;
  const onBlocked = deps.onBlocked ?? ((d: string) => writeBlockedMarker(d, new Date()));
  const onRecovered = deps.onRecovered ?? clearBlockedMarker;

  let attempt = 0;

  for (;;) {
    attempt += 1;

    const lookup = read();
    if (lookup.token) {
      if (attempt > 1) {
        log.info(
          `[Enroll] Enrollment token appeared after ${attempt} checks. Continuing.`
        );
        onRecovered();
      }
      return lookup.token;
    }

    const diagnosis = describeTokenLookup(lookup);

    if (attempt === 1) {
      // El primer fallo es el que se lee. Va completo y con el remedio.
      log.error(
        "[Enroll] No enrollment token. The agent cannot enroll until one exists.\n" +
          diagnosis +
          "\nThe agent will keep checking and will continue on its own; " +
          "restarting the service will NOT help."
      );
      onBlocked(diagnosis);
    } else if (shouldLogAttempt(attempt)) {
      log.warn(`[Enroll] Still no enrollment token (check ${attempt}).`);
    }

    if (deps.maxAttempts !== undefined && attempt >= deps.maxAttempts) {
      return null;
    }

    await sleep(nextTokenWaitDelayMs(attempt));
  }
}
