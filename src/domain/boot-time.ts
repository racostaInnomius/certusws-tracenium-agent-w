// Cuándo arrancó el sistema operativo.
//
// ⚠️ "La fecha del último reinicio" son DOS preguntas en Windows y ninguna
// fuente responde las dos:
//
//   · el contador monótono (`os.uptime()`, que en Windows es GetTickCount64)
//     NO cuenta el tiempo suspendido ni hibernado — un portátil que duerme
//     cada noche reporta menos tiempo del que lleva encendido;
//   · el instante absoluto que declara el sistema choca con el Inicio rápido,
//     donde "apagar" es hibernar la sesión de kernel y no un arranque.
//
// Por eso se recogen las dos cosas: el instante y el contador crudo. Donde
// discrepen, la discrepancia ES el diagnóstico —durmió, o inicio rápido— en
// lugar de un número silenciosamente equivocado. Un solo campo obligaría a
// elegir una definición y a callar la otra.
//
// ⚠️ Nada de esto abre un proceso. `os.uptime()` es una llamada al sistema y
// `/proc/stat` es leer un fichero. La receta clásica —`systeminfo | find
// "System Boot Time"`— es un subproceso caro y con salida LOCALIZADA, que es
// exactamente cómo un equipo con tres directivas de grupo aplicadas acabó
// contándose como equipo sin ninguna.

/** Tope de cordura: ningún equipo lleva 50 años encendido. */
const MAX_UPTIME_SECONDS = 50 * 365 * 24 * 3600;

export interface BootTimeReading {
  /** ISO 8601 en UTC, redondeado al minuto. `null` = no se pudo determinar. */
  bootTimeUtc: string | null;
  /** El contador crudo, tal cual lo dio el sistema. */
  uptimeSeconds: number | null;
}

export function normalizeUptimeSeconds(raw: unknown): number | null {
  // ⚠️ La conversión NO es `Number(raw)` a secas. `Number(null)`, `Number("")`
  // y `Number([])` valen 0, pasan `isFinite` y se convierten en "el equipo
  // acaba de arrancar" — toda la flota recién reiniciada porque a un colector
  // le faltó un campo. Es el mismo agujero que ya se coló en el cálculo de
  // distancias y en el fabricante de los paquetes: sólo un número, o una
  // cadena que de verdad contenga un número.
  let value: number;
  if (typeof raw === "number") {
    value = raw;
  } else if (typeof raw === "string" && raw.trim() !== "") {
    value = Number(raw);
  } else {
    return null;
  }
  if (!Number.isFinite(value)) return null;
  // Cero es legítimo durante el primer segundo tras arrancar, pero un negativo
  // no lo es nunca y un valor absurdo delata un contador roto.
  if (value < 0 || value > MAX_UPTIME_SECONDS) return null;
  return Math.floor(value);
}

/**
 * El instante del arranque a partir del contador, redondeado al MINUTO.
 *
 * ⚠️ El redondeo no es cosmético. `ahora − uptime` se recalcula en cada
 * snapshot y baila un par de segundos cada vez; sin redondear, cualquier
 * comparación posterior —"¿cambió la fecha de arranque?", una alerta de
 * "reinició anoche"— se llena de reinicios que no ocurrieron.
 */
export function bootTimeFromUptime(nowMs: number, uptimeSeconds: unknown): string | null {
  const uptime = normalizeUptimeSeconds(uptimeSeconds);
  if (uptime === null) return null;
  if (!Number.isFinite(nowMs) || nowMs <= 0) return null;

  const bootMs = nowMs - uptime * 1000;
  if (bootMs <= 0) return null;

  return new Date(Math.round(bootMs / 60_000) * 60_000).toISOString();
}

/**
 * El epoch del arranque que declara el kernel de Linux en `/proc/stat`.
 *
 * Es exacto y gratis, y a diferencia del contador no se ve afectado por la
 * suspensión. Cuando está, gana.
 */
export function parseProcStatBtime(text: unknown): number | null {
  if (typeof text !== "string") return null;

  for (const line of text.split("\n")) {
    const m = /^btime\s+(\d+)\s*$/.exec(line.trim());
    if (!m) continue;
    const seconds = Number(m[1]);
    // Un btime de 0 es un kernel que no lo sabe, no el 1 de enero de 1970.
    if (!Number.isFinite(seconds) || seconds <= 0) return null;
    return seconds;
  }

  return null;
}

export function bootTimeFromProcStat(text: unknown): string | null {
  const seconds = parseProcStatBtime(text);
  if (seconds === null) return null;
  return new Date(Math.round((seconds * 1000) / 60_000) * 60_000).toISOString();
}

/**
 * La lectura completa, con la fuente exacta por delante cuando existe.
 *
 * `readProcStat` sólo se pasa en Linux; devolver `null` desde ahí —fichero
 * ausente, sin permisos— cae al contador, que es peor pero no es nada.
 */
export function readBootTime(deps: {
  nowMs: number;
  uptimeSeconds: unknown;
  readProcStat?: () => string | null;
}): BootTimeReading {
  const uptime = normalizeUptimeSeconds(deps.uptimeSeconds);

  let bootTimeUtc: string | null = null;
  if (deps.readProcStat) {
    try {
      bootTimeUtc = bootTimeFromProcStat(deps.readProcStat());
    } catch {
      bootTimeUtc = null;
    }
  }
  if (bootTimeUtc === null) {
    bootTimeUtc = bootTimeFromUptime(deps.nowMs, uptime);
  }

  return { bootTimeUtc, uptimeSeconds: uptime };
}
