// src/domain/battery.ts
//
// La batería del equipo, para `hardware.runtime.battery`.
//
// 🔴 Hasta aquí el agente NO la mandaba en ninguna plataforma: el backend
// leía `hardware.static.battery.percent` y nadie la escribía — 0 de 83 equipos
// con dato en prod (24-sep), portátiles incluidos. Y va en `runtime`, no en
// `static`, a propósito: el backend deduplica el hardware por el hash de
// `static`, y la carga cambia a cada minuto; en `static` rompería esa dedup.
//
// `present: false` es una respuesta ("no tiene batería": sobremesa, servidor,
// VM), distinta de no mandar el bloque ("no se pudo leer").

export type BatteryRuntime = {
  present: boolean;
  /** Carga 0–100, o null si el sistema no la dio. */
  percent: number | null;
  isCharging: boolean | null;
  acConnected: boolean | null;
};

const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);

/** Lo que devuelve `si.battery()`, reducido y validado. undefined = no leído. */
export function normalizeBattery(raw: any): BatteryRuntime | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  if (raw.hasBattery !== true) {
    // systeminformation devuelve hasBattery=false tanto en un sobremesa como
    // cuando no pudo consultar; sólo lo damos por "sin batería" si lo dijo
    // explícitamente.
    return raw.hasBattery === false
      ? { present: false, percent: null, isCharging: null, acConnected: bool(raw.acConnected) }
      : undefined;
  }
  const n = Number(raw.percent);
  // 0 con batería presente es posible (agotada), pero un número fuera de rango
  // o no numérico es basura del driver, no una carga.
  const percent = raw.percent !== null && raw.percent !== "" && Number.isFinite(n) && n >= 0 && n <= 100 ? Math.round(n) : null;
  return { present: true, percent, isCharging: bool(raw.isCharging), acConnected: bool(raw.acConnected) };
}
