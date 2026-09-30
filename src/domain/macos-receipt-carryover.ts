// src/domain/macos-receipt-carryover.ts
//
// Un recibo de pkgutil que no se pudo LEER no se desinstaló.
//
// ⚠️ EL DEFECTO (T1, iMac-de-iMac-2.local, 30-sep 05:33Z). A las 05:32:55 se
// lanzó un `installer` con la cola de PackageKit atascada; `pkgutil` se colgó
// y el escaneo de un minuto después se quedó SIN recibos: el `catch` de
// `pkgutil --pkgs` los descartaba todos en silencio, y `--pkg-info` que
// fallaba trataba el recibo como huérfano. El delta dio por desinstalados 18
// (Safari, Zoom, Wacom, el propio Tracenium Agent) y el escaneo de las 11:32
// los «reinstaló». Mismo patrón, 14 días: el iMac otra vez el 19-sep,
// CLIFIJIMENEZlocal y JPR-MacBookPro. Activity lo contaba dos veces.
//
// Es la misma regla que las apps por usuario de Windows con el perfil sin
// sesión (software-user-hive-carryover): «no pude leerlo» ≠ «no está». De lo
// que no se pudo leer se conserva lo que la línea base ya sabía, tal cual. Un
// recibo que desaparece de verdad deja de salir en `pkgutil --pkgs` en el
// siguiente escaneo que funcione, y entonces sí se va.

import type { SoftwareApplication } from "./normalize-app";

/** Lo que el colector de pkgutil no pudo leer en este escaneo. */
export type ReceiptReadGap = {
  /** `pkgutil --pkgs` falló: no se sabe qué recibos hay. */
  all: boolean;
  /** Recibos listados cuyo `--pkg-info` falló (id canónico, sin versión). */
  ids: Set<string>;
};

export const NO_RECEIPT_GAP: ReceiptReadGap = Object.freeze({ all: false, ids: new Set<string>() }) as ReceiptReadGap;

const RECEIPT_SOURCE = "pkgutil";

/**
 * El inventario de este escaneo más los recibos de la línea base que no se
 * pudieron leer y hoy no aparecen.
 */
export function carryOverUnreadReceipts(
  current: SoftwareApplication[],
  previous: SoftwareApplication[],
  gap: ReceiptReadGap
): { apps: SoftwareApplication[]; carried: number } {
  if (!gap.all && gap.ids.size === 0) return { apps: current, carried: 0 };
  const seen = new Set(current.map((a) => a.installId).filter(Boolean));
  const carried = previous.filter((p) => {
    if (!p.installId || seen.has(p.installId)) return false;
    if (String(p.source ?? "").toLowerCase() !== RECEIPT_SOURCE) return false;
    return gap.all || gap.ids.has(String(p.packageFamilyName ?? p.name ?? ""));
  });
  return carried.length === 0 ? { apps: current, carried: 0 } : { apps: [...current, ...carried], carried: carried.length };
}
