// src/plugins/amp/providers/printers-pipeline.ts
//
// Shared post-collection pipeline for printers: turn a raw Printer[]
// snapshot (from any platform collector) into the PrinterInventory
// payload + persist the baseline. Same flow as the inline software
// pipeline in providers/windows.ts:
//
//   1. First run (no baseline) → ship full items[], hasChanges=true,
//      upsert all rows.
//   2. Subsequent run with changes → compute delta, upsert/delete
//      against baseline, ship delta but ELIDE items[] (the backend's
//      device_printers projection is maintained incrementally).
//   3. Subsequent run without changes → no items, no delta,
//      hasChanges=false. Scheduler skips this dimension entirely.
//
// Centralizing this here keeps providers/windows.ts, providers/macos.ts
// and providers/linux.ts symmetric and tiny — they only need to
// produce the raw Printer[] and hand it to this function.

import type { PrinterInventory } from "../../../domain/amp-types";
import type { Printer } from "../../../domain/printer";
import { printerNoiseKind } from "../../../domain/printer";
import {
  computePrinterDelta,
  toPrinterBaselineOps
} from "../../../domain/printer-inventory-delta";
import {
  loadPrinterBaseline,
  upsertPrinterBaseline,
  deletePrintersByIds
} from "../../../domain/printer-baseline-repo";

export function buildPrinterInventoryWithBaseline(
  collected: Printer[],
  /**
   * Alcances de la lectura (Windows). Ver PrinterInventory.machineScope.
   *
   * ⚠️ `measured=false` significa que NO se pudo mirar. Es distinto de mirar y
   * no encontrar nada, y la diferencia importa aquí más que en ningún sitio:
   * la primera ejecución PERSISTE la baseline, así que grabar una lista vacía
   * que en realidad era un fallo de lectura convierte "no pude" en "no tiene"
   * de forma permanente — las ejecuciones siguientes ya no ven cambio y el
   * equipo se queda sin impresoras para siempre.
   */
  scopes?: { machineScope: string; userScope: string }
): PrinterInventory {
  // Las colas de sesión RDP y las virtuales se quedan en el equipo (ver
  // printerNoiseKind). Se filtran ANTES del delta: una baseline que ya las
  // tenía las da de baja en la próxima lectura completa, y el backend borra
  // sus filas sin migración.
  const current = collected.filter((p) => printerNoiseKind(p) === null);
  const read = classifyPrinterRead(scopes);

  if (read === "blind") {
    // Nada se leyó: ni baseline, ni cambio. El count es el ÚLTIMO CONOCIDO y
    // no 0 — el backend lo escribe en host_current_status.total_printers, y
    // un cero ahí es un hecho falso sobre el equipo.
    return {
      count: (loadPrinterBaseline() ?? []).length,
      items: undefined,
      delta: null,
      hasChanges: false,
      machineScope: scopes!.machineScope,
      userScope: scopes!.userScope
    };
  }

  const previous = loadPrinterBaseline() ?? [];

  if (read === "partial") {
    return applyPartialRead(current, previous, scopes!);
  }

  const isFirstRun = previous.length === 0;

  if (isFirstRun) {
    // Even when `current` is empty we still flip hasChanges=true on
    // the first run, so the backend records the (empty) initial
    // baseline — otherwise a device with no printers would forever
    // look like "we never collected printers" to the backend.
    upsertPrinterBaseline(current);
    return {
      count: current.length,
      items: current,
      delta: null,
      hasChanges: true,
      ...scopes
    };
  }

  const deltaResult = computePrinterDelta(current, previous);

  if (!deltaResult.hasChanges) {
    return {
      count: deltaResult.currentCount,
      items: undefined,
      delta: null,
      hasChanges: false,
      ...scopes
    };
  }

  const { upserts, deletes } = toPrinterBaselineOps(deltaResult.delta);
  if (upserts.length > 0) upsertPrinterBaseline(upserts);
  if (deletes.length > 0) deletePrintersByIds(deletes);

  // Same payload reduction as software: don't reship items[] when
  // the backend can rebuild current state from the delta. The first-
  // run path above is the only one that ever ships items[].
  return {
    count: deltaResult.currentCount,
    items: undefined,
    delta: deltaResult.delta,
    hasChanges: true,
    // ⚠️ Los tres caminos llevan los alcances; éste los perdía.
    ...scopes
  };
}

/**
 * Qué se puede concluir de una lectura, según sus alcances (Windows).
 *
 *   complete — la lista es la verdad: altas, cambios Y bajas.
 *   partial  — una mitad se leyó y la otra falló: altas y cambios sí, bajas
 *              NO, porque lo que falta puede ser justo lo que no se miró.
 *   blind    — no se leyó ninguna mitad: no se concluye nada.
 *
 * ⚠️ HASTA 2026-09-14 SÓLO `machineScope: "unavailable"` CONTABA COMO CIEGO.
 * Un `timeout` del Spooler —el caso que su propio comentario en privsvc
 * describe como "Spooler colgado"— con nadie conectado era una lista vacía
 * MEDIDA: delta con todo en `removed`, y el backend borraba las filas del
 * equipo. En el primer ciclo era peor: baseline vacía grabada y anunciada,
 * que el backend aplica como "no tiene impresoras".
 *
 * Por eso se enumera lo BUENO y no lo malo: sólo `collected` es una lectura
 * de máquina. `timeout`, `empty_output`, `unknown` (privsvc anterior a los
 * alcances) y cualquier valor que privsvc invente mañana cuentan como fallo.
 *
 * `no_user_hive` con la máquina leída sigue siendo `complete`: sin nadie
 * conectado no hay conexiones de usuario que leer, y tratarlo como parcial
 * dejaría a un servidor sin sesiones sin poder registrar nunca una baja.
 */
export function classifyPrinterRead(
  scopes?: { machineScope: string; userScope: string }
): "complete" | "partial" | "blind" {
  if (!scopes) return "complete"; // macOS/Linux: una sola lectura, sin alcances
  const machineRead = scopes.machineScope === "collected";
  const userRead = scopes.userScope === "collected";
  const userSettled = userRead || scopes.userScope === "no_user_hive";

  if (machineRead && userSettled) return "complete";
  if (machineRead || userRead) return "partial";
  return "blind";
}

/**
 * Lectura a medias: se aplican las altas y los cambios de lo que SÍ se vio, y
 * lo que no aparece se da por presente hasta la próxima lectura completa.
 *
 * Siempre por delta, también sin baseline previa: el backend aplica `items[]`
 * como SUSTITUCIÓN (DELETE + INSERT), y una lectura incompleta no puede
 * sustituir nada. Y sin baseline ni filas no hay cambio que anunciar — nunca
 * se graba una baseline vacía desde aquí.
 */
function applyPartialRead(
  current: Printer[],
  previous: Printer[],
  scopes: { machineScope: string; userScope: string }
): PrinterInventory {
  const { delta } = computePrinterDelta(current, previous);
  const upserts = [...delta.added, ...delta.updated];
  if (upserts.length > 0) upsertPrinterBaseline(upserts);

  // Lo visto más lo que no se vio pero no consta que se fuera.
  const count = previous.length + delta.added.length;

  if (upserts.length === 0) {
    return { count, items: undefined, delta: null, hasChanges: false, ...scopes };
  }

  return {
    count,
    items: undefined,
    delta: { ...delta, removed: [], unchanged: Math.max(0, count - upserts.length) },
    hasChanges: true,
    ...scopes
  };
}

/**
 * Convenience fallback used when a collector throws or returns a
 * malformed snapshot. Returns the cheapest possible PrinterInventory
 * payload (hasChanges=false) so the caller's overall AmpNamespace
 * remains shippable.
 *
 * NOTE: we intentionally do NOT touch the baseline here — if today's
 * collection failed transiently, the previous baseline is still our
 * best guess at "what's on this device". A bad cycle shouldn't blow
 * away the device's printer history.
 */
export function emptyPrinterInventory(): PrinterInventory {
  return {
    count: 0,
    items: undefined,
    delta: null,
    hasChanges: false
  };
}
