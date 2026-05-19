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
  current: Printer[]
): PrinterInventory {
  const previous = loadPrinterBaseline() ?? [];
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
      hasChanges: true
    };
  }

  const deltaResult = computePrinterDelta(current, previous);

  if (!deltaResult.hasChanges) {
    return {
      count: deltaResult.currentCount,
      items: undefined,
      delta: null,
      hasChanges: false
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
    hasChanges: true
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
