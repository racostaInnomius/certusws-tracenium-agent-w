// src/domain/printer-inventory-delta.ts
//
// Delta engine for printer inventory. Direct mirror of
// software-inventory-delta.ts — same shape, same contract, just with
// the Printer model instead of SoftwareApplication. Kept as a separate
// file (not a generic) because:
//
//   1. The "did this row change?" predicate is asset-specific
//      (isPrinterUpdated below uses different fields than
//      isAppUpdated). Forcing a generic would hide that logic behind a
//      callback and obscure each asset's identity definition.
//
//   2. The added/removed/updated array members are Printer-typed in
//      the wire payload — the backend's projection table inserts/
//      updates rely on the field set being known statically.

import { Printer } from "./printer";

export interface PrinterDelta {
  added: Printer[];
  removed: Printer[];
  updated: Printer[];
  unchanged: number;
}

export interface PrinterDeltaResult {
  delta: PrinterDelta;
  hasChanges: boolean;
  currentCount: number;
}

/**
 * Compute delta between current and previous printer inventories.
 * Identity is `installId` (same convention as software). Rows missing
 * an installId are silently skipped — collectors should always emit
 * one, but if a future bug ever leaks a malformed row we'd rather
 * lose it from the delta than corrupt the baseline.
 */
export function computePrinterDelta(
  current: Printer[],
  previous: Printer[]
): PrinterDeltaResult {
  const prevMap = new Map<string, Printer>();
  const currMap = new Map<string, Printer>();

  for (const p of previous) {
    const id = p?.installId ? String(p.installId) : "";
    if (!id) continue;
    prevMap.set(id, p);
  }

  for (const p of current) {
    const id = p?.installId ? String(p.installId) : "";
    if (!id) continue;
    currMap.set(id, p);
  }

  const added: Printer[] = [];
  const removed: Printer[] = [];
  const updated: Printer[] = [];

  for (const p of currMap.values()) {
    if (!p?.installId) continue;
    const prev = prevMap.get(p.installId);
    if (!prev) {
      added.push(p);
      continue;
    }
    if (isPrinterUpdated(prev, p)) {
      updated.push(p);
    }
  }

  for (const p of prevMap.values()) {
    if (!p?.installId) continue;
    if (!currMap.has(p.installId)) {
      removed.push(p);
    }
  }

  const sortById = (a: Printer, b: Printer) =>
    (a.installId || "").localeCompare(b.installId || "");

  added.sort(sortById);
  removed.sort(sortById);
  updated.sort(sortById);

  const unchanged = Math.max(
    0,
    currMap.size - added.length - updated.length
  );

  const delta: PrinterDelta = {
    added,
    removed,
    updated,
    unchanged
  };

  return {
    delta,
    hasChanges: Boolean(
      added.length || removed.length || updated.length
    ),
    currentCount: currMap.size
  };
}

/**
 * Decides whether a Printer row materially changed between snapshots.
 *
 * Status (online/offline/error) is INTENTIONALLY excluded — that
 * field is volatile (paper jam clears, printer wakes from sleep) and
 * treating it as a change would generate a stream of meaningless
 * "updated" events. The backend gets status with each baseline
 * snapshot anyway; if we ever want a separate status-event stream we
 * can add it without touching this comparison.
 *
 * isDefault is included because it represents an operator intent
 * change ("user changed which printer is the default"), which is
 * legitimately interesting to surface.
 */
function isPrinterUpdated(prev: Printer, curr: Printer): boolean {
  const prevDriver  = normalize(prev.driver);
  const currDriver  = normalize(curr.driver);
  const prevPort    = normalize(prev.port);
  const currPort    = normalize(curr.port);
  const prevLoc     = normalize(prev.location);
  const currLoc     = normalize(curr.location);
  const prevComm    = normalize(prev.comments);
  const currComm    = normalize(curr.comments);
  const prevDefault = Boolean(prev.isDefault);
  const currDefault = Boolean(curr.isDefault);
  const prevShared  = Boolean(prev.isShared);
  const currShared  = Boolean(curr.isShared);
  const prevNetwork = Boolean(prev.isNetwork);
  const currNetwork = Boolean(curr.isNetwork);

  if (
    prevDriver  === currDriver  &&
    prevPort    === currPort    &&
    prevLoc     === currLoc     &&
    prevComm    === currComm    &&
    prevDefault === currDefault &&
    prevShared  === currShared  &&
    prevNetwork === currNetwork
  ) {
    return false;
  }

  return true;
}

function normalize(value?: string | null): string {
  if (!value) return "";
  return value.trim().toLowerCase();
}

/**
 * Convert delta into incremental baseline operations. Same shape as
 * toBaselineOps in software-inventory-delta — keeps the call sites in
 * the providers symmetric across the two assets.
 */
export function toPrinterBaselineOps(delta: PrinterDelta) {
  const upserts: Printer[] = [...delta.added, ...delta.updated];
  const deletes: string[] = delta.removed
    .map(p => p.installId)
    .filter((id): id is string => Boolean(id));
  return { upserts, deletes };
}
