// src/domain/software-inventory-delta.ts

import { SoftwareApplication } from "./normalize-app";

export interface SoftwareDelta {
  added: SoftwareApplication[];
  removed: SoftwareApplication[];
  updated: SoftwareApplication[];
  unchanged: number;
}

export interface SoftwareDeltaResult {
  delta: SoftwareDelta;
  hasChanges: boolean;
  currentCount: number;
}

/**
 * Compute delta between current and previous software inventories.
 * Comparison is based on installId (stable identity).
 */
export function computeSoftwareDelta(
  current: SoftwareApplication[],
  previous: SoftwareApplication[]
): SoftwareDeltaResult {
  const prevMap = new Map<string, SoftwareApplication>();
  const currMap = new Map<string, SoftwareApplication>();

  for (const app of previous) {
    const id = app?.installId ? String(app.installId) : "";
    if (!id) continue;
    // last-write-wins for duplicates
    prevMap.set(id, app);
  }

  for (const app of current) {
    const id = app?.installId ? String(app.installId) : "";
    if (!id) continue;
    // last-write-wins for duplicates
    currMap.set(id, app);
  }

  const added: SoftwareApplication[] = [];
  const removed: SoftwareApplication[] = [];
  const updated: SoftwareApplication[] = [];

  // Added + Updated
  for (const app of currMap.values()) {
    if (!app?.installId) continue;
    const prev = prevMap.get(app.installId);

    if (!prev) {
      added.push(app);
      continue;
    }

    if (isAppUpdated(prev, app)) {
      updated.push(app);
    }
  }

  // Removed
  for (const app of prevMap.values()) {
    if (!app?.installId) continue;
    if (!currMap.has(app.installId)) {
      removed.push(app);
    }
  }

  // Sort outputs for deterministic ordering
  const sortById = (a: SoftwareApplication, b: SoftwareApplication) =>
    (a.installId || "").localeCompare(b.installId || "");

  added.sort(sortById);
  removed.sort(sortById);
  updated.sort(sortById);

  const unchanged = Math.max(
    0,
    currMap.size - added.length - updated.length
  );

  const delta: SoftwareDelta = {
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
 * Determines if an application changed between snapshots.
 * Ignores trivial/noisy changes (e.g. whitespace-only version changes).
 */
function isAppUpdated(
  prev: SoftwareApplication,
  curr: SoftwareApplication
): boolean {
  // Normalize all comparable fields
  const prevVersion = normalize(prev.version);
  const currVersion = normalize(curr.version);

  const prevPublisher = normalize(prev.publisher);
  const currPublisher = normalize(curr.publisher);

  const prevLocation = normalize(prev.installLocation);
  const currLocation = normalize(curr.installLocation);

  const prevPkg = normalize(prev.packageFamilyName);
  const currPkg = normalize(curr.packageFamilyName);

  // Ignore changes if all normalized values are identical
  if (
    prevVersion === currVersion &&
    prevPublisher === currPublisher &&
    prevLocation === currLocation &&
    prevPkg === currPkg
  ) {
    return false;
  }

  return true;
}

/**
 * Normalize comparison values to avoid false positives.
 */
function normalize(value?: string | null): string {
  if (!value) return "";
  return value.trim().toLowerCase();
}

/**
 * Optional helper to convert delta into event-based model.
 */
export type SoftwareEvent =
  | { type: "installed"; app: SoftwareApplication }
  | { type: "removed"; installId: string }
  | { type: "updated"; app: SoftwareApplication };

export function toSoftwareEvents(delta: SoftwareDelta) {
  const events: SoftwareEvent[] = [];

  for (const app of delta.added) {
    events.push({
      type: "installed",
      app
    });
  }

  for (const app of delta.removed) {
    events.push({
      type: "removed",
      installId: app.installId
    });
  }

  for (const app of delta.updated) {
    events.push({
      type: "updated",
      app
    });
  }

  return events;
}

/**
 * Convert delta into incremental baseline operations.
 * - upserts: added + updated
 * - deletes: installIds of removed
 */
export function toBaselineOps(delta: SoftwareDelta) {
  const upserts: SoftwareApplication[] = [
    ...delta.added,
    ...delta.updated
  ];

  const deletes: string[] = delta.removed
    .map(a => a.installId)
    .filter((id): id is string => Boolean(id));

  return { upserts, deletes };
}