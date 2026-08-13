// src/core/namespace-hash.ts
//
// Pure helpers for the scheduler's change-detection gate: a stable
// (key-sorted) JSON hash of each namespace, computed over a projection
// that strips fields which must never count as "change". Extracted from
// scheduler.ts so they are unit-testable without dragging in the
// outbox/update-task import graph.

import crypto from "crypto";
import type { PmpNamespace } from "../domain/pmp-types";
import type { ScpNamespace } from "../domain/scp-types";

export function normalizeForHash(value: unknown): unknown {
  if (value === undefined) {
    return null;
  }

  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(normalizeForHash);
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entryValue]) => [key, normalizeForHash(entryValue)]);

  return Object.fromEntries(entries);
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map((key) => `"${key}":${stableStringify((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

export function hashNamespace(value: unknown): string {
  return crypto.createHash("sha256").update(stableStringify(normalizeForHash(value))).digest("hex");
}

export function buildScpStateForHash(namespace: ScpNamespace) {
  const { hasChanges: _ignored, ...rest } = namespace;

  // patches.lastScanUtc is stamped by privsvc on EVERY collection
  // (DateTime.UtcNow on Windows, new Date() on macOS), so leaving it
  // in the hash made hasChanges always-true on those platforms — a
  // full SCP snapshot (including the complete Windows Update history)
  // shipped every tick even with zero posture drift. Linux never
  // forwarded the field, which is why the gate still worked there.
  // Strip it; the backend takes collectedAtUtc from the envelope, not
  // from inside the evidence.
  const patches = rest.patches;
  if (patches && typeof patches === "object" && !Array.isArray(patches)) {
    const { lastScanUtc: _volatile, ...stablePatches } = patches as Record<string, unknown>;
    return { ...rest, patches: stablePatches };
  }
  return rest;
}

export function buildPmpStateForHash(namespace: PmpNamespace) {
  const { hasChanges: _ignored, ...rest } = namespace;
  return rest;
}
