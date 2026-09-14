// src/domain/browser-extension-inventory-delta.ts
//
// Delta del inventario de extensiones. Mismo contrato que
// printer-inventory-delta.ts: identidad por `installId`, y un "cambió" que
// mira sólo lo que importa al operador.
//
// ⚠️ `permissions` y `hostPermissions` SÍ cuentan como cambio. Una extensión
// que en una actualización pasa de "tabs" a "<all_urls>" es exactamente el
// patrón de una extensión comprada y convertida en malware — ese `updated`
// es el evento que más vale del inventario entero.

import type { BrowserExtension } from "./browser-extension";

export interface BrowserExtensionDelta {
  added: BrowserExtension[];
  removed: BrowserExtension[];
  updated: BrowserExtension[];
  unchanged: number;
}

export interface BrowserExtensionDeltaResult {
  delta: BrowserExtensionDelta;
  hasChanges: boolean;
  currentCount: number;
}

const byId = (a: BrowserExtension, b: BrowserExtension) => (a.installId || "").localeCompare(b.installId || "");

function sameList(a: string[] | undefined, b: string[] | undefined): boolean {
  const x = [...(a ?? [])].sort();
  const y = [...(b ?? [])].sort();
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

export function isExtensionUpdated(prev: BrowserExtension, curr: BrowserExtension): boolean {
  return !(
    prev.name === curr.name &&
    (prev.version ?? null) === (curr.version ?? null) &&
    (prev.enabled ?? null) === (curr.enabled ?? null) &&
    prev.installSource === curr.installSource &&
    (prev.manifestVersion ?? null) === (curr.manifestVersion ?? null) &&
    (prev.updateUrl ?? null) === (curr.updateUrl ?? null) &&
    sameList(prev.permissions, curr.permissions) &&
    sameList(prev.hostPermissions, curr.hostPermissions)
  );
}

export function computeBrowserExtensionDelta(current: BrowserExtension[], previous: BrowserExtension[]): BrowserExtensionDeltaResult {
  const prevMap = new Map<string, BrowserExtension>();
  const currMap = new Map<string, BrowserExtension>();
  for (const e of previous) if (e?.installId) prevMap.set(String(e.installId), e);
  for (const e of current) if (e?.installId) currMap.set(String(e.installId), e);

  const added: BrowserExtension[] = [];
  const removed: BrowserExtension[] = [];
  const updated: BrowserExtension[] = [];
  for (const e of currMap.values()) {
    const prev = prevMap.get(e.installId);
    if (!prev) added.push(e);
    else if (isExtensionUpdated(prev, e)) updated.push(e);
  }
  for (const e of prevMap.values()) if (!currMap.has(e.installId)) removed.push(e);

  added.sort(byId);
  removed.sort(byId);
  updated.sort(byId);
  return {
    delta: { added, removed, updated, unchanged: Math.max(0, currMap.size - added.length - updated.length) },
    hasChanges: Boolean(added.length || removed.length || updated.length),
    currentCount: currMap.size,
  };
}

export function toBrowserExtensionBaselineOps(delta: BrowserExtensionDelta): { upserts: BrowserExtension[]; deletes: string[] } {
  return {
    upserts: [...delta.added, ...delta.updated],
    deletes: delta.removed.map((e) => e.installId).filter(Boolean),
  };
}
