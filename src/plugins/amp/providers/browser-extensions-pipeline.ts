// src/plugins/amp/providers/browser-extensions-pipeline.ts
//
// De la lectura de perfiles al payload `amp.browserExtensions`, con la
// misma disciplina que printers-pipeline.ts:
//
//   1. Primera pasada (sin baseline) → items[] completo, hasChanges=true.
//   2. Con cambios → sólo el delta.
//   3. Sin cambios → nada más que el recuento.
//
// ⚠️ Y la lección de las impresoras: si NO se pudo mirar (`unavailable`) o
// la plataforma no se lee (`unsupported`), la baseline no se toca. Grabar un
// vacío que en realidad es "no pude" lo convierte en "no tiene extensiones"
// para siempre, porque las pasadas siguientes ya no ven cambio.

import type { BrowserExtensionInventory } from "../../../domain/amp-types";
import { scanBrowserExtensions, defaultUsersRoot, type ExtensionScanResult } from "./browser-extensions";
import { computeBrowserExtensionDelta, toBrowserExtensionBaselineOps } from "../../../domain/browser-extension-inventory-delta";
import {
  loadBrowserExtensionBaseline,
  upsertBrowserExtensionBaseline,
  deleteBrowserExtensionsByIds,
} from "../../../domain/browser-extension-baseline-repo";

export function buildBrowserExtensionInventory(scan: ExtensionScanResult): BrowserExtensionInventory {
  const meta = { scope: scan.scope, profiles: scan.profiles, profileErrors: scan.profileErrors };
  if (scan.scope !== "collected") {
    return { count: 0, items: undefined, delta: null, hasChanges: false, ...meta };
  }

  const previous = loadBrowserExtensionBaseline();
  const current = scan.extensions;

  // Sin baseline no hay forma de distinguir "primera vez" de "se borró
  // todo": se manda la foto completa, también si está vacía, para que el
  // backend registre que se miró.
  if (previous.length === 0) {
    upsertBrowserExtensionBaseline(current);
    return { count: current.length, items: current, delta: null, hasChanges: true, ...meta };
  }

  const r = computeBrowserExtensionDelta(current, previous);
  if (!r.hasChanges) {
    return { count: r.currentCount, items: undefined, delta: null, hasChanges: false, ...meta };
  }
  const { upserts, deletes } = toBrowserExtensionBaselineOps(r.delta);
  if (upserts.length) upsertBrowserExtensionBaseline(upserts);
  if (deletes.length) deleteBrowserExtensionsByIds(deletes);
  return { count: r.currentCount, items: undefined, delta: r.delta, hasChanges: true, ...meta };
}

export function emptyBrowserExtensionInventory(scope: BrowserExtensionInventory["scope"] = "unavailable"): BrowserExtensionInventory {
  return { count: 0, items: undefined, delta: null, hasChanges: false, scope, profiles: 0, profileErrors: 0 };
}

/**
 * Lo que llaman los providers: leer + construir, sin dejar que un fallo
 * envenene el resto del namespace AMP. Se llama ANTES del bloque de software
 * por la misma razón que las impresoras: ese bloque retorna temprano cuando
 * no hay cambios.
 */
export function collectBrowserExtensionInventory(platform: NodeJS.Platform, warn?: (msg: string, meta?: any) => void): BrowserExtensionInventory {
  try {
    return buildBrowserExtensionInventory(scanBrowserExtensions({ platform, usersRoot: defaultUsersRoot(platform) }));
  } catch (err: any) {
    warn?.("[browserExtensions] collection failed, scope unavailable", { error: err?.message || String(err) });
    return emptyBrowserExtensionInventory("unavailable");
  }
}
