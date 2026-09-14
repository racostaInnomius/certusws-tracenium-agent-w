// src/domain/extension-policy-owned-repo.ts
//
// Qué ids de las listas de Chrome/Edge añadió ESTE agente. Es lo que le
// permite retirar una regla sin tocar lo que puso una GPO u otra herramienta
// (ver domain/extension-policy.ts). Vive en agent.db junto a las baselines.
//
// ⚠️ No se borra con reset_baseline: no es una foto del inventario, es la
// memoria de qué escribimos. Perderla dejaría nuestros bloqueos huérfanos en
// el registro, sin que nadie pueda quitarlos desde el portal.

import Database from "better-sqlite3";
import type { ChromiumBrowser, PolicyListKind } from "./extension-policy";
import { ensureAgentDataDir, getSoftwareBaselineDbPath } from "../bootstrap/paths";

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;
  ensureAgentDataDir();
  dbInstance = new Database(getSoftwareBaselineDbPath());
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS extension_policy_owned (
      browser      TEXT NOT NULL,
      list         TEXT NOT NULL,
      extension_id TEXT NOT NULL,
      added_at_utc TEXT NOT NULL,
      PRIMARY KEY (browser, list, extension_id)
    );
  `);
  return dbInstance;
}

export function loadOwnedEntries(browser: ChromiumBrowser, list: PolicyListKind): string[] {
  return (getDb()
    .prepare(`SELECT extension_id AS id FROM extension_policy_owned WHERE browser = ? AND list = ? ORDER BY added_at_utc, extension_id`)
    .all(browser, list) as Array<{ id: string }>).map((r) => r.id);
}

/** Sustituye lo anotado para (navegador, lista) por `owned`, conservando la fecha de lo que ya estaba. */
export function saveOwnedEntries(browser: ChromiumBrowser, list: PolicyListKind, owned: string[], nowUtc: string): void {
  const db = getDb();
  db.transaction(() => {
    const keep = new Set(owned);
    const existing = loadOwnedEntries(browser, list);
    const del = db.prepare(`DELETE FROM extension_policy_owned WHERE browser = ? AND list = ? AND extension_id = ?`);
    for (const id of existing) if (!keep.has(id)) del.run(browser, list, id);
    const ins = db.prepare(`INSERT OR IGNORE INTO extension_policy_owned (browser, list, extension_id, added_at_utc) VALUES (?, ?, ?, ?)`);
    for (const id of owned) ins.run(browser, list, id, nowUtc);
  })();
}
