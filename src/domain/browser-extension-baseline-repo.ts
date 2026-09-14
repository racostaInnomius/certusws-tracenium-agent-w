// src/domain/browser-extension-baseline-repo.ts
//
// Baseline local de extensiones, en el mismo `agent.db` que software y
// impresoras (ver printer-baseline-repo.ts para por qué se comparte el
// fichero). Cada fila guarda la extensión entera como JSON: el delta la
// compara campo a campo en TypeScript y el esquema de columnas no aporta
// nada salvo migraciones cuando el modelo crece.

import Database from "better-sqlite3";
import type { BrowserExtension } from "./browser-extension";
import { ensureAgentDataDir, getSoftwareBaselineDbPath } from "../bootstrap/paths";

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;
  ensureAgentDataDir();
  dbInstance = new Database(getSoftwareBaselineDbPath());
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS browser_extension_baseline (
      install_id      TEXT PRIMARY KEY,
      payload         TEXT NOT NULL,
      detected_at_utc TEXT NOT NULL
    );
  `);
  return dbInstance;
}

export function loadBrowserExtensionBaseline(): BrowserExtension[] {
  const rows = getDb()
    .prepare(`SELECT payload, detected_at_utc AS detectedAtUtc FROM browser_extension_baseline ORDER BY install_id`)
    .all() as Array<{ payload: string; detectedAtUtc: string }>;
  const out: BrowserExtension[] = [];
  for (const r of rows) {
    try {
      out.push({ ...(JSON.parse(r.payload) as BrowserExtension), detectedAtUtc: r.detectedAtUtc });
    } catch {
      // Una fila ilegible se trata como ausente: la siguiente pasada la vuelve a añadir.
    }
  }
  return out;
}

/** Tras esto la siguiente pasada manda el inventario completo (reset_baseline). */
export function clearBrowserExtensionBaseline(): void {
  getDb().exec(`DELETE FROM browser_extension_baseline`);
}

/** `detected_at_utc` conserva la PRIMERA vez que se vio. */
export function upsertBrowserExtensionBaseline(rows: BrowserExtension[]): void {
  if (!rows?.length) return;
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO browser_extension_baseline (install_id, payload, detected_at_utc)
    VALUES (@installId, @payload, @detectedAtUtc)
    ON CONFLICT(install_id) DO UPDATE SET
      payload = excluded.payload,
      detected_at_utc = COALESCE(browser_extension_baseline.detected_at_utc, excluded.detected_at_utc)
  `);
  db.transaction((list: BrowserExtension[]) => {
    for (const e of list) {
      if (!e?.installId || !e?.detectedAtUtc) continue;
      stmt.run({ installId: e.installId, payload: JSON.stringify(e), detectedAtUtc: e.detectedAtUtc });
    }
  })(rows);
}

export function deleteBrowserExtensionsByIds(ids: string[]): void {
  if (!ids?.length) return;
  const db = getDb();
  const stmt = db.prepare(`DELETE FROM browser_extension_baseline WHERE install_id = ?`);
  db.transaction((list: string[]) => {
    for (const id of list) if (id) stmt.run(id);
  })(ids);
}
