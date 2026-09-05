// src/domain/cdp-adcs-repo.ts
//
// Cursor incremental del conector AD CS: el ultimo RequestID visto por
// CA. Misma base SQLite que la baseline de CDP, tabla clave/valor
// `cdp_meta` (identica a la que usa el pin de anclas en `main`: CREATE IF
// NOT EXISTS, asi que el merge no puede chocar en el esquema).

import Database from "better-sqlite3";
import { ensureAgentDataDir, getSoftwareBaselineDbPath } from "../bootstrap/paths";

let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (db) return db;
  ensureAgentDataDir();
  db = new Database(getSoftwareBaselineDbPath());
  db.pragma("journal_mode = WAL");
  db.exec(`CREATE TABLE IF NOT EXISTS cdp_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
  return db;
}

const keyFor = (ca: string) => `adcs_last_request_id:${ca}`;

export function readAdcsCursor(ca: string): number {
  const row = getDb().prepare(`SELECT value FROM cdp_meta WHERE key = ?`).get(keyFor(ca)) as { value?: string } | undefined;
  const n = Number(row?.value ?? 0);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

export function writeAdcsCursor(ca: string, requestId: number): void {
  getDb()
    .prepare(`INSERT INTO cdp_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
    .run(keyFor(ca), String(Math.floor(requestId)));
}

/** Solo para tests. */
export function resetAdcsCursors(): void {
  getDb().prepare(`DELETE FROM cdp_meta WHERE key LIKE 'adcs_last_request_id:%'`).run();
}
