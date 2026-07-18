// src/domain/printer-baseline-repo.ts
//
// SQLite-backed printer baseline. Mirror of software-baseline-repo.ts
// in role and shape. Important design choices that differ from the
// software repo:
//
//   * SHARED DB FILE. Lives in the same `agent.db` as software_baseline.
//     We open with the SAME Database object — better-sqlite3 reuses
//     connections per-path under the hood, so two parallel handles
//     against the same file would just race the journal. The
//     getDb() here MUST coordinate with software-baseline-repo's:
//     both use the same DB_PATH (getSoftwareBaselineDbPath, also
//     reused for printer baseline since the path is fundamentally
//     about "this device's agent local state DB", not asset-typed).
//
//   * NO LEGACY MIGRATION. The software repo migrates from a
//     pre-consolidation `./data/agent.db` location; printer_baseline
//     never existed there, so we just CREATE TABLE IF NOT EXISTS on
//     first open and move on.

import Database from "better-sqlite3";
import path from "path";
import { Printer } from "./printer";
import {
  ensureAgentDataDir,
  getSoftwareBaselineDbPath
} from "../bootstrap/paths";

const DB_PATH = getSoftwareBaselineDbPath();

function ensureDbDir() {
  ensureAgentDataDir();
}

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;

  ensureDbDir();
  dbInstance = new Database(DB_PATH);
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");

  initSchema(dbInstance);

  return dbInstance;
}

function initSchema(db: Database.Database) {
  // IF NOT EXISTS so co-locating with software_baseline in the same
  // DB file is safe — first run creates the table; subsequent opens
  // (including upgrades from agents that didn't have this table) just
  // no-op the DDL.
  db.exec(`
    CREATE TABLE IF NOT EXISTS printer_baseline (
      install_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      source TEXT NOT NULL,
      driver TEXT,
      port TEXT,
      is_default INTEGER NOT NULL DEFAULT 0,
      is_network INTEGER NOT NULL DEFAULT 0,
      is_shared INTEGER NOT NULL DEFAULT 0,
      location TEXT,
      comments TEXT,
      status TEXT,
      detected_at_utc TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_printer_baseline_name
      ON printer_baseline(name);

    CREATE INDEX IF NOT EXISTS idx_printer_baseline_source
      ON printer_baseline(source);
  `);
}

/**
 * Load full printer baseline from SQLite. Returns [] if the table is
 * empty or doesn't exist yet (the latter shouldn't happen after
 * getDb() but we tolerate it for defensive reasons).
 */
export function loadPrinterBaseline(): Printer[] {
  const db = getDb();

  const rows = db
    .prepare(
      `
      SELECT
        install_id      as installId,
        name,
        source,
        driver,
        port,
        is_default      as isDefault,
        is_network      as isNetwork,
        is_shared       as isShared,
        location,
        comments,
        status,
        detected_at_utc as detectedAtUtc
      FROM printer_baseline
      ORDER BY install_id
      `
    )
    .all() as any[];

  return rows.map(r => ({
    installId: r.installId,
    name: r.name,
    source: r.source,
    driver: r.driver ?? undefined,
    port: r.port ?? undefined,
    isDefault: Boolean(r.isDefault),
    isNetwork: Boolean(r.isNetwork),
    isShared: Boolean(r.isShared),
    location: r.location ?? undefined,
    comments: r.comments ?? undefined,
    status: r.status ?? undefined,
    detectedAtUtc: r.detectedAtUtc
  })) as Printer[];
}

/**
 * Wipe the entire printer baseline. Mirror of clearSoftwareBaseline:
 * after this the next collection tick re-sends the FULL printers items[]
 * (first-run path), which is what the control plane's `reset_baseline`
 * self-heal needs to repopulate an emptied device_printers projection.
 */
export function clearPrinterBaseline() {
  const db = getDb();
  db.exec(`DELETE FROM printer_baseline`);
}

/**
 * Upsert printers incrementally — same semantics as
 * upsertSoftwareBaseline. Used after delta computation, with the
 * union of added + updated rows.
 *
 * detected_at_utc uses COALESCE so the EARLIEST sighting is
 * preserved on updates (a printer that's been around for 6 months
 * shouldn't have its detected_at_utc jump to today just because its
 * driver got a minor version bump).
 */
export function upsertPrinterBaseline(printers: Printer[]) {
  if (!printers?.length) return;

  const db = getDb();

  const upsert = db.prepare(`
    INSERT INTO printer_baseline (
      install_id,
      name,
      source,
      driver,
      port,
      is_default,
      is_network,
      is_shared,
      location,
      comments,
      status,
      detected_at_utc
    ) VALUES (
      @installId,
      @name,
      @source,
      @driver,
      @port,
      @isDefault,
      @isNetwork,
      @isShared,
      @location,
      @comments,
      @status,
      @detectedAtUtc
    )
    ON CONFLICT(install_id) DO UPDATE SET
      name            = excluded.name,
      source          = excluded.source,
      driver          = excluded.driver,
      port            = excluded.port,
      is_default      = excluded.is_default,
      is_network      = excluded.is_network,
      is_shared       = excluded.is_shared,
      location        = excluded.location,
      comments        = excluded.comments,
      status          = excluded.status,
      detected_at_utc = COALESCE(printer_baseline.detected_at_utc, excluded.detected_at_utc)
  `);

  const tx = db.transaction((rows: Printer[]) => {
    for (const p of rows) {
      if (!p?.installId || !p?.name || !p?.source) {
        console.warn("[PRINTER_BASELINE] Skipping invalid row", p);
        continue;
      }

      upsert.run({
        installId: p.installId,
        name: p.name,
        source: p.source,
        driver: p.driver ?? null,
        port: p.port ?? null,
        isDefault: p.isDefault ? 1 : 0,
        isNetwork: p.isNetwork ? 1 : 0,
        isShared: p.isShared ? 1 : 0,
        location: p.location ?? null,
        comments: p.comments ?? null,
        status: p.status ?? null,
        detectedAtUtc: p.detectedAtUtc
      });
    }
  });

  tx(printers);
}

/**
 * Delete printers by installId. Used after delta computation to
 * prune rows that disappeared from the current snapshot.
 */
export function deletePrintersByIds(installIds: string[]) {
  if (!installIds?.length) return;

  const db = getDb();
  const stmt = db.prepare(
    `DELETE FROM printer_baseline WHERE install_id = ?`
  );

  const tx = db.transaction((ids: string[]) => {
    for (const id of ids) {
      if (!id) continue;
      stmt.run(id);
    }
  });

  tx(installIds);
}
