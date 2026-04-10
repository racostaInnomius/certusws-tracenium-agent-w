// src/domain/software-baseline-repo.ts

import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import { SoftwareApplication } from "./normalize-app";
import {
  ensureAgentDataDir,
  getLegacySoftwareBaselineDbPath,
  getSoftwareBaselineDbPath
} from "../bootstrap/paths";

const DB_PATH = getSoftwareBaselineDbPath();
const LEGACY_DB_PATH = getLegacySoftwareBaselineDbPath();
const DB_DIR = path.dirname(DB_PATH);

function ensureDbDir() {
  ensureAgentDataDir();
}

function migrateLegacyDbIfNeeded() {
  if (fs.existsSync(DB_PATH) || !fs.existsSync(LEGACY_DB_PATH)) {
    return;
  }

  try {
    fs.copyFileSync(LEGACY_DB_PATH, DB_PATH);
    console.log("[BASELINE] migrated legacy baseline db", {
      from: LEGACY_DB_PATH,
      to: DB_PATH
    });
  } catch (err) {
    console.warn("[BASELINE] failed to migrate legacy baseline db", {
      from: LEGACY_DB_PATH,
      to: DB_PATH,
      err
    });
  }
}

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;

  ensureDbDir();
  migrateLegacyDbIfNeeded();
  dbInstance = new Database(DB_PATH);
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");

  initSchema(dbInstance);

  return dbInstance;
}

function initSchema(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS software_baseline (
      install_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT,
      publisher TEXT,
      source TEXT NOT NULL,
      install_location TEXT,
      package_family_name TEXT,
      detected_at_utc TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_software_baseline_name
      ON software_baseline(name);

    CREATE INDEX IF NOT EXISTS idx_software_baseline_publisher
      ON software_baseline(publisher);

    CREATE INDEX IF NOT EXISTS idx_software_baseline_install_id
      ON software_baseline(install_id);
  `);
}

/**
 * Load full baseline from SQLite
 */
export function loadSoftwareBaseline(): SoftwareApplication[] {
  const db = getDb();

  const rows = db
    .prepare(
      `
      SELECT
        install_id as installId,
        name,
        version,
        publisher,
        source,
        install_location as installLocation,
        package_family_name as packageFamilyName,
        detected_at_utc as detectedAtUtc
      FROM software_baseline
      ORDER BY install_id
      `
    )
    .all();

  return rows as SoftwareApplication[];
}

/**
 * Replace baseline atomically (full snapshot overwrite)
 */
// @deprecated Use incremental baseline (upsertSoftwareBaseline + deleteSoftwareByIds)
export function saveSoftwareBaseline(apps: SoftwareApplication[]) {
  const db = getDb();

  const insertStmt = db.prepare(`
    INSERT INTO software_baseline (
      install_id,
      name,
      version,
      publisher,
      source,
      install_location,
      package_family_name,
      detected_at_utc
    ) VALUES (
      @installId,
      @name,
      @version,
      @publisher,
      @source,
      @installLocation,
      @packageFamilyName,
      @detectedAtUtc
    )
  `);

  const tx = db.transaction((apps: SoftwareApplication[]) => {
    // Full replace strategy
    db.exec(`DELETE FROM software_baseline`);

    for (const app of apps) {
      if (!app?.installId || !app?.name || !app?.source) {
        console.warn("[BASELINE] Skipping invalid software row", app);
        continue;
      }
      insertStmt.run({
        installId: app.installId,
        name: app.name,
        version: app.version ?? null,
        publisher: app.publisher ?? null,
        source: app.source,
        installLocation: app.installLocation ?? null,
        packageFamilyName: app.packageFamilyName ?? null,
        detectedAtUtc: app.detectedAtUtc
      });
    }
  });

  tx(apps);
}

/**
 * Upsert baseline incrementally (optional optimization)
 */
export function upsertSoftwareBaseline(apps: SoftwareApplication[]) {
  if (!apps?.length) return;

  const db = getDb();

  const upsert = db.prepare(`
    INSERT INTO software_baseline (
      install_id,
      name,
      version,
      publisher,
      source,
      install_location,
      package_family_name,
      detected_at_utc
    ) VALUES (
      @installId,
      @name,
      @version,
      @publisher,
      @source,
      @installLocation,
      @packageFamilyName,
      @detectedAtUtc
    )
    ON CONFLICT(install_id) DO UPDATE SET
      name = excluded.name,
      version = excluded.version,
      publisher = excluded.publisher,
      source = excluded.source,
      install_location = excluded.install_location,
      package_family_name = excluded.package_family_name,
      detected_at_utc = COALESCE(software_baseline.detected_at_utc, excluded.detected_at_utc)
  `);

  const tx = db.transaction((apps: SoftwareApplication[]) => {
    for (const app of apps) {
      if (!app?.installId || !app?.name || !app?.source) {
        console.warn("[BASELINE] Skipping invalid software row", app);
        continue;
      }

      upsert.run({
        installId: app.installId,
        name: app.name,
        version: app.version ?? null,
        publisher: app.publisher ?? null,
        source: app.source,
        installLocation: app.installLocation ?? null,
        packageFamilyName: app.packageFamilyName ?? null,
        detectedAtUtc: app.detectedAtUtc
      });
    }
  });

  tx(apps);
}

/**
 * Delete specific installIds (useful for delta-removed optimization)
 */
export function deleteSoftwareByIds(installIds: string[]) {
  if (!installIds.length) return;

  const db = getDb();

  const placeholders = installIds.map(() => "?").join(",");
  const stmt = db.prepare(`
    DELETE FROM software_baseline
    WHERE install_id IN (${placeholders})
  `);

  stmt.run(...installIds);
}
