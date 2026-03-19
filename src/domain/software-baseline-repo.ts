// src/domain/software-baseline-repo.ts

import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import { SoftwareApplication } from "./normalize-app";

const DB_DIR = path.join(process.cwd(), "data");
const DB_PATH = path.join(DB_DIR, "agent.db");

function ensureDbDir() {
  if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(DB_DIR, { recursive: true });
  }
}

function getDb(): Database.Database {
  ensureDbDir();
  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  return db;
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
  `);
}

/**
 * Load full baseline from SQLite
 */
export function loadSoftwareBaseline(): SoftwareApplication[] {
  const db = getDb();
  initSchema(db);

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
      `
    )
    .all();

  return rows as SoftwareApplication[];
}

/**
 * Replace baseline atomically (full snapshot overwrite)
 */
export function saveSoftwareBaseline(apps: SoftwareApplication[]) {
  const db = getDb();
  initSchema(db);

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
        continue; // skip invalid rows
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
  const db = getDb();
  initSchema(db);

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
      detected_at_utc = excluded.detected_at_utc
  `);

  const tx = db.transaction((apps: SoftwareApplication[]) => {
    for (const app of apps) {
      if (!app?.installId || !app?.name || !app?.source) continue;

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
  initSchema(db);

  const stmt = db.prepare(`
    DELETE FROM software_baseline WHERE install_id = ?
  `);

  const tx = db.transaction((ids: string[]) => {
    for (const id of ids) {
      stmt.run(id);
    }
  });

  tx(installIds);
}