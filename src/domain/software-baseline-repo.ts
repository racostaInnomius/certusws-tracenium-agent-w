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

  // ── Las cuatro columnas de identidad de ADR-0019 F0 ───────────────
  //
  // 🔴 Medido en prod el 18-sep (T111, WES-MSIG-RC-JL, agente 1.1.76): 147
  // mensajes AMP en UNA hora, todos con `software.hasChanges=true` y 98 apps
  // en `updated`, todas con la misma versión, editor y ruta que la vez
  // anterior. Cada uno de esos mensajes dispara en el backend una
  // reevaluación completa del equipo; un solo equipo agotó las 8 conexiones
  // del pool del tenant (~690 timeouts de conexión en 15 minutos).
  //
  // La causa: desde 1.1.65 `isAppUpdated` compara también la identidad
  // (productCode, uninstallString, quietUninstallString, uninstallKeyPath),
  // pero esta tabla nunca las guardó. La baseline volvía de SQLite con las
  // cuatro en `undefined`, el inventario recién recogido SÍ las traía, y la
  // comparación daba "actualizada" en CADA ciclo, para siempre. El efecto de
  // una sola vez que describe `software-inventory-delta.ts` se volvió
  // permanente porque el lado que debía recordar el valor no existía.
  //
  // El fichero ya existe en cada equipo, así que las columnas se añaden con
  // ALTER sobre lo que haya (el mismo patrón que `printer_baseline`). Tras
  // actualizar, la primera pasada marca las apps win32 como `updated` una vez
  // —ahí es cuando se rellenan— y a partir de la segunda converge.
  const cols = new Set(
    (db.prepare(`PRAGMA table_info(software_baseline)`).all() as Array<{ name: string }>).map(c => c.name)
  );
  if (!cols.has("uninstall_string")) db.exec(`ALTER TABLE software_baseline ADD COLUMN uninstall_string TEXT`);
  if (!cols.has("quiet_uninstall_string")) db.exec(`ALTER TABLE software_baseline ADD COLUMN quiet_uninstall_string TEXT`);
  if (!cols.has("product_code")) db.exec(`ALTER TABLE software_baseline ADD COLUMN product_code TEXT`);
  if (!cols.has("uninstall_key_path")) db.exec(`ALTER TABLE software_baseline ADD COLUMN uninstall_key_path TEXT`);
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
        uninstall_string as uninstallString,
        quiet_uninstall_string as quietUninstallString,
        product_code as productCode,
        uninstall_key_path as uninstallKeyPath,
        detected_at_utc as detectedAtUtc
      FROM software_baseline
      ORDER BY install_id
      `
    )
    .all() as any[];

  // SQLite devuelve NULL donde el tipo dice `string | undefined`. La
  // diferencia importa: `undefined` es lo que trae un origen que no sabe
  // desinstalar (pkgutil, dpkg…), y es con lo que se compara el delta.
  return rows.map(r => ({
    ...r,
    version: r.version ?? undefined,
    publisher: r.publisher ?? undefined,
    installLocation: r.installLocation ?? undefined,
    packageFamilyName: r.packageFamilyName ?? undefined,
    uninstallString: r.uninstallString ?? undefined,
    quietUninstallString: r.quietUninstallString ?? undefined,
    productCode: r.productCode ?? undefined,
    uninstallKeyPath: r.uninstallKeyPath ?? undefined
  })) as SoftwareApplication[];
}

/**
 * Wipe the entire software baseline. After this, the next collection tick
 * sees `previous.length === 0` → the provider treats it as a first-run and
 * re-sends the FULL software items[] (not an elided delta). This is the
 * mechanism the control plane's `reset_baseline` self-heal relies on when
 * its projection table (software_current_app) has diverged/emptied.
 */
export function clearSoftwareBaseline() {
  const db = getDb();
  db.exec(`DELETE FROM software_baseline`);
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
      uninstall_string,
      quiet_uninstall_string,
      product_code,
      uninstall_key_path,
      detected_at_utc
    ) VALUES (
      @installId,
      @name,
      @version,
      @publisher,
      @source,
      @installLocation,
      @packageFamilyName,
      @uninstallString,
      @quietUninstallString,
      @productCode,
      @uninstallKeyPath,
      @detectedAtUtc
    )
    ON CONFLICT(install_id) DO UPDATE SET
      name = excluded.name,
      version = excluded.version,
      publisher = excluded.publisher,
      source = excluded.source,
      install_location = excluded.install_location,
      package_family_name = excluded.package_family_name,
      uninstall_string = excluded.uninstall_string,
      quiet_uninstall_string = excluded.quiet_uninstall_string,
      product_code = excluded.product_code,
      uninstall_key_path = excluded.uninstall_key_path,
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
        uninstallString: app.uninstallString ?? null,
        quietUninstallString: app.quietUninstallString ?? null,
        productCode: app.productCode ?? null,
        uninstallKeyPath: app.uninstallKeyPath ?? null,
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
