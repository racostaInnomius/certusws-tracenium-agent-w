// src/domain/file-integrity-baseline-repo.ts
//
// ADR-0027 — la última lectura de los ficheros vigilados, en el mismo
// `agent.db` que las demás líneas base. De cada fichero, lo mismo que viaja al
// control plane: ruta, hash, tamaño y fecha. Nunca el contenido.

import Database from "better-sqlite3";
import { ensureAgentDataDir, getSoftwareBaselineDbPath } from "../bootstrap/paths";
import { keyOf, type PreviousEntry, type ScannedFile } from "./file-integrity-scan";

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;
  ensureAgentDataDir();
  dbInstance = new Database(getSoftwareBaselineDbPath());
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS file_integrity_baseline (
      set_id          TEXT    NOT NULL,
      path            TEXT    NOT NULL,
      sha256          TEXT,
      hashed          INTEGER NOT NULL,
      size_bytes      INTEGER NOT NULL,
      mtime_ms        REAL    NOT NULL,
      modified_at_utc TEXT    NOT NULL,
      PRIMARY KEY (set_id, path)
    );
  `);
  return dbInstance;
}

export type BaselineFile = ScannedFile;

export function loadFileIntegrityBaseline(): BaselineFile[] {
  const rows = getDb()
    .prepare(`SELECT set_id, path, sha256, hashed, size_bytes, mtime_ms, modified_at_utc FROM file_integrity_baseline`)
    .all() as any[];
  return rows.map((r) => ({
    setId: String(r.set_id),
    path: String(r.path),
    sha256: r.sha256 ?? null,
    hashed: r.hashed === 1,
    sizeBytes: Number(r.size_bytes),
    mtimeMs: Number(r.mtime_ms),
    modifiedAtUtc: String(r.modified_at_utc),
  }));
}

export function toPreviousMap(files: BaselineFile[]): Map<string, PreviousEntry> {
  return new Map(files.map((f) => [keyOf(f.setId, f.path), { sha256: f.sha256, sizeBytes: f.sizeBytes, mtimeMs: f.mtimeMs }]));
}

/** La línea base ES la última lectura completa: se sustituye entera, en una transacción. */
export function replaceFileIntegrityBaseline(files: ScannedFile[]): void {
  const db = getDb();
  const insert = db.prepare(`
    INSERT INTO file_integrity_baseline (set_id, path, sha256, hashed, size_bytes, mtime_ms, modified_at_utc)
    VALUES (@setId, @path, @sha256, @hashed, @sizeBytes, @mtimeMs, @modifiedAtUtc)
  `);
  db.transaction((rows: ScannedFile[]) => {
    db.exec(`DELETE FROM file_integrity_baseline`);
    for (const f of rows) insert.run({ ...f, hashed: f.hashed ? 1 : 0 });
  })(files);
}

/** reset_baseline: la siguiente pasada manda la foto completa. */
export function clearFileIntegrityBaseline(): void {
  getDb().exec(`DELETE FROM file_integrity_baseline`);
}
