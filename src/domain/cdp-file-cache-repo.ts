// src/domain/cdp-file-cache-repo.ts
//
// Ola 1.1 — caché del descubrimiento de ficheros de CDP.
//
// El recorrido por defecto mira miles de ficheros en /etc, /opt o
// %ProgramFiles% cada escaneo, y casi todos siguen igual que ayer.
// Releerlos y reparsearlos (un PKCS#12 con PBKDF2 cuesta de verdad) es
// gastar el presupuesto de tiempo en lo que ya sabemos. Así que por cada
// fichero se guarda (tamaño, mtime) y lo que se sacó de él, y si los dos
// coinciden se reutiliza.
//
// ⚠️ La caché ahorra TRABAJO, no INVENTARIO: lo que sale de ella se vuelve
// a emitir entero en cada escaneo. El baseline del control plane retira
// por ausencia; un fichero sin cambios que dejara de reportarse sería una
// baja fantasma.
//
// Qué se guarda: los certificados en DER (datos públicos: los mismos
// bytes que cualquier cliente TLS recibe) y los metadatos de las claves
// sueltas. NUNCA un byte de clave privada — la descripción de una clave
// es algoritmo, tamaño, cifrada sí/no y el hash de su parte PÚBLICA.
//
// Misma agent.db que la baseline (WAL), tabla propia. La versión en cada
// fila invalida la caché cuando cambia el parser (una versión nueva del
// agente puede sacar campos nuevos del mismo fichero: caIssuerUrls, por
// ejemplo): una fila de otra versión es un fallo de caché, no un acierto.

import Database from "better-sqlite3";
import { ensureAgentDataDir, getSoftwareBaselineDbPath } from "../bootstrap/paths";
import type { FileScanCache, FileScanRecord } from "../plugins/cdp/providers/cert-files";

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;
  ensureAgentDataDir();
  dbInstance = new Database(getSoftwareBaselineDbPath());
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS cdp_file_scan_cache (
      path TEXT PRIMARY KEY,
      size INTEGER NOT NULL,
      mtime_ms REAL NOT NULL,
      version TEXT NOT NULL,
      record_json TEXT NOT NULL,
      scanned_at_utc TEXT NOT NULL
    );
  `);
  return dbInstance;
}

/**
 * Caché respaldada por SQLite. `version` identifica al parser (agente +
 * esquema de la fila): con otra versión, todo es fallo de caché.
 */
export function openCdpFileScanCache(version: string): FileScanCache {
  const db = getDb();
  const getStmt = db.prepare(`SELECT size, mtime_ms AS mtimeMs, version, record_json AS json FROM cdp_file_scan_cache WHERE path = ?`);
  const putStmt = db.prepare(
    `INSERT INTO cdp_file_scan_cache (path, size, mtime_ms, version, record_json, scanned_at_utc)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(path) DO UPDATE SET size = excluded.size, mtime_ms = excluded.mtime_ms,
       version = excluded.version, record_json = excluded.record_json, scanned_at_utc = excluded.scanned_at_utc`
  );
  return {
    get(path, size, mtimeMs) {
      const row = getStmt.get(path) as { size: number; mtimeMs: number; version: string; json: string } | undefined;
      if (!row || row.version !== version || row.size !== size || row.mtimeMs !== mtimeMs) return undefined;
      try {
        return JSON.parse(row.json) as FileScanRecord;
      } catch {
        return undefined;
      }
    },
    put(path, size, mtimeMs, record) {
      putStmt.run(path, size, mtimeMs, version, JSON.stringify(record), new Date().toISOString());
    },
    prune(seen, keepPrefixes) {
      // Lo que no se vio y no cuelga de una raíz a medias ya no existe
      // (o dejó de ser candidato). Lo de una raíz a medias se conserva:
      // no haberlo visitado no dice nada de él.
      const rows = db.prepare(`SELECT path FROM cdp_file_scan_cache`).all() as Array<{ path: string }>;
      const del = db.prepare(`DELETE FROM cdp_file_scan_cache WHERE path = ?`);
      const tx = db.transaction((paths: string[]) => {
        for (const p of paths) del.run(p);
      });
      tx(rows.map((r) => r.path).filter((p) => !seen.has(p) && !keepPrefixes.some((k) => p.startsWith(k))));
    }
  };
}
