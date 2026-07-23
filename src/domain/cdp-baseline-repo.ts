// src/domain/cdp-baseline-repo.ts
//
// Local baseline for the CDP certificate inventory. Same agent.db file
// as the software baseline (WAL mode makes multi-connection access
// safe), own table. The baseline lets the collector send a delta
// instead of re-shipping 300+ mostly-static OS roots every tick.
//
// Each row stores the item's content hash AND the full item JSON: the
// hash drives added/updated detection, the JSON lets a future
// reset_baseline-style self-heal rehydrate a full items[] resend
// without re-scanning the stores.

import Database from "better-sqlite3";
import crypto from "crypto";
import { ensureAgentDataDir, getSoftwareBaselineDbPath } from "../bootstrap/paths";
import type { CdpCertItem, CdpDelta } from "./cdp-types";

const DB_PATH = getSoftwareBaselineDbPath();

let dbInstance: Database.Database | null = null;

function getDb(): Database.Database {
  if (dbInstance) return dbInstance;

  ensureAgentDataDir();
  dbInstance = new Database(DB_PATH);
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("synchronous = NORMAL");

  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS cdp_certificate_baseline (
      cert_id TEXT PRIMARY KEY,
      content_hash TEXT NOT NULL,
      item_json TEXT NOT NULL,
      detected_at_utc TEXT NOT NULL
    );
  `);

  return dbInstance;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  return `{${keys.map((key) => `"${key}":${stableStringify(record[key])}`).join(",")}}`;
}

export function hashCdpItem(item: CdpCertItem): string {
  return crypto.createHash("sha256").update(stableStringify(item)).digest("hex");
}

export function loadCdpBaselineHashes(): Map<string, string> {
  const db = getDb();
  const rows = db
    .prepare(`SELECT cert_id as certId, content_hash as contentHash FROM cdp_certificate_baseline`)
    .all() as Array<{ certId: string; contentHash: string }>;

  return new Map(rows.map((row) => [row.certId, row.contentHash]));
}

/**
 * Diff current items against the stored baseline. Does NOT mutate the
 * baseline — call commitCdpBaseline() after the snapshot is enqueued.
 * Returns null when the baseline is empty (first run → send full items[]).
 */
export function computeCdpDelta(items: CdpCertItem[]): CdpDelta | null {
  const previous = loadCdpBaselineHashes();

  if (previous.size === 0) {
    return null;
  }

  const delta: CdpDelta = { added: [], removed: [], updated: [] };
  const seen = new Set<string>();

  for (const item of items) {
    seen.add(item.id);
    const previousHash = previous.get(item.id);
    if (previousHash === undefined) {
      delta.added.push(item);
    } else if (previousHash !== hashCdpItem(item)) {
      delta.updated.push(item);
    }
  }

  for (const certId of previous.keys()) {
    if (!seen.has(certId)) {
      delta.removed.push({ id: certId });
    }
  }

  return delta;
}

/** Replace the baseline with the current scan (single transaction). */
export function commitCdpBaseline(items: CdpCertItem[]) {
  const db = getDb();
  const nowUtc = new Date().toISOString();

  const upsert = db.prepare(`
    INSERT INTO cdp_certificate_baseline (cert_id, content_hash, item_json, detected_at_utc)
    VALUES (@certId, @contentHash, @itemJson, @detectedAtUtc)
    ON CONFLICT(cert_id) DO UPDATE SET
      content_hash = excluded.content_hash,
      item_json = excluded.item_json,
      detected_at_utc = COALESCE(cdp_certificate_baseline.detected_at_utc, excluded.detected_at_utc)
  `);

  const tx = db.transaction((current: CdpCertItem[]) => {
    const ids = current.map((item) => item.id);

    if (ids.length === 0) {
      db.exec(`DELETE FROM cdp_certificate_baseline`);
    } else {
      // Deleting rows absent from the current scan keeps the baseline
      // an exact mirror, so the next diff's `removed` list stays honest.
      const placeholders = ids.map(() => "?").join(",");
      db.prepare(
        `DELETE FROM cdp_certificate_baseline WHERE cert_id NOT IN (${placeholders})`
      ).run(...ids);
    }

    for (const item of current) {
      upsert.run({
        certId: item.id,
        contentHash: hashCdpItem(item),
        itemJson: JSON.stringify(item),
        detectedAtUtc: nowUtc
      });
    }
  });

  tx(items);
}

export function clearCdpBaseline() {
  const db = getDb();
  db.exec(`DELETE FROM cdp_certificate_baseline`);
}
