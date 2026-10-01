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

    CREATE TABLE IF NOT EXISTS cdp_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    -- Lo que se aplicará cuando el backend confirme la entrega (ver
    -- stageCdpDelivery). seq propio y no el id del outbox: si el outbox se
    -- recrea, sus ids vuelven a empezar; el orden de los escaneos no.
    CREATE TABLE IF NOT EXISTS cdp_delivery_pending (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      outbox_id INTEGER NOT NULL,
      commit_json TEXT NOT NULL,
      staged_at_utc TEXT NOT NULL
    );
  `);

  return dbInstance;
}

// ── Memoria del pin de anclas (ADR-0011 fase 0, paso 1) ──────────────
//
// ⚠️ Existe por una trampa concreta del planificador: si `hasChanges` es
// falso, el namespace CDP ENTERO se descarta y no llega nada al control
// plane. Colgar el estado del pin de ese namespace sin más significaría
// que una flota estable —que es la normal— no reportaría su pin casi
// nunca. Sería reproducir, un nivel más arriba, el mismo fallo que este
// paso viene a arreglar: un dato que existe y no se ve.
//
// Con esto, un pin que cambia es un cambio que merece envío, igual que
// un certificado nuevo.

export function cdpAnchorDigestChanged(digest: string): boolean {
  const db = getDb();
  const row = db
    .prepare(`SELECT value FROM cdp_meta WHERE key = 'anchor_pin_digest'`)
    .get() as { value?: string } | undefined;
  return row?.value !== digest;
}

export function commitCdpAnchorDigest(digest: string): void {
  getDb()
    .prepare(
      `INSERT INTO cdp_meta (key, value) VALUES ('anchor_pin_digest', ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`
    )
    .run(digest);
}

export function hashCdpAnchorState(state: unknown): string {
  return crypto.createHash("sha256").update(stableStringify(state)).digest("hex");
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
 * baseline — it moves only when the backend confirms the send that carried
 * the scan (stageCdpDelivery → promoteCdpDelivery).
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
  db.transaction(() => applyBaseline(db, items))();
}

function applyBaseline(db: Database.Database, current: CdpCertItem[]) {
  const nowUtc = new Date().toISOString();

  const upsert = db.prepare(`
    INSERT INTO cdp_certificate_baseline (cert_id, content_hash, item_json, detected_at_utc)
    VALUES (@certId, @contentHash, @itemJson, @detectedAtUtc)
    ON CONFLICT(cert_id) DO UPDATE SET
      content_hash = excluded.content_hash,
      item_json = excluded.item_json,
      detected_at_utc = COALESCE(cdp_certificate_baseline.detected_at_utc, excluded.detected_at_utc)
  `);

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
}

// ── Entrega confirmada (2026-10-01) ──────────────────────────────────
//
// ⚠️ La línea base es «lo que el control plane YA TIENE»: el siguiente
// escaneo sólo manda lo que difiere de ella. Se guardaba al recoger, ANTES
// de entregar — y un envío que no llegaba (payload por encima del límite
// gRPC, proyección que fallaba y respondía OK) quedaba dado por entregado
// para siempre. 5 equipos acabaron con 500–2000 certificados que el
// servidor nunca tuvo; uno de ellos, sin su primer baseline completo.
//
// Ahora el plugin no escribe nada al recoger: deja un paquete (la base, los
// digests de los bloques laterales y los cursores de AD CS) que el llamador
// asocia al id del outbox, y que se aplica sólo con el ACK_OK de ese envío.
// Sin ACK, el siguiente escaneo vuelve a diffear contra la base anterior y
// reenvía los mismos cambios — idempotentes en el servidor.

export type CdpDeliveryCommit = {
  baseline: CdpCertItem[];
  /** Claves de cdp_meta: digests de bloques laterales, cursores de AD CS, pin de anclas. */
  meta: Record<string, string>;
};

const DELIVERY_ACKED_KEY = "delivery_acked";
const DELIVERY_LAST_SEQ_KEY = "delivery_last_seq";
/** Un paquete sin ACK en una semana es de un envío que no llegará. */
const STAGE_MAX_AGE_DAYS = 7;

function readMeta(db: Database.Database, key: string): string | null {
  const row = db.prepare(`SELECT value FROM cdp_meta WHERE key = ?`).get(key) as { value?: string } | undefined;
  return row?.value ?? null;
}

function writeMeta(db: Database.Database, key: string, value: string) {
  db.prepare(
    `INSERT INTO cdp_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(key, value);
}

/** Asocia el paquete de un escaneo al envío que lo lleva. */
export function stageCdpDelivery(outboxId: number, commit: CdpDeliveryCommit): void {
  const db = getDb();
  db.transaction(() => {
    // El outbox deduplica payloads idénticos devolviendo el id existente:
    // el paquete más reciente para ese id es el que vale.
    db.prepare(`DELETE FROM cdp_delivery_pending WHERE outbox_id = ?`).run(outboxId);
    db.prepare(
      `DELETE FROM cdp_delivery_pending WHERE staged_at_utc < ?`
    ).run(new Date(Date.now() - STAGE_MAX_AGE_DAYS * 86_400_000).toISOString());
    db.prepare(
      `INSERT INTO cdp_delivery_pending (outbox_id, commit_json, staged_at_utc) VALUES (?, ?, ?)`
    ).run(outboxId, JSON.stringify(commit), new Date().toISOString());
  })();
}

/**
 * ACK_OK del envío `outboxId`: aplica su paquete. Un ACK que llega DESPUÉS
 * del de un escaneo posterior ya aplicado no retrocede la base
 * («superseded»). «none»: ese envío no llevaba CDP.
 */
export function promoteCdpDelivery(outboxId: number): "promoted" | "superseded" | "none" {
  const db = getDb();
  return db.transaction(() => {
    const row = db
      .prepare(`SELECT seq, commit_json AS commitJson FROM cdp_delivery_pending WHERE outbox_id = ? ORDER BY seq DESC LIMIT 1`)
      .get(outboxId) as { seq: number; commitJson: string } | undefined;
    if (!row) return "none" as const;

    db.prepare(`DELETE FROM cdp_delivery_pending WHERE seq <= ?`).run(row.seq);
    const lastSeq = Number(readMeta(db, DELIVERY_LAST_SEQ_KEY) ?? 0);
    if (row.seq <= lastSeq) return "superseded" as const;

    const commit = JSON.parse(row.commitJson) as CdpDeliveryCommit;
    applyBaseline(db, Array.isArray(commit.baseline) ? commit.baseline : []);
    for (const [key, value] of Object.entries(commit.meta ?? {})) writeMeta(db, key, String(value));
    writeMeta(db, DELIVERY_LAST_SEQ_KEY, String(row.seq));
    writeMeta(db, DELIVERY_ACKED_KEY, "1");
    return "promoted" as const;
  })();
}

/**
 * ¿Ha aplicado este agente alguna vez una base CONFIRMADA? Un agente que
 * viene de una versión que guardaba la base sin confirmar no lo sabe: su
 * base puede decir que el servidor tiene certificados que nunca llegaron.
 * Mientras sea false, el plugin manda la lista completa (una vez: al primer
 * ACK queda en true).
 */
export function isCdpDeliveryAcked(): boolean {
  return readMeta(getDb(), DELIVERY_ACKED_KEY) === "1";
}

/**
 * Certificados de la baseline cuyo almacen cumple `match` y que NO estan
 * en el escaneo actual (`presentIds`). Es lo que un escaneo parcial
 * ARRASTRA: el almacen no se pudo leer, asi que su ultimo contenido
 * conocido sigue siendo la mejor verdad. Se recomite con los items
 * nuevos para que (a) no se reporten como bajas y (b) cuando el almacen
 * vuelva a leerse, lo que siga igual no aparezca como alta y lo que de
 * verdad falte si aparezca como baja.
 */
export function loadCdpBaselineItemsByStore(
  match: (storeId: string) => boolean,
  presentIds: Set<string>
): CdpCertItem[] {
  const db = getDb();
  const rows = db
    .prepare(`SELECT cert_id as certId, item_json as itemJson FROM cdp_certificate_baseline`)
    .all() as Array<{ certId: string; itemJson: string }>;
  const out: CdpCertItem[] = [];
  for (const row of rows) {
    if (presentIds.has(row.certId)) continue;
    try {
      const item = JSON.parse(row.itemJson) as CdpCertItem;
      if (item?.store?.id && match(String(item.store.id))) out.push(item);
    } catch {
      /* una fila corrupta no arrastra nada */
    }
  }
  return out;
}

export function clearCdpBaseline() {
  const db = getDb();
  db.exec(`DELETE FROM cdp_certificate_baseline`);
}
