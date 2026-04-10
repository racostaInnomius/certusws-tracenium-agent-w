// src/queue/sqlite-outbox.ts
import os from "os";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";
import zlib from "zlib";

export type OutboxStatus = "PENDING" | "IN_FLIGHT" | "SENT" | "FAILED";

export type OutboxEventType =
  | "FACTS_SNAPSHOT"
  | "FACTS_DELTA"
  | "JOB_RESULT"
  | "LOG_BUNDLE"
  | "RCM_SESSION_META";

export interface EnqueueInput {
  type: OutboxEventType;
  payload: unknown;
}

interface OutboxAttemptsRow {
  attempts: number;
}

const MAX_ATTEMPTS = 20;
const COMPRESS_THRESHOLD_BYTES = 50 * 1024; // 50KB

function utcNow(): string {
  return new Date().toISOString();
}

function computeBackoffSeconds(attempt: number): number {
  const base = 30;
  const max = 3600;
  const secs = Math.min(max, base * Math.pow(2, attempt - 1));
  const jitter = Math.floor(Math.random() * 10);
  return secs + jitter;
}

function addSecondsIso(iso: string, secs: number): string {
  const d = new Date(iso);
  d.setSeconds(d.getSeconds() + secs);
  return d.toISOString();
}

function maybeCompressPayload(json: string): string {
  const size = Buffer.byteLength(json, "utf8");

  if (size < COMPRESS_THRESHOLD_BYTES) return json;

  try {
    const gz = zlib.gzipSync(Buffer.from(json, "utf8"));
    return "gz:" + gz.toString("base64");
  } catch {
    return json;
  }
}

function maybeDecompressPayload(value: string): string {
  if (!value.startsWith("gz:")) return value;

  try {
    const b64 = value.slice(3);
    const buf = Buffer.from(b64, "base64");
    return zlib.gunzipSync(buf).toString("utf8");
  } catch {
    return value;
  }
}

function defaultDbPath(): string {
  if (os.platform() === "win32") {
    const programData =
      process.env.PROGRAMDATA ||
      process.env.ProgramData ||
      "C:\\ProgramData";
    return path.join(programData, "Tracenium", "Agent", "outbox.db");
  }

  return path.join(os.homedir(), ".tracenium", "agent", "outbox.db");
}

export class SqliteOutbox {
  private db: Database.Database;
  private lockOwner: string;
  private listeners = new Set<() => void>();

  constructor(private dbPath = defaultDbPath()) {
    this.lockOwner = `agentcore:${os.hostname()}:${process.pid}`;

    const dir = path.dirname(dbPath);
    fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(dbPath);
    console.log("[outbox] initialized");
    //console.log("[outbox] initialized", { dbPath: this.dbPath, lockOwner: this.lockOwner });
    this.initialize();
  }

  private initialize() {
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS outbox_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        type TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        payload_hash TEXT NOT NULL,

        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at_utc TEXT NOT NULL,

        locked_at_utc TEXT NULL,
        lock_owner TEXT NULL,

        last_error TEXT NULL,
        sent_at_utc TEXT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_outbox_status_next
        ON outbox_events(status, next_attempt_at_utc);

      CREATE INDEX IF NOT EXISTS idx_outbox_inflight
        ON outbox_events(status, locked_at_utc);

      CREATE INDEX IF NOT EXISTS idx_outbox_payload_hash
        ON outbox_events(payload_hash);

      CREATE TABLE IF NOT EXISTS agent_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_outbox_lock_owner
        ON outbox_events(lock_owner);
    `);

    // ensure payload_hash column exists (for older DBs)
    const cols = this.db.prepare(`PRAGMA table_info(outbox_events)`).all() as Array<{ name: string }>;
    const hasPayloadHash = cols.some(c => c.name === "payload_hash");
    if (!hasPayloadHash) {
      this.db.exec(`ALTER TABLE outbox_events ADD COLUMN payload_hash TEXT`);
      // backfill hash for existing rows
      const rows = this.db.prepare(`SELECT id, payload_json FROM outbox_events`).all() as Array<{ id: number; payload_json: string }>;
      const upd = this.db.prepare(`UPDATE outbox_events SET payload_hash=? WHERE id=?`);
      for (const r of rows) {
        try {
          const decompressed = typeof r.payload_json === "string" ? maybeDecompressPayload(r.payload_json) : String(r.payload_json);
          const raw = typeof decompressed === "string" ? decompressed : JSON.stringify(decompressed);
          const h = require("crypto").createHash("sha256").update(raw).digest("hex");
          upd.run(h, r.id);
        } catch {
          // fallback: hash stored string
          const h = require("crypto").createHash("sha256").update(String(r.payload_json)).digest("hex");
          upd.run(h, r.id);
        }
      }
    }

    this.recoverStaleInflight(600);
  }

  enqueue(input: EnqueueInput): number {
    const rawJson = JSON.stringify(input.payload);
    const baselineHash =
      input &&
      typeof input.payload === "object" &&
      input.payload !== null &&
      typeof (input.payload as any)?._meta?.baselineHash === "string"
        ? String((input.payload as any)._meta.baselineHash)
        : null;

    const hash = baselineHash || require("crypto")
      .createHash("sha256")
      .update(rawJson)
      .digest("hex");

    const payloadJson = maybeCompressPayload(rawJson);
    // prevent extremely large payloads from entering the outbox
    const maxBytes = 2 * 1024 * 1024; // 2MB safety limit
    if (Buffer.byteLength(payloadJson, "utf8") > maxBytes) {
      throw new Error("Outbox payload too large (>2MB)");
    }

    const existing = this.db
      .prepare(`
        SELECT id FROM outbox_events
        WHERE payload_hash = ?
          AND type = ?
          AND status IN ('PENDING','IN_FLIGHT')
        LIMIT 1
      `)
      .get(hash, input.type) as { id: number } | undefined;

    if (existing && typeof existing.id === "number") {
      return existing.id;
    }

    const stmt = this.db.prepare(`
      INSERT INTO outbox_events
      (type, created_at_utc, payload_json, payload_hash, status, attempts, next_attempt_at_utc)
      VALUES (?, ?, ?, ?, 'PENDING', 0, ?)
    `);

    const now = utcNow();

    const result = stmt.run(
      input.type,
      now,
      payloadJson,
      hash,
      now
    );

    console.log("[outbox] enqueue inserted", {
      id: Number(result.lastInsertRowid),
      type: input.type,
      hash
    });

    this.notifyChanged();
    return Number(result.lastInsertRowid);
  }

  leaseReady(limit = 25): Array<Record<string, any>> {
    const now = utcNow();

    // Fast-path: skip DB work if no pending events exist
    const hasPending = this.db
      .prepare(`
        SELECT 1
        FROM outbox_events
        WHERE status='PENDING'
          AND attempts < ?
          AND next_attempt_at_utc <= ?
        LIMIT 1
      `)
      .get(MAX_ATTEMPTS, now);

    if (!hasPending) {
      return [];
    }

    const tx = this.db.transaction(() => {
      const candidates = this.db
        .prepare(`
          SELECT id
          FROM outbox_events
          WHERE status='PENDING'
            AND attempts < ?
            AND next_attempt_at_utc <= ?
          ORDER BY id ASC
          LIMIT ?
        `)
        .all(MAX_ATTEMPTS, now, limit) as Array<{ id: number }>;

      if (candidates.length === 0) return [];

      const ids = candidates.map((r: { id: number }) => Number(r.id));

      const placeholders = ids.map(() => "?").join(",");

      const updRes = this.db.prepare(`
        UPDATE outbox_events
        SET status='IN_FLIGHT',
            locked_at_utc=?,
            lock_owner=?
        WHERE id IN (${placeholders})
          AND status='PENDING'
          AND lock_owner IS NULL
      `).run(now, this.lockOwner, ...ids);

      if ((updRes as any)?.changes === 0) {
        return [];
      }

      const rows = this.db.prepare(`
        SELECT *
        FROM outbox_events
        WHERE id IN (${placeholders})
          AND status='IN_FLIGHT'
          AND lock_owner=?
        ORDER BY id ASC
      `).all(...ids, this.lockOwner);

      return rows.map((r: any) => {
        let payload = r.payload_json;

        if (typeof payload === "string") {
          const decompressed = maybeDecompressPayload(payload);
          try {
            payload = JSON.parse(decompressed);
          } catch {
            payload = decompressed;
          }
        }

        return {
          ...r,
          payload_json: payload
        };
      });
    });

    return tx();
  }

  markSent(id: number) {
    const now = utcNow();

    //console.log("[outbox] markSent called", { id, dbPath: this.dbPath });

    const res = this.db.prepare(`
      UPDATE outbox_events
      SET status='SENT',
          sent_at_utc=?,
          locked_at_utc=NULL,
          lock_owner=NULL,
          last_error=NULL
      WHERE id=? AND status IN ('PENDING','IN_FLIGHT')
    `).run(now, id);

    //console.log("[outbox] markSent result", { id, changes: (res as any)?.changes });

    const row = this.db
      .prepare(`SELECT id, status, lock_owner, sent_at_utc FROM outbox_events WHERE id=?`)
      .get(id);

    //console.log("[outbox] row after markSent", row);

    if ((res as any)?.changes === 0) {
      console.warn("markSent: no rows updated (unexpected state)", { id });
      return;
    }

    this.notifyChanged();
  }

  markFailed(id: number, error: string) {
    const row = this.db
      .prepare("SELECT attempts FROM outbox_events WHERE id=? AND status IN ('PENDING','IN_FLIGHT')")
      .get(id) as OutboxAttemptsRow | undefined;

    if (!row) {
      return;
    }

    const attempts = (row?.attempts ?? 0) + 1;

    if (attempts >= MAX_ATTEMPTS) {
      this.db.prepare(`
        UPDATE outbox_events
        SET status='FAILED',
            attempts=?,
            locked_at_utc=NULL,
            lock_owner=NULL,
            last_error=?
        WHERE id=?
      `).run(attempts, error.slice(0, 2000), id);
      this.notifyChanged();
      return;
    }

    const next = addSecondsIso(utcNow(), computeBackoffSeconds(attempts));

    this.db.prepare(`
      UPDATE outbox_events
      SET status='PENDING',
          attempts=?,
          next_attempt_at_utc=?,
          locked_at_utc=NULL,
          lock_owner=NULL,
          last_error=?
      WHERE id=?
    `).run(attempts, next, error.slice(0, 2000), id);
    this.notifyChanged();
  }

  markRejected(id: number, error: string) {
    const res = this.db.prepare(`
      UPDATE outbox_events
      SET status='FAILED',
          locked_at_utc=NULL,
          lock_owner=NULL,
          last_error=?
      WHERE id=? AND status IN ('PENDING','IN_FLIGHT')
    `).run(error.slice(0, 2000), id);

    if ((res as any)?.changes === 0) {
      console.warn("markRejected: no rows updated (unexpected state)", { id });
      return;
    }

    this.notifyChanged();
  }

  recoverStaleInflight(ttlSeconds: number) {
    const cutoff = addSecondsIso(utcNow(), -ttlSeconds);

    const rows = this.db.prepare(`
      SELECT id, attempts
      FROM outbox_events
      WHERE status='IN_FLIGHT'
        AND locked_at_utc < ?
        AND lock_owner IS NOT NULL
    `).all(cutoff) as Array<{ id: number; attempts: number }>;

    const upd = this.db.prepare(`
      UPDATE outbox_events
      SET status='PENDING',
          attempts=?,
          next_attempt_at_utc=?,
          locked_at_utc=NULL,
          lock_owner=NULL
      WHERE id=?
    `);

    const fail = this.db.prepare(`
      UPDATE outbox_events
      SET status='FAILED',
          attempts=?,
          locked_at_utc=NULL,
          lock_owner=NULL,
          last_error=?
      WHERE id=?
    `);

    let changed = false;
    for (const r of rows) {
      const nextAttempts = (r.attempts ?? 0) + 1;

      if (nextAttempts >= MAX_ATTEMPTS) {
        fail.run(nextAttempts, "stale inflight exceeded max attempts", r.id);
        changed = true;
        continue;
      }

      const next = addSecondsIso(utcNow(), computeBackoffSeconds(nextAttempts));
      upd.run(nextAttempts, next, r.id);
      changed = true;
    }
    if (changed) {
      this.notifyChanged();
    }
  }

  hasPendingOfType(type: OutboxEventType): boolean {
    const row = this.db
      .prepare(`
        SELECT id
        FROM outbox_events
        WHERE type = ?
          AND status IN ('PENDING', 'IN_FLIGHT')
        ORDER BY id ASC
        LIMIT 1
      `)
      .get(type) as { id: number } | undefined;

    return !!row;
  }

  cleanup(retentionDays = 14) {
    const cutoff = addSecondsIso(
      utcNow(),
      -(retentionDays * 86400)
    );

    this.db.prepare(`
      DELETE FROM outbox_events
      WHERE (status='SENT' AND sent_at_utc < ?)
         OR (status='FAILED' AND created_at_utc < ?)
    `).run(cutoff, cutoff);
  }

  getState(key: string): string | null {
    const row = this.db
      .prepare(`SELECT value FROM agent_state WHERE key=?`)
      .get(key) as { value: string } | undefined;

    return row?.value ?? null;
  }

  setState(key: string, value: string) {
    const now = utcNow();

    this.db.prepare(`
      INSERT INTO agent_state (key, value, updated_at_utc)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value=excluded.value,
        updated_at_utc=excluded.updated_at_utc
    `).run(key, value, now);
  }

  onChanged(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  }

  private notifyChanged() {
    for (const cb of Array.from(this.listeners)) {
      try {
        cb();
      } catch {}
    }
  }

  getNextReadyDelayMs(): number | null {
    const row = this.db
      .prepare(`
        SELECT next_attempt_at_utc
        FROM outbox_events
        WHERE status='PENDING'
          AND attempts < ?
        ORDER BY next_attempt_at_utc ASC
        LIMIT 1
      `)
      .get(MAX_ATTEMPTS) as { next_attempt_at_utc: string } | undefined;

    if (!row?.next_attempt_at_utc) {
      return null;
    }

    const delay = new Date(row.next_attempt_at_utc).getTime() - Date.now();
    return Math.max(0, delay);
  }
}

export const outbox = new SqliteOutbox();
