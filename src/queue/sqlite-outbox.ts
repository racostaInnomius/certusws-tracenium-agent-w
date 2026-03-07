// src/queue/sqlite-outbox.ts
import os from "os";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";

export type OutboxStatus = "PENDING" | "IN_FLIGHT" | "SENT" | "FAILED";

export type OutboxEventType =
  | "FACTS_SNAPSHOT"
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

  constructor(private dbPath = defaultDbPath()) {
    this.lockOwner = `agentcore:${os.hostname()}:${process.pid}`;

    const dir = path.dirname(dbPath);
    fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(dbPath);
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
    `);

    this.recoverStaleInflight(600);
  }

  enqueue(input: EnqueueInput): number {
    const stmt = this.db.prepare(`
      INSERT INTO outbox_events
      (type, created_at_utc, payload_json, status, attempts, next_attempt_at_utc)
      VALUES (?, ?, ?, 'PENDING', 0, ?)
    `);

    const now = utcNow();

    const result = stmt.run(
      input.type,
      now,
      JSON.stringify(input.payload),
      now
    );

    return Number(result.lastInsertRowid);
  }

  leaseReady(limit = 25): any[] {
    const now = utcNow();

    const tx = this.db.transaction(() => {
      const candidates = this.db
        .prepare(`
          SELECT id
          FROM outbox_events
          WHERE status='PENDING'
            AND next_attempt_at_utc <= ?
          ORDER BY id ASC
          LIMIT ?
        `)
        .all(now, limit);

      if (candidates.length === 0) return [];

      const ids = candidates.map((r: any) => r.id);

      const placeholders = ids.map(() => "?").join(",");

      this.db.prepare(`
        UPDATE outbox_events
        SET status='IN_FLIGHT',
            locked_at_utc=?,
            lock_owner=?
        WHERE id IN (${placeholders})
      `).run(now, this.lockOwner, ...ids);

      return this.db.prepare(`
        SELECT *
        FROM outbox_events
        WHERE id IN (${placeholders})
        ORDER BY id ASC
      `).all(...ids);
    });

    return tx();
  }

  markSent(id: number) {
    const now = utcNow();

    this.db.prepare(`
      UPDATE outbox_events
      SET status='SENT',
          sent_at_utc=?,
          locked_at_utc=NULL,
          lock_owner=NULL,
          last_error=NULL
      WHERE id=?
    `).run(now, id);
  }

  markFailed(id: number, error: string) {
    const row = this.db
      .prepare("SELECT attempts FROM outbox_events WHERE id=?")
      .get(id) as OutboxAttemptsRow | undefined;

    const attempts = (row?.attempts ?? 0) + 1;
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
  }

  recoverStaleInflight(ttlSeconds: number) {
    const cutoff = addSecondsIso(utcNow(), -ttlSeconds);

    this.db.prepare(`
      UPDATE outbox_events
      SET status='PENDING',
          locked_at_utc=NULL,
          lock_owner=NULL
      WHERE status='IN_FLIGHT'
        AND locked_at_utc < ?
    `).run(cutoff);
  }

  cleanup(retentionDays = 14) {
    const cutoff = addSecondsIso(
      utcNow(),
      -(retentionDays * 86400)
    );

    this.db.prepare(`
      DELETE FROM outbox_events
      WHERE status='SENT'
        AND sent_at_utc < ?
    `).run(cutoff);
  }
}