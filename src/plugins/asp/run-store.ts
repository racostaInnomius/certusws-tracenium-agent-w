// src/plugins/asp/run-store.ts
//
// ADR-0022 decisión 3 — la corrida entera se escribe en la SQLite del agente
// ANTES de subir nada. Sobrevive a un reinicio del agente: una corrida evaluada
// que no llegó a encolarse se encola al arrancar, y los trozos ya encolados los
// reintenta el outbox desde el último ACK.
//
// Base propia (`asp.db`) y no la del outbox: el outbox se auto-repara
// reconstruyendo el fichero si lo ve corrupto, y la corrida no debe perderse con
// él. Constructor con ruta inyectable para los tests.

import Database from "better-sqlite3";
import path from "path";
import { agentDataDir, ensureAgentDataDir } from "../../bootstrap/paths";
import type { AspResult } from "./evaluate";

export type LocalRunStatus = "running" | "evaluated" | "enqueued" | "failed" | "aborted";

export type LocalRun = {
  runId: string;
  instanceId: number;
  domain: string;
  jobId: string;
  status: LocalRunStatus;
  startedAt: string;
  finishedAt: string | null;
  indicatorsTotal: number;
  chunksTotal: number | null;
  durationMs: number | null;
  collectorNotes: string[];
  error: string | null;
};

function rowToRun(r: any): LocalRun {
  return {
    runId: String(r.run_id),
    instanceId: Number(r.instance_id),
    domain: String(r.domain),
    jobId: String(r.job_id),
    status: r.status,
    startedAt: String(r.started_at),
    finishedAt: r.finished_at ?? null,
    indicatorsTotal: Number(r.indicators_total),
    chunksTotal: r.chunks_total == null ? null : Number(r.chunks_total),
    durationMs: r.duration_ms == null ? null : Number(r.duration_ms),
    collectorNotes: r.collector_notes ? JSON.parse(r.collector_notes) : [],
    error: r.error ?? null
  };
}

export class AspRunStore {
  private db: Database.Database;

  constructor(dbPath?: string) {
    if (!dbPath) ensureAgentDataDir();
    this.db = new Database(dbPath ?? path.join(agentDataDir(), "asp.db"));
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS asp_runs (
        run_id           TEXT PRIMARY KEY,
        instance_id      INTEGER NOT NULL,
        domain           TEXT NOT NULL,
        job_id           TEXT NOT NULL,
        status           TEXT NOT NULL,
        started_at       TEXT NOT NULL,
        finished_at      TEXT,
        indicators_total INTEGER NOT NULL,
        chunks_total     INTEGER,
        duration_ms      INTEGER,
        collector_notes  TEXT,
        error            TEXT
      );
      CREATE TABLE IF NOT EXISTS asp_run_results (
        run_id         TEXT NOT NULL,
        control_id     TEXT NOT NULL,
        status         TEXT NOT NULL,
        severity       TEXT NOT NULL,
        affected_count INTEGER,
        evidence_json  TEXT,
        reason         TEXT,
        PRIMARY KEY (run_id, control_id)
      );
    `);
  }

  get(runId: string): LocalRun | null {
    const r = this.db.prepare(`SELECT * FROM asp_runs WHERE run_id = ?`).get(runId);
    return r ? rowToRun(r) : null;
  }

  running(): LocalRun | null {
    const r = this.db.prepare(`SELECT * FROM asp_runs WHERE status = 'running' ORDER BY started_at DESC LIMIT 1`).get();
    return r ? rowToRun(r) : null;
  }

  start(input: { runId: string; instanceId: number; domain: string; jobId: string; indicatorsTotal: number; startedAt: string }): void {
    this.db
      .prepare(
        `INSERT INTO asp_runs (run_id, instance_id, domain, job_id, status, started_at, indicators_total)
         VALUES (?, ?, ?, ?, 'running', ?, ?)`
      )
      .run(input.runId, input.instanceId, input.domain, input.jobId, input.startedAt, input.indicatorsTotal);
  }

  /** Resultados + cierre en UNA transacción: o está la corrida entera o no está. */
  saveEvaluated(runId: string, results: AspResult[], meta: { chunksTotal: number; durationMs: number; collectorNotes: string[]; finishedAt: string }): void {
    const insert = this.db.prepare(
      `INSERT OR REPLACE INTO asp_run_results (run_id, control_id, status, severity, affected_count, evidence_json, reason)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    const tx = this.db.transaction(() => {
      this.db.prepare(`DELETE FROM asp_run_results WHERE run_id = ?`).run(runId);
      for (const r of results) {
        insert.run(runId, r.controlId, r.status, r.severity, r.affectedCount, JSON.stringify(r.evidence ?? null), r.reason);
      }
      this.db
        .prepare(
          `UPDATE asp_runs SET status = 'evaluated', finished_at = ?, chunks_total = ?, duration_ms = ?, collector_notes = ? WHERE run_id = ?`
        )
        .run(meta.finishedAt, meta.chunksTotal, meta.durationMs, JSON.stringify(meta.collectorNotes), runId);
    });
    tx();
  }

  results(runId: string): AspResult[] {
    return (this.db.prepare(`SELECT * FROM asp_run_results WHERE run_id = ? ORDER BY control_id`).all(runId) as any[]).map((r) => ({
      controlId: String(r.control_id),
      status: r.status,
      severity: r.severity,
      affectedCount: r.affected_count == null ? null : Number(r.affected_count),
      evidence: r.evidence_json ? JSON.parse(r.evidence_json) : null,
      reason: r.reason ?? null
    }));
  }

  markEnqueued(runId: string): void {
    this.db.prepare(`UPDATE asp_runs SET status = 'enqueued' WHERE run_id = ? AND status = 'evaluated'`).run(runId);
  }

  markFailed(runId: string, error: string): void {
    this.db.prepare(`UPDATE asp_runs SET status = 'failed', finished_at = ?, error = ? WHERE run_id = ?`).run(new Date().toISOString(), error.slice(0, 500), runId);
  }

  /** Evaluadas y sin encolar: lo que un reinicio dejó a medias. */
  pendingEnqueue(): LocalRun[] {
    return (this.db.prepare(`SELECT * FROM asp_runs WHERE status = 'evaluated' ORDER BY started_at`).all() as any[]).map(rowToRun);
  }

  /**
   * Al arrancar: una corrida `running` es de un proceso que ya no existe. Se da
   * por abortada; el backend la cerrará `incomplete` por TTL, que es la verdad.
   */
  abortRunning(): number {
    return this.db.prepare(`UPDATE asp_runs SET status = 'aborted', finished_at = ?, error = 'agent_restarted' WHERE status = 'running'`).run(new Date().toISOString()).changes;
  }

  /** Borra corridas cerradas de más de `days` días. La verdad ya está en el backend. */
  cleanup(days = 30): number {
    const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
    const old = this.db.prepare(`SELECT run_id FROM asp_runs WHERE status IN ('enqueued','failed','aborted') AND started_at < ?`).all(cutoff) as any[];
    const tx = this.db.transaction(() => {
      for (const r of old) {
        this.db.prepare(`DELETE FROM asp_run_results WHERE run_id = ?`).run(r.run_id);
        this.db.prepare(`DELETE FROM asp_runs WHERE run_id = ?`).run(r.run_id);
      }
    });
    tx();
    return old.length;
  }

  close(): void {
    this.db.close();
  }
}

let shared: AspRunStore | null = null;
export function getAspRunStore(): AspRunStore {
  if (!shared) shared = new AspRunStore();
  return shared;
}
