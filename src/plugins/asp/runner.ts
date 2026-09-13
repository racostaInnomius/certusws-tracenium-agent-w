// src/plugins/asp/runner.ts
//
// ADR-0022 — una corrida de Assessment Service en el DC colector.
//
//   1. Parte el catálogo en tandas y pide cada una al PrivSvc (`asp.ad.collect`,
//      carril IPC lento: 330 s de cliente sobre un handler de 300 s).
//   2. Sostiene el presupuesto TOTAL de 900 s. Una corrida que no cabe falla
//      entera: nunca se sube una corrida con indicadores recortados, porque el
//      backend no puntuaría y el cliente vería un score de datos parciales.
//   3. Evalúa en local (evaluate.ts) y escribe la corrida en SQLite.
//   4. Encola los trozos y el cierre en el outbox como facts del namespace
//      `asp`. El outbox da persistencia, reintento y ACK por evento.
//
// Sin dependencias de transporte: se le inyectan IPC, almacén y outbox, que es
// lo que permite probar el recorrido completo sin Windows ni gRPC.

import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";
import { evaluateIndicator, type AgentIndicator, type AspResult, type CollectorInfo, type CollectorQueryResult } from "./evaluate";
import { compilePredicate } from "./predicate";
import type { AspRunStore } from "./run-store";

/** Método IPC del PrivSvc. El test de los tres saltos lo busca en el router C#. */
export const ASP_COLLECT_METHOD = "asp.ad.collect";
/** Tipo de job del backend (modules/orchestrator/job-types.ts). Pineado a mano. */
export const ASP_JOB_TYPE = "asp_assess";

export const ASP_RUN_BUDGET_MS_DEFAULT = 900_000;
/** Techo del handler del PrivSvc por tanda (AspCollectorShape.HandlerCeilingMs). */
export const ASP_PRIVSVC_BATCH_CEILING_MS = 300_000;
export const ASP_BATCH_SIZE = 8;
export const ASP_CHUNK_SIZE = 10;
/** Por debajo de esto no se lanza otra tanda: no daría tiempo ni a arrancar PowerShell. */
const MIN_BATCH_BUDGET_MS = 20_000;
const LATIDO_MS = 60_000;

export type AspAssessPayload = {
  runId: string;
  instanceId: number;
  domain: string;
  catalogFamily: string;
  catalogVersion: string;
  budgetSeconds: number;
  evidenceLimit: number;
  trigger: "manual" | "scheduled";
  indicators: AgentIndicator[];
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateAssessPayload(raw: any): { ok: true; payload: AspAssessPayload } | { ok: false; error: string } {
  if (!raw || typeof raw !== "object") return { ok: false, error: "payload_not_object" };
  if (typeof raw.runId !== "string" || !UUID_RE.test(raw.runId)) return { ok: false, error: "bad_run_id" };
  if (!Number.isSafeInteger(raw.instanceId) || raw.instanceId <= 0) return { ok: false, error: "bad_instance_id" };
  if (typeof raw.domain !== "string" || !raw.domain.trim()) return { ok: false, error: "bad_domain" };
  if (!Array.isArray(raw.indicators) || raw.indicators.length === 0 || raw.indicators.length > 500) return { ok: false, error: "bad_indicators" };
  for (const ind of raw.indicators) {
    if (!ind || typeof ind.controlId !== "string" || !ind.query || typeof ind.query.kind !== "string") return { ok: false, error: "bad_indicator_shape" };
    // El backend ya compiló el predicado; se vuelve a compilar porque un
    // predicado roto aquí sería una excepción a mitad de corrida.
    if (compilePredicate(ind.predicate).length > 0) return { ok: false, error: `bad_predicate:${ind.controlId}` };
  }
  const budgetSeconds = Number(raw.budgetSeconds);
  const evidenceLimit = Number(raw.evidenceLimit);
  return {
    ok: true,
    payload: {
      runId: raw.runId.toLowerCase(),
      instanceId: raw.instanceId,
      domain: raw.domain.trim().toLowerCase(),
      catalogFamily: String(raw.catalogFamily ?? ""),
      catalogVersion: String(raw.catalogVersion ?? ""),
      budgetSeconds: Number.isFinite(budgetSeconds) && budgetSeconds > 0 ? Math.min(budgetSeconds, 3600) : ASP_RUN_BUDGET_MS_DEFAULT / 1000,
      evidenceLimit: Number.isInteger(evidenceLimit) && evidenceLimit >= 1 && evidenceLimit <= 200 ? evidenceLimit : 200,
      trigger: raw.trigger === "manual" ? "manual" : "scheduled",
      indicators: raw.indicators.map((i: any) => ({
        controlId: i.controlId,
        severity: i.severity,
        requires: i.requires,
        query: i.query,
        derive: Array.isArray(i.derive) ? i.derive : [],
        predicate: i.predicate,
        onFail: i.onFail === "needs_review" ? "needs_review" : "fail",
        whenMissing: i.whenMissing === "not_applicable" ? "not_applicable" : "not_assessed"
      }))
    }
  };
}

/**
 * Tandas: las sondas de registro juntas (son lecturas puntuales del propio DC)
 * y el resto de a `size`. El orden dentro de cada tanda es el del catálogo.
 */
export function planBatches(indicators: AgentIndicator[], size = ASP_BATCH_SIZE): AgentIndicator[][] {
  const registry = indicators.filter((i) => i.query.kind === "registry");
  const rest = indicators.filter((i) => i.query.kind !== "registry");
  const out: AgentIndicator[][] = [];
  for (let i = 0; i < rest.length; i += size) out.push(rest.slice(i, i + size));
  if (registry.length) out.push(registry);
  return out;
}

/** Los eventos de facts de una corrida evaluada: N trozos y el cierre. */
export function buildUploadEvents(
  runId: string,
  results: AspResult[],
  meta: { durationMs: number; collectorNotes: string[] },
  chunkSize = ASP_CHUNK_SIZE
): Array<{ schemaVersion: string; namespaces: { asp: Record<string, unknown> } }> {
  const events: Array<{ schemaVersion: string; namespaces: { asp: Record<string, unknown> } }> = [];
  const chunks = Math.max(1, Math.ceil(results.length / chunkSize));
  for (let seq = 0; seq < chunks; seq++) {
    events.push({
      schemaVersion: FACTS_SCHEMA_VERSION,
      namespaces: { asp: { kind: "chunk", runId, seq, results: results.slice(seq * chunkSize, (seq + 1) * chunkSize) } }
    });
  }
  events.push({
    schemaVersion: FACTS_SCHEMA_VERSION,
    namespaces: {
      asp: { kind: "complete", runId, indicatorsTotal: results.length, chunksTotal: chunks, durationMs: meta.durationMs, collectorNotes: meta.collectorNotes }
    }
  });
  return events;
}

export type EnqueueFn = (payload: unknown) => number;

/** Encola una corrida ya evaluada. Idempotente: el outbox deduplica por contenido. */
export function enqueueEvaluatedRun(store: AspRunStore, enqueue: EnqueueFn, runId: string): number {
  const run = store.get(runId);
  if (!run || (run.status !== "evaluated" && run.status !== "enqueued")) return 0;
  const events = buildUploadEvents(runId, store.results(runId), { durationMs: run.durationMs ?? 0, collectorNotes: run.collectorNotes });
  for (const e of events) enqueue(e);
  store.markEnqueued(runId);
  return events.length;
}

export type AspPrivCall = (req: { v: 1; id: string; method: string; params: Record<string, unknown>; meta: { tenantId: string; deviceId: string } }) => Promise<any>;

export type RunnerDeps = {
  call: AspPrivCall;
  store: AspRunStore;
  enqueue: EnqueueFn;
  meta: { tenantId: string; deviceId: string };
  now?: () => number;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void };
  onProgress?: (done: number, total: number) => void;
};

export type RunOutcome =
  | { status: "complete"; indicators: number; chunks: number; durationMs: number; notAssessed: number }
  | { status: "failed"; reason: string };

let inFlight: string | null = null;

/** Para la guardia de update-task: una corrida viva no se deja matar por un MSI. */
export function aspRunInFlight(): string | null {
  return inFlight;
}

export async function runAspAssessment(deps: RunnerDeps, input: { jobId: string; payload: AspAssessPayload }): Promise<RunOutcome> {
  const now = deps.now ?? Date.now;
  const { payload } = input;
  const started = now();
  const deadline = started + payload.budgetSeconds * 1000;
  const total = payload.indicators.length;

  deps.store.start({
    runId: payload.runId,
    instanceId: payload.instanceId,
    domain: payload.domain,
    jobId: input.jobId,
    indicatorsTotal: total,
    startedAt: new Date(started).toISOString()
  });
  inFlight = payload.runId;

  try {
    const raw = new Map<string, CollectorQueryResult>();
    let collector: CollectorInfo = null;
    let contextError: string | null = null;
    let done = 0;
    const batches = planBatches(payload.indicators);

    for (let b = 0; b < batches.length; b++) {
      const remaining = deadline - now();
      if (remaining < MIN_BATCH_BUDGET_MS) {
        const reason = `budget_exceeded:batch_${b}_of_${batches.length}`;
        deps.store.markFailed(payload.runId, reason);
        return { status: "failed", reason };
      }
      const batch = batches[b];
      let resp: any;
      try {
        resp = await deps.call({
          v: 1,
          id: `asp-${payload.runId}-${b}`,
          method: ASP_COLLECT_METHOD,
          params: {
            runId: payload.runId,
            batch: b,
            evidenceLimit: payload.evidenceLimit,
            budgetMs: Math.min(remaining - 5_000, ASP_PRIVSVC_BATCH_CEILING_MS),
            queries: batch.map((i) => ({ id: i.controlId, query: i.query }))
          },
          meta: deps.meta
        });
      } catch (err: any) {
        const reason = `ipc:${String(err?.message || err).slice(0, 160)}`;
        deps.store.markFailed(payload.runId, reason);
        return { status: "failed", reason };
      }
      if (!resp?.ok) {
        // El colector no pudo ni arrancar (script ausente o sin firma, tanda
        // rechazada, timeout del proceso): la corrida entera falla con el
        // código del PrivSvc. No se convierte en 30 `not_assessed`, que
        // parecería una corrida válida sin cobertura.
        const reason = `privsvc:${resp?.error?.code || "unknown"}${resp?.error?.message ? `:${String(resp.error.message).slice(0, 120)}` : ""}`;
        deps.store.markFailed(payload.runId, reason);
        return { status: "failed", reason };
      }
      const result = resp.result ?? {};
      if (!collector && result.collector) collector = result.collector;
      if (result.contextError && !contextError) contextError = String(result.contextError.hresult ?? result.contextError.message ?? "context_error");
      for (const ind of batch) {
        const r = result.results?.[ind.controlId];
        if (r) raw.set(ind.controlId, r);
      }
      done += batch.length;
      deps.onProgress?.(done, total);
    }

    const nowMs = now();
    const results = payload.indicators.map((ind) => evaluateIndicator(ind, raw.get(ind.controlId), collector, { evidenceLimit: payload.evidenceLimit, nowMs }));
    const durationMs = nowMs - started;
    const collectorNotes = [
      collector ? `host:${(collector as any).host ?? "?"}` : "host:unknown",
      collector ? `is_dc:${collector.isDomainController === true}` : "is_dc:unknown",
      collector && (collector as any).ranAs ? `ran_as:${(collector as any).ranAs}` : null,
      collector && (collector as any).psVersion ? `ps:${(collector as any).psVersion}` : null,
      contextError ? `context_error:${contextError}` : null
    ].filter(Boolean) as string[];

    const chunks = Math.max(1, Math.ceil(results.length / ASP_CHUNK_SIZE));
    deps.store.saveEvaluated(payload.runId, results, { chunksTotal: chunks, durationMs, collectorNotes, finishedAt: new Date(nowMs).toISOString() });
    enqueueEvaluatedRun(deps.store, deps.enqueue, payload.runId);

    const notAssessed = results.filter((r) => r.status === "not_assessed").length;
    deps.logger?.info?.("[asp] run evaluated and enqueued", { runId: payload.runId, indicators: results.length, chunks, durationMs, notAssessed });
    return { status: "complete", indicators: results.length, chunks, durationMs, notAssessed };
  } catch (err: any) {
    const reason = `runner:${String(err?.message || err).slice(0, 160)}`;
    try {
      deps.store.markFailed(payload.runId, reason);
    } catch {
      /* el almacén también puede ser la causa */
    }
    return { status: "failed", reason };
  } finally {
    inFlight = null;
  }
}

export { LATIDO_MS as ASP_HEARTBEAT_MS };
