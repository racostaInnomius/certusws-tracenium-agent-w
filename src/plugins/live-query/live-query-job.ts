// src/plugins/live-query/live-query-job.ts
//
// ADR-0029 F2 — el job `live_query`: una pregunta de la consulta en vivo.
//
// El recorrido en este lado:
//   1. revalidar la pregunta (domain/live-query-question.ts): lo que el backend
//      aceptó no se lee sin volver a mirarlo
//   2. la sonda corre con un tope de tiempo: el backend da 120 s y la pantalla
//      espera; mejor un «error: timeout» a los 30 s que un silencio
//   3. la respuesta viaja como facts en el namespace `live_query`, SOLO, por el
//      outbox: persistencia, reintento y ACK por evento sin tocar el proto. El
//      backend la ata a (pregunta, equipo del certificado)
//   4. el ACK del job dice el desenlace; el dato va en los facts
//
// Una pregunta que el agente rechaza también se contesta (outcome `error` con
// el motivo), para que la pantalla diga por qué ese equipo no respondió en vez
// de dejarlo en «no answer».

import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";
import { parseLiveQueryJob } from "../../domain/live-query-question";
import { runProbe, type ProbeDeps, type ProbeOutcome } from "./probes";

/** Nombre del job; el backend lo declara en modules/orchestrator/job-types.ts. */
export const LIVE_QUERY_JOB_TYPE = "live_query";
/** Namespace de facts; el backend lo atiende en controlplane.ts y va solo en su evento. */
export const LIVE_QUERY_FACTS_NAMESPACE = "live_query";
/** Tope de una sonda. Cada comando tiene 10 s; esto cubre dos seguidos y el hash. */
export const LIVE_QUERY_BUDGET_MS = 30_000;

export type LiveQueryJobDeps = {
  probe: ProbeDeps;
  /** ¿AMP está activo en la política? Defensa en profundidad: el backend ya lo exige. */
  ampEnabled: () => boolean;
  enqueue: (payload: unknown) => number;
  budgetMs?: number;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void };
};

export type JobAck = { status: 0 | 1 | 2; message: string };

/** Sólo caracteres seguros en un campo de ACK (`;` y `=` lo romperían). */
function safe(v: unknown): string {
  return String(v ?? "unknown").replace(/[^A-Za-z0-9_.:\- ]/g, "_").slice(0, 120) || "unknown";
}

function withBudget(p: Promise<ProbeOutcome>, ms: number): Promise<ProbeOutcome> {
  let t: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<ProbeOutcome>((resolve) => {
      t = setTimeout(() => resolve({ outcome: "error", error: `timeout after ${Math.round(ms / 1000)} s` }), ms);
    }),
  ]).finally(() => clearTimeout(t));
}

export async function runLiveQueryJob(deps: LiveQueryJobDeps, input: { jobId: string; payload: unknown }): Promise<JobAck> {
  const parsed = parseLiveQueryJob(input.payload);
  const send = (queryId: string, probe: unknown, o: ProbeOutcome) =>
    deps.enqueue({
      schemaVersion: FACTS_SCHEMA_VERSION,
      namespaces: {
        [LIVE_QUERY_FACTS_NAMESPACE]: {
          queryId,
          probe,
          outcome: o.outcome,
          ...(o.outcome === "answered" ? { answer: o.answer } : {}),
          ...(o.outcome === "error" ? { error: o.error } : {}),
        },
      },
    });

  if (!parsed.ok) {
    // Sin queryId válido no hay a quién contestar; con él, se dice el motivo.
    const probe = (input.payload as any)?.probe;
    if (parsed.queryId && typeof probe === "string") send(parsed.queryId, probe, { outcome: "error", error: `rejected by the agent: ${parsed.error}` });
    return { status: 2, message: `live_query_failed;reason=bad_payload:${safe(parsed.error)}` };
  }
  const { queryId, question } = parsed.job;

  if (!deps.ampEnabled()) {
    send(queryId, question.probe, { outcome: "error", error: "Asset Management is not enabled on this device" });
    return { status: 2, message: `live_query_failed;query=${queryId};reason=amp_disabled` };
  }

  const started = Date.now();
  const outcome = await withBudget(runProbe(deps.probe, question), deps.budgetMs ?? LIVE_QUERY_BUDGET_MS);
  send(queryId, question.probe, outcome);
  deps.logger?.info?.("[live-query] answered", { queryId, probe: question.probe, outcome: outcome.outcome, ms: Date.now() - started });
  return { status: 0, message: `live_query_answered;query=${queryId};outcome=${outcome.outcome}` };
}
