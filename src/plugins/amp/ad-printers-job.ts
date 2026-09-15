// src/plugins/amp/ad-printers-job.ts
//
// ADR-0023 — el job `ad_printers`: leer las impresoras publicadas en Active
// Directory en el equipo que eligió el admin (Agent Settings → Asset
// Management), y devolverlas al control plane.
//
// El recorrido en este lado:
//   1. el rol `adPrinterCollector` llega en la política efectiva (lo deriva el
//      backend de su registro); un equipo sin rol ignora la orden
//   2. privsvc ejecuta `Scripts/ad-printers.ps1` por `-File` como SYSTEM, es
//      decir con la cuenta de máquina (método IPC `amp.ad.printers`)
//   3. el resultado —bueno o con el error del script— viaja como facts en el
//      namespace `ad_printers`, por el outbox: persistencia, reintento y ACK por
//      evento sin tocar el proto
//   4. un fallo ANTES de tener resultado (privsvc caído, script sin firma,
//      timeout) se devuelve como ACK de error del job con su motivo
//
// Aquí no se interpreta nada del contenido: el backend valida y normaliza
// (modules/ad-printers/ad-printers-logic.ts). Un solo intérprete, no dos que
// diverjan.

import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";

/** Nombre del job; el backend lo declara en modules/orchestrator/job-types.ts. */
export const AD_PRINTERS_JOB_TYPE = "ad_printers";
/** Método IPC; Ipc/Router.cs lo enruta a AdPrinters.Handle. */
export const AD_PRINTERS_METHOD = "amp.ad.printers";
/** Namespace de facts; el backend lo atiende en controlplane.ts y va solo en su evento. */
export const AD_PRINTERS_FACTS_NAMESPACE = "ad_printers";

/**
 * Presupuesto que se pide al script. Por debajo del techo del handler
 * (AdPrintersShape.HandlerCeilingMs = 120 s) y éste por debajo del cliente IPC
 * (150 s). En T111 la consulta tardó 314 ms: el margen es para DCs lentos.
 */
export const AD_PRINTERS_BUDGET_MS = 100_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type AdPrintersPayload = { runId: string; trigger: "manual" | "scheduled" };

export function validateAdPrintersPayload(payload: unknown): { ok: true; payload: AdPrintersPayload } | { ok: false; error: string } {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return { ok: false, error: "not_an_object" };
  const p = payload as Record<string, unknown>;
  if (typeof p.runId !== "string" || !UUID.test(p.runId)) return { ok: false, error: "run_id" };
  if (p.trigger !== "manual" && p.trigger !== "scheduled") return { ok: false, error: "trigger" };
  return { ok: true, payload: { runId: p.runId.toLowerCase(), trigger: p.trigger } };
}

export type AdPrintersDeps = {
  platform: NodeJS.Platform;
  isCollector: () => boolean;
  call: (req: { v: 1; id: string; method: string; params: Record<string, unknown>; meta: { tenantId: string; deviceId: string } }) => Promise<any>;
  enqueue: (payload: unknown) => number;
  meta: { tenantId: string; deviceId: string };
  logger?: { warn?: (...a: any[]) => void };
};

export type JobAck = { status: 0 | 1 | 2; message: string };

/** Sólo caracteres seguros en un campo `reason=` de un ACK (`;` y `=` lo romperían). */
function reasonOf(v: unknown): string {
  return String(v ?? "unknown").replace(/[^A-Za-z0-9_.:\- ]/g, "_").slice(0, 120) || "unknown";
}

export async function runAdPrintersJob(deps: AdPrintersDeps, input: { jobId: string; payload: unknown }): Promise<JobAck> {
  if (deps.platform !== "win32") {
    return { status: 2, message: "ad_printers_failed;reason=platform_not_supported" };
  }
  const parsed = validateAdPrintersPayload(input.payload);
  if (!parsed.ok) return { status: 2, message: `ad_printers_failed;reason=bad_payload:${parsed.error}` };
  const { runId } = parsed.payload;

  // ⚠️ La autorización es el rol de la política, no el job: un job que llegue a
  // un equipo que ya no es colector (el admin lo cambió entre medias) no lee AD.
  if (!deps.isCollector()) {
    return { status: 2, message: `ad_printers_failed;run=${runId};reason=not_collector` };
  }

  let resp: any;
  try {
    resp = await deps.call({
      v: 1,
      id: `adp-${runId}`,
      method: AD_PRINTERS_METHOD,
      params: { runId, budgetMs: AD_PRINTERS_BUDGET_MS },
      meta: deps.meta,
    });
  } catch (err: any) {
    deps.logger?.warn?.("[ad-printers] privsvc call failed", { runId, error: err?.message || String(err) });
    return { status: 2, message: `ad_printers_failed;run=${runId};reason=privsvc_unreachable:${reasonOf(err?.message)}` };
  }
  if (!resp?.ok) {
    return { status: 2, message: `ad_printers_failed;run=${runId};reason=${reasonOf(resp?.error?.code || resp?.error?.message)}` };
  }

  const result = resp.result && typeof resp.result === "object" ? resp.result : {};
  // El resultado viaja ENTERO, también con `error`: el backend cierra la corrida
  // `failed` con el motivo del script y no toca la lista anterior.
  deps.enqueue({
    schemaVersion: FACTS_SCHEMA_VERSION,
    namespaces: { [AD_PRINTERS_FACTS_NAMESPACE]: { ...result, kind: "result", runId } },
  });
  const queues = Array.isArray(result.queues) ? result.queues.length : 0;
  return {
    status: 0,
    message: result.error
      ? `ad_printers_complete;run=${runId};error=1`
      : `ad_printers_complete;run=${runId};queues=${queues}`,
  };
}
