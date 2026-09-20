// src/plugins/amp/ad-discovery-job.ts
//
// Cobertura — el job `ad_discovery`: leer los objetos de EQUIPO de Active
// Directory en el equipo que el admin eligió como colector de AD, para que el
// control plane pueda decir qué equipos existen y cuáles no tienen agente.
//
// Gemelo de ad-printers-job: mismo colector, mismo recorrido, otra pregunta.
//
// El recorrido en este lado:
//   1. el rol `adPrinterCollector` llega en la política efectiva (lo deriva el
//      backend de su registro); un equipo sin rol ignora la orden. ⚠️ Es EL
//      MISMO rol que el de impresoras: una sola designación de «quién habla con
//      el dominio», no dos que se puedan contradecir
//   2. privsvc ejecuta `Scripts/ad-computers.ps1` por `-File` como SYSTEM, es
//      decir con la cuenta de máquina (método IPC `amp.ad.computers`)
//   3. el resultado —bueno o con el error del script— viaja como facts en el
//      namespace `ad_discovery`, por el outbox: persistencia, reintento y ACK
//      por evento sin tocar el proto
//   4. un fallo ANTES de tener resultado (privsvc caído, script sin firma,
//      timeout) se devuelve como ACK de error del job con su motivo
//
// Aquí no se interpreta nada del contenido: el backend valida y normaliza
// (modules/discovery/discovery-logic.ts). Un solo intérprete, no dos que
// diverjan — ni siquiera se mira cuántos equipos vinieron para el ACK, que se
// cuenta pero no se filtra.

import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";

/** Nombre del job; el backend lo declara en modules/orchestrator/job-types.ts. */
export const AD_DISCOVERY_JOB_TYPE = "ad_discovery";
/** Método IPC; Ipc/Router.cs lo enruta a AdComputers.Handle. */
export const AD_DISCOVERY_METHOD = "amp.ad.computers";
/** Namespace de facts; el backend lo atiende en controlplane.ts y va solo en su evento. */
export const AD_DISCOVERY_FACTS_NAMESPACE = "ad_discovery";

/**
 * Presupuesto que se pide al script. Por debajo del techo del handler
 * (AdComputersShape.HandlerCeilingMs = 120 s) y éste por debajo del cliente IPC
 * (150 s). Un AD con miles de objetos tarda más que 21 colas de impresión, y el
 * script pagina de 1000 en 1000 dentro de ese presupuesto.
 */
export const AD_DISCOVERY_BUDGET_MS = 100_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type AdDiscoveryPayload = { runId: string; trigger: "manual" | "scheduled" };

export function validateAdDiscoveryPayload(payload: unknown): { ok: true; payload: AdDiscoveryPayload } | { ok: false; error: string } {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return { ok: false, error: "not_an_object" };
  const p = payload as Record<string, unknown>;
  if (typeof p.runId !== "string" || !UUID.test(p.runId)) return { ok: false, error: "run_id" };
  if (p.trigger !== "manual" && p.trigger !== "scheduled") return { ok: false, error: "trigger" };
  return { ok: true, payload: { runId: p.runId.toLowerCase(), trigger: p.trigger } };
}

export type AdDiscoveryDeps = {
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

export async function runAdDiscoveryJob(deps: AdDiscoveryDeps, input: { jobId: string; payload: unknown }): Promise<JobAck> {
  if (deps.platform !== "win32") {
    return { status: 2, message: "ad_discovery_failed;reason=platform_not_supported" };
  }
  const parsed = validateAdDiscoveryPayload(input.payload);
  if (!parsed.ok) return { status: 2, message: `ad_discovery_failed;reason=bad_payload:${parsed.error}` };
  const { runId } = parsed.payload;

  // ⚠️ La autorización es el rol de la política, no el job: un job que llegue a
  // un equipo que ya no es colector (el admin lo cambió entre medias) no lee AD.
  if (!deps.isCollector()) {
    return { status: 2, message: `ad_discovery_failed;run=${runId};reason=not_collector` };
  }

  let resp: any;
  try {
    resp = await deps.call({
      v: 1,
      id: `adc-${runId}`,
      method: AD_DISCOVERY_METHOD,
      params: { runId, budgetMs: AD_DISCOVERY_BUDGET_MS },
      meta: deps.meta,
    });
  } catch (err: any) {
    deps.logger?.warn?.("[ad-discovery] privsvc call failed", { runId, error: err?.message || String(err) });
    return { status: 2, message: `ad_discovery_failed;run=${runId};reason=privsvc_unreachable:${reasonOf(err?.message)}` };
  }
  if (!resp?.ok) {
    return { status: 2, message: `ad_discovery_failed;run=${runId};reason=${reasonOf(resp?.error?.code || resp?.error?.message)}` };
  }

  const result = resp.result && typeof resp.result === "object" ? resp.result : {};
  // El resultado viaja ENTERO, también con `error`: el backend cierra la corrida
  // `failed` con el motivo del script y no toca la lista anterior.
  deps.enqueue({
    schemaVersion: FACTS_SCHEMA_VERSION,
    namespaces: { [AD_DISCOVERY_FACTS_NAMESPACE]: { ...result, kind: "result", runId } },
  });
  const computers = Array.isArray(result.computers) ? result.computers.length : 0;
  return {
    status: 0,
    message: result.error
      ? `ad_discovery_complete;run=${runId};error=1`
      : `ad_discovery_complete;run=${runId};computers=${computers}`,
  };
}
