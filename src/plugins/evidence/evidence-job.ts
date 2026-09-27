// src/plugins/evidence/evidence-job.ts
//
// ADR-0032 F2 — el job `evidence_capture`.
//
// El recorrido:
//   1. revalidar la orden: lo que el backend aceptó no se ejecuta sin volver a
//      mirarlo (misma regla que ADR-0029)
//   2. correr los colectores con un presupuesto de tiempo. Lo VOLÁTIL primero
//      —sesiones y procesos—, porque es lo único que deja de existir si la
//      máquina se reinicia mientras capturamos
//   3. hashear cada artefacto EN EL EQUIPO y subirlo con el destino que da el
//      control plane
//   4. mandar el MANIFIESTO por el namespace `evidence`, con la hora del equipo
//      y su desfase
//
// ⚠️ El manifiesto se manda SIEMPRE, incluso si todo falló: un paquete vacío
// con la razón de cada ausencia es evidencia; el silencio no. El backend cierra
// la captura como `partial` o `failed` a partir de él.
//
// ⚠️ La carpeta de trabajo se borra al terminar, pase lo que pase. Dejar en el
// disco del cliente una copia de sus registros de seguridad sería exactamente
// el problema que este módulo dice cuidar.

import fsp from "fs/promises";
import os from "os";
import path from "path";
import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";
import {
  MAX_ARTIFACT_BYTES,
  runCollector,
  sha256File,
  type Artifact,
  type CollectorDeps,
  type CollectorKey,
  type CollectorParams,
} from "./collectors";

/** Nombre del job; el backend lo declara en modules/orchestrator/job-types.ts. */
export const EVIDENCE_JOB_TYPE = "evidence_capture";
/** Namespace de facts; viaja SOLO en su evento. */
export const EVIDENCE_FACTS_NAMESPACE = "evidence";
/** Presupuesto total de la captura. El backend da 15 min de timeout al job. */
export const EVIDENCE_BUDGET_MS = 10 * 60_000;
/** Tope del paquete entero. */
export const MAX_CAPTURE_BYTES = 200 * 1024 * 1024;

const KNOWN: readonly CollectorKey[] = [
  "sessions",
  "processes",
  "services",
  "network",
  "event_logs",
  "scheduled_tasks",
  "storage",
  "pending_reboot",
  "agent_self",
];

/**
 * Orden de ejecución: lo VOLÁTIL primero.
 *
 * No es cosmética. La captura ocurre en mitad de una incidencia, y la mitad de
 * las veces alguien está a punto de reiniciar la máquina «a ver si se arregla».
 * Si el reinicio nos pilla a medias, lo que tiene que estar ya recogido son las
 * sesiones y los procesos: los registros de eventos sobreviven al arranque, y
 * el estado volátil no.
 */
const ORDER: readonly CollectorKey[] = [
  "sessions",
  "processes",
  "network",
  "services",
  "pending_reboot",
  "scheduled_tasks",
  "storage",
  "event_logs",
  "agent_self",
];

export type ParsedCapture = { captureId: string; collectors: CollectorKey[]; params: CollectorParams };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Revalida la orden. Devuelve null con el motivo si no se puede ejecutar. */
export function parseEvidenceJob(payload: unknown): { ok: true; value: ParsedCapture } | { ok: false; error: string } {
  const p = payload && typeof payload === "object" && !Array.isArray(payload) ? (payload as Record<string, unknown>) : null;
  if (!p) return { ok: false, error: "payload is not an object" };

  const captureId = String(p.captureId ?? "").trim();
  if (!UUID_RE.test(captureId)) return { ok: false, error: "captureId is not a uuid" };

  if (!Array.isArray(p.collectors) || p.collectors.length === 0) return { ok: false, error: "collectors is empty" };
  const collectors: CollectorKey[] = [];
  for (const raw of p.collectors) {
    const key = String(raw ?? "").trim() as CollectorKey;
    // ⚠️ Un colector que este agente no conoce se IGNORA, no tumba la captura:
    // un backend más nuevo puede pedir uno que esta versión no trae, y lo útil
    // entonces es recoger el resto y decir qué faltó.
    if (KNOWN.includes(key) && !collectors.includes(key)) collectors.push(key);
  }
  if (!collectors.length) return { ok: false, error: "no known collector was requested" };

  const params = (p.params && typeof p.params === "object" && !Array.isArray(p.params) ? p.params : {}) as CollectorParams;
  return { ok: true, value: { captureId, collectors, params } };
}

export type ManifestEntry = {
  name: string;
  collector: CollectorKey;
  bytes: number;
  sha256?: string;
  status: "ok" | "failed" | "skipped";
  detail?: string;
};

export type EvidenceJobDeps = {
  platform: NodeJS.Platform;
  collectorDeps: (workDir: string) => CollectorDeps;
  /** Sube un artefacto y resuelve cuando el control plane lo tiene. */
  upload: (input: { captureId: string; name: string; filePath: string; bytes: number }) => Promise<void>;
  enqueue: (payload: unknown) => unknown;
  /** ¿AMP está activo? Defensa en profundidad: el backend ya lo exige. */
  ampEnabled?: () => boolean;
  mkdtemp?: (prefix: string) => Promise<string>;
  rm?: (dir: string) => Promise<void>;
  stat?: (p: string) => Promise<{ size: number }>;
  hash?: (p: string) => Promise<string>;
  now?: () => Date;
  budgetMs?: number;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void };
};

export type JobAck = { status: 0 | 1 | 2; message: string };

/** Sólo caracteres seguros en un campo de ACK (`;` y `=` lo romperían). */
function safe(v: unknown): string {
  return String(v ?? "unknown").replace(/[^A-Za-z0-9_.:\- ]/g, "_").slice(0, 120) || "unknown";
}

/**
 * El desfase del equipo respecto a UTC, en minutos.
 *
 * ⚠️ `getTimezoneOffset()` devuelve el signo AL REVÉS de como se escribe un
 * huso: en UTC-5 devuelve +300. Aquí se invierte, porque el backend exige
 * «minutos desde UTC» y un signo cambiado desplazaría la cronología DIEZ horas
 * en vez de cero. En el caso que originó esto, una hora mal colocada ya estuvo
 * a punto de fechar mal el incidente.
 */
export function utcOffsetMinutes(now: Date): number {
  return -now.getTimezoneOffset();
}

export function deviceTimeZone(): string | null {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {
    return null;
  }
}

export async function runEvidenceJob(deps: EvidenceJobDeps, input: { jobId: string; payload: unknown }): Promise<JobAck> {
  const parsed = parseEvidenceJob(input.payload);
  if (!parsed.ok) return { status: 2, message: `evidence_rejected;reason=${safe(parsed.error)}` };
  const { captureId, collectors, params } = parsed.value;

  if (deps.ampEnabled && !deps.ampEnabled()) {
    return { status: 2, message: "evidence_rejected;reason=amp_disabled" };
  }

  const mkdtemp = deps.mkdtemp ?? ((prefix: string) => fsp.mkdtemp(prefix));
  const rm = deps.rm ?? ((dir: string) => fsp.rm(dir, { recursive: true, force: true }));
  const stat = deps.stat ?? (async (p: string) => ({ size: (await fsp.stat(p)).size }));
  const hash = deps.hash ?? sha256File;
  const now = deps.now ?? (() => new Date());
  const budgetMs = deps.budgetMs ?? EVIDENCE_BUDGET_MS;

  const startedAt = Date.now();
  const capturedAt = now();
  let workDir: string | null = null;
  const entries: ManifestEntry[] = [];

  try {
    workDir = await mkdtemp(path.join(os.tmpdir(), "tracenium-evidence-"));
    const cDeps = deps.collectorDeps(workDir);
    const ordered = [...collectors].sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b));
    let uploadedBytes = 0;

    for (const key of ordered) {
      const left = budgetMs - (Date.now() - startedAt);
      if (left <= 0) {
        // Se dice cuál se quedó fuera, en vez de devolver un paquete que
        // parece completo porque nadie cuenta lo que falta.
        entries.push({ name: `${key}.skipped`, collector: key, bytes: 0, status: "failed", detail: "capture ran out of time before this collector" });
        continue;
      }

      let produced: Artifact[];
      try {
        produced = await runCollector(cDeps, key, params);
      } catch (err: any) {
        entries.push({ name: `${key}.failed`, collector: key, bytes: 0, status: "failed", detail: String(err?.message ?? err).slice(0, 300) });
        continue;
      }

      for (const art of produced) {
        if (art.status !== "ok") {
          entries.push({ name: art.name, collector: art.collector, bytes: 0, status: art.status, detail: art.detail });
          continue;
        }
        try {
          const { size } = await stat(art.filePath);
          if (size > MAX_ARTIFACT_BYTES) {
            entries.push({ name: art.name, collector: art.collector, bytes: 0, status: "failed", detail: `artifact is ${size} bytes, over the limit` });
            continue;
          }
          if (uploadedBytes + size > MAX_CAPTURE_BYTES) {
            entries.push({ name: art.name, collector: art.collector, bytes: 0, status: "failed", detail: "the package reached its size limit before this artifact" });
            continue;
          }
          const sha256 = await hash(art.filePath);
          await deps.upload({ captureId, name: art.name, filePath: art.filePath, bytes: size });
          uploadedBytes += size;
          entries.push({ name: art.name, collector: art.collector, bytes: size, sha256, status: "ok" });
        } catch (err: any) {
          // Subir es donde más cosas pueden salir mal (red, SAS caducado,
          // permiso). Se cuenta como artefacto fallido, no como captura rota:
          // los demás siguen.
          entries.push({ name: art.name, collector: art.collector, bytes: 0, status: "failed", detail: `upload: ${String(err?.message ?? err).slice(0, 250)}` });
        }
      }
    }
  } catch (err: any) {
    deps.logger?.warn?.("[evidence] captura fallida", { captureId, error: err?.message });
    entries.push({ name: "capture.failed", collector: "agent_self", bytes: 0, status: "failed", detail: String(err?.message ?? err).slice(0, 300) });
  } finally {
    // Pase lo que pase: no se deja una copia de los registros del cliente en su
    // propio disco.
    if (workDir) await rm(workDir).catch(() => {});
  }

  deps.enqueue({
    schemaVersion: FACTS_SCHEMA_VERSION,
    namespaces: {
      [EVIDENCE_FACTS_NAMESPACE]: {
        captureId,
        capturedAtUtc: capturedAt.toISOString(),
        utcOffsetMinutes: utcOffsetMinutes(capturedAt),
        timeZone: deviceTimeZone(),
        artifacts: entries,
      },
    },
  });

  const ok = entries.filter((e) => e.status === "ok").length;
  const failed = entries.filter((e) => e.status === "failed").length;
  return {
    status: ok > 0 ? 0 : 2,
    message: `evidence_capture ${ok > 0 ? (failed ? "partial" : "complete") : "failed"};collected=${ok};failed=${failed}`,
  };
}
