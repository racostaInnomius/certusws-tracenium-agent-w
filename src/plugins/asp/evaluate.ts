// src/plugins/asp/evaluate.ts
//
// ADR-0022 decisión 3 — el agente EVALÚA EN LOCAL. Lo que devuelve el colector
// .ps1 (recuentos, DN acotados, atributos, valores de registro) entra aquí y
// sale un veredicto por indicador con una evidencia acotada. Lo único que viaja
// al backend es lo que sale de `evaluateIndicator`; ningún objeto de AD entero.
//
// Puro: sin IPC, sin disco, sin reloj salvo el que se inyecta. Las reglas de la
// fase 0 del ADR que viven aquí:
//   · 0x8007200A (ERROR_DS_NO_ATTRIBUTE_OR_VALUE) o acceso denegado en un
//     indicador `requires: privileged` = `not_assessed` con motivo, NUNCA error
//     del colector (ensuciaría la cobertura) y nunca pass.
//   · Un valor de registro ausente es el valor por defecto que el catálogo
//     declara para ese SO — un veredicto, no un vacío.
//   · Una sonda de registro en un colector que no es DC es `not_assessed`.

import { evaluatePredicate, type Predicate } from "./predicate";

export type AspVerdict = "pass" | "fail" | "not_assessed" | "needs_review" | "not_applicable";
export type AspSeverity = "critical" | "high" | "medium" | "low" | "info";

export type AgentIndicator = {
  controlId: string;
  severity: AspSeverity;
  requires: "member" | "dc_registry" | "privileged";
  query: { kind: string; [k: string]: unknown };
  derive: Array<{ as: string; op: string; from: string }>;
  predicate: Predicate;
  onFail: "fail" | "needs_review";
  whenMissing: "not_assessed" | "not_applicable";
};

export type CollectorQueryResult =
  | { ok: true; data: any; ms?: number }
  | { ok: false; error: { hresult?: string | null; type?: string; message?: string } | null; ms?: number };

export type CollectorInfo = {
  isDomainController?: boolean;
  osBuild?: number;
  dnsDomain?: string;
  host?: string;
} | null;

export type AspResult = {
  controlId: string;
  status: AspVerdict;
  severity: AspSeverity;
  affectedCount: number | null;
  evidence: unknown;
  reason: string | null;
};

/** HRESULT que significan «la cuenta de máquina no puede leer esto». */
const PRIVILEGE_HRESULTS = new Set([
  "0x8007200A", // ERROR_DS_NO_ATTRIBUTE_OR_VALUE — medido en PSO como SYSTEM (§Fase 0)
  "0x80070005", // E_ACCESSDENIED
  "0x80072098" // ERROR_DS_INSUFF_ACCESS_RIGHTS
]);

const FILETIME_EPOCH_OFFSET_MS = 11644473600000;
const FILETIME_NEVER = "9223372036854775807";

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^-?\d+$/.test(v.trim())) return Number(v.trim());
  return null;
}

function getPath(root: any, path: string): unknown {
  let node = root;
  for (const part of path.split(".")) {
    if (node === null || typeof node !== "object" || !Object.prototype.hasOwnProperty.call(node, part)) return undefined;
    node = node[part];
  }
  return node;
}

/** Días transcurridos desde un FILETIME de AD. null para 0 o «nunca». */
export function fileTimeAgeDays(raw: unknown, nowMs: number): number | null {
  if (raw === null || raw === undefined) return null;
  const s = String(raw).trim();
  if (!/^\d+$/.test(s) || s === "0" || s === FILETIME_NEVER) return null;
  // BigInt: un FILETIME real (~1,3e17) no cabe exacto en un double, y el
  // colector lo manda como texto precisamente por eso.
  const ms = Number(BigInt(s) / 10000n) - FILETIME_EPOCH_OFFSET_MS;
  if (!Number.isFinite(ms) || ms <= 0) return null;
  return Math.max(0, Math.floor((nowMs - ms) / 86_400_000));
}

/** El valor de ausencia de una sonda de registro para el build del colector. */
export function absentValueFor(query: Record<string, any>, osBuild: number | null | undefined): unknown {
  if (Array.isArray(query.absentValueByOsBuild)) {
    const build = typeof osBuild === "number" ? osBuild : 0;
    const match = [...query.absentValueByOsBuild]
      .filter((b: any) => Number.isFinite(b?.minBuild))
      .sort((a: any, b: any) => b.minBuild - a.minBuild)
      .find((b: any) => build >= b.minBuild);
    if (match) return match.value;
  }
  return query.absentValue;
}

function boundList(list: unknown, limit: number): { list: unknown[]; truncated: boolean } {
  if (!Array.isArray(list)) return { list: [], truncated: false };
  return { list: list.slice(0, limit), truncated: list.length > limit };
}

/**
 * Construye la evidencia que ve el predicado Y la que viaja. Es la misma: el
 * backend recibe exactamente lo que decidió el veredicto, acotado.
 */
export function buildEvidence(
  indicator: AgentIndicator,
  data: any,
  opts: { evidenceLimit: number; osBuild: number | null | undefined; nowMs: number }
): Record<string, unknown> {
  const q = indicator.query as Record<string, any>;
  const ev: Record<string, unknown> = {};

  switch (q.kind) {
    case "registry": {
      const present = data?.present === true;
      ev.present = present;
      ev.value = present ? data.value : absentValueFor(q, opts.osBuild);
      if (!present) ev.absent = true;
      break;
    }
    case "ldap_object":
    case "rootdse": {
      if (data?.found === false) {
        ev.found = false;
        break;
      }
      ev.found = true;
      const attrs: Record<string, unknown> = { ...(data?.attributes ?? {}) };
      if (q.defaults && typeof q.defaults === "object") {
        for (const [k, v] of Object.entries(q.defaults)) {
          if (!Object.prototype.hasOwnProperty.call(attrs, k)) attrs[k] = v;
        }
      }
      ev.attributes = attrs;
      break;
    }
    default: {
      // ldap_search / group_members / acl / sysvol_files: recuento + muestra.
      if (data?.found === false) {
        ev.found = false;
        break;
      }
      if (typeof data?.count === "number") ev.count = data.count;
      const { list, truncated } = boundList(data?.sample, opts.evidenceLimit);
      ev.sample = list;
      if (truncated || data?.truncated === true) ev.truncated = true;
      if (typeof data?.filesScanned === "number") ev.filesScanned = data.filesScanned;
    }
  }

  for (const d of indicator.derive ?? []) {
    if (d.op === "fileTimeAgeDays") {
      const age = fileTimeAgeDays(getPath(ev, d.from), opts.nowMs);
      // Una ausencia se queda ausente: el predicado la ve como evidencia que
      // falta, no como «0 días».
      if (age !== null) ev[d.as] = age;
    }
  }
  return ev;
}

export function evaluateIndicator(
  indicator: AgentIndicator,
  raw: CollectorQueryResult | undefined,
  collector: CollectorInfo,
  opts: { evidenceLimit: number; nowMs: number }
): AspResult {
  const base = { controlId: indicator.controlId, severity: indicator.severity };

  if (indicator.requires === "dc_registry" && collector?.isDomainController !== true) {
    return { ...base, status: "not_assessed", affectedCount: null, evidence: null, reason: "requires_dc_registry" };
  }
  if (!raw) {
    return { ...base, status: "not_assessed", affectedCount: null, evidence: null, reason: "collector_no_result" };
  }
  if (raw.ok !== true) {
    const hr = String(raw.error?.hresult ?? "").toUpperCase().replace(/^0X/, "0x");
    if (raw.error?.type === "budget_exceeded") {
      return { ...base, status: "not_assessed", affectedCount: null, evidence: null, reason: "budget_exceeded" };
    }
    if (PRIVILEGE_HRESULTS.has(hr)) {
      // §Fase 0, hallazgo 2: por CÓDIGO, no por texto. Si el indicador no
      // declaró `privileged` y aun así no se pudo leer, se dice tal cual.
      const reason = indicator.requires === "privileged" ? `requires_privileged_read:${hr}` : `insufficient_rights:${hr}`;
      return { ...base, status: "not_assessed", affectedCount: null, evidence: null, reason };
    }
    // 0x80131501 es el código de cualquier error de PowerShell: sin el texto
    // no se puede saber qué falló (primera corrida real, 14-sep).
    const message = typeof raw.error?.message === "string" ? raw.error.message.slice(0, 300) : null;
    const type = typeof raw.error?.type === "string" ? raw.error.type.slice(0, 100) : null;
    return {
      ...base,
      status: "not_assessed",
      affectedCount: null,
      evidence: message || type ? { collectorError: { hresult: hr || null, type, message } } : null,
      reason: `collector_error:${hr || raw.error?.type || "unknown"}`
    };
  }

  const evidence = buildEvidence(indicator, raw.data, { evidenceLimit: opts.evidenceLimit, osBuild: collector?.osBuild, nowMs: opts.nowMs });
  const affectedCount = typeof evidence.count === "number" ? (evidence.count as number) : null;
  const outcome = evaluatePredicate(indicator.predicate, evidence);

  if (outcome.outcome === "true") {
    return { ...base, status: "pass", affectedCount, evidence, reason: null };
  }
  if (outcome.outcome === "false") {
    return { ...base, status: indicator.onFail === "needs_review" ? "needs_review" : "fail", affectedCount, evidence, reason: null };
  }
  if (indicator.whenMissing === "not_applicable") {
    return { ...base, status: "not_applicable", affectedCount, evidence, reason: `not_present:${outcome.path}` };
  }
  return { ...base, status: "not_assessed", affectedCount, evidence, reason: `missing_evidence:${outcome.path}` };
}
