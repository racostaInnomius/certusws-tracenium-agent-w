// src/core/reset-baseline.ts
//
// Qué líneas base AMP limpia un job `reset_baseline`.
//
// 🔴 ANTES LIMPIABA LAS TRES SIEMPRE (software + impresoras + extensiones),
// aunque el control plane sólo necesitara una. El 14-sep, 34 resets del
// autorreparador de EXTENSIONES hicieron reenviar también el software completo
// de 34 equipos de T111, y el backend de entonces reinició la «primera
// detección» de cada app. El backend ya conserva esa fecha para el software,
// pero impresoras y extensiones siguen reescribiéndose con cada foto completa,
// y reenviar 300 apps para reparar una tabla de extensiones es ruido igual.
//
// Contrato del payload: `{ namespace: "amp", scopes?: AmpBaselineScope[] }`.
//   · sin `scopes` → las tres, como siempre (backends anteriores);
//   · con `scopes` → SÓLO esas.
//
// ⚠️ Un `scopes` presente pero vacío o con un nombre desconocido se RECHAZA, no
// se interpreta como «todas» ni como «ninguna»: un backend más nuevo que pida un
// alcance que este agente no conoce tiene que ver un error reconocible en el job,
// no un éxito que no hizo lo que pidió — ni un borrado de más.

export const AMP_BASELINE_SCOPES = ["software", "printers", "browserExtensions"] as const;
export type AmpBaselineScope = (typeof AMP_BASELINE_SCOPES)[number];

export type ResetBaselinePlan =
  | { ok: true; namespace: "amp"; scopes: AmpBaselineScope[] }
  | { ok: false; message: string };

export function planResetBaseline(payload: any): ResetBaselinePlan {
  const namespace = String(payload?.namespace || "").trim().toLowerCase();
  if (namespace !== "amp") {
    // Sólo "amp" tiene protocolo de deltas hoy.
    return { ok: false, message: `reset_baseline rejected: unsupported namespace "${namespace}"` };
  }

  const raw = payload?.scopes;
  if (raw === undefined || raw === null) {
    return { ok: true, namespace, scopes: [...AMP_BASELINE_SCOPES] };
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    return { ok: false, message: "reset_baseline rejected: scopes must be a non-empty array" };
  }
  const unknown = raw.filter((s) => !(AMP_BASELINE_SCOPES as readonly unknown[]).includes(s));
  if (unknown.length > 0) {
    return {
      ok: false,
      message: `reset_baseline rejected: unsupported scopes ${unknown.map((s) => JSON.stringify(s)).join(", ")}`,
    };
  }
  // Orden canónico y sin repetidos: el mensaje del job sale igual pida como pida.
  return { ok: true, namespace, scopes: AMP_BASELINE_SCOPES.filter((s) => raw.includes(s)) };
}
