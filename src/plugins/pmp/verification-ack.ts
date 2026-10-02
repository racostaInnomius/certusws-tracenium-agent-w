// src/plugins/pmp/verification-ack.ts
//
// El resultado de patch_verify viaja en el ACK como
//   patch_verify:<passed|failed|no_baseline>;result=<b64url(JSON)>
// — el mismo formato que el lote de remediaciones (`items=`), que el backend
// ya sabe separar por `;`/`=`. Acotado: si no cabe, se recortan las listas y
// se dice.

import type { ServiceSnapshot, VerificationResult } from "./verification";
import type { ListenerObservation } from "./listeners";

const MAX_B64 = 200_000;

export function encodeVerificationAck(r: VerificationResult): string {
  let body: VerificationResult & { truncated?: true } = r;
  let b64 = Buffer.from(JSON.stringify(body)).toString("base64url");
  if (b64.length > MAX_B64) {
    body = {
      ...r,
      services: r.services.status === "compared" ? { ...r.services, regressions: r.services.regressions.slice(0, 50) } : r.services,
      checks: r.checks.slice(0, 25),
      truncated: true,
    };
    b64 = Buffer.from(JSON.stringify(body)).toString("base64url");
  }
  return `patch_verify:${r.status};result=${b64}`;
}

/**
 * F2 — `verify_discover:ok;result=<b64url(JSON)>`: lo que escucha el equipo y
 * sus servicios automáticos en marcha. Acotado igual que el veredicto.
 */
export function encodeDiscoverAck(d: { listeners: ListenerObservation; services: ServiceSnapshot }): string {
  let body: any = d;
  let b64 = Buffer.from(JSON.stringify(body)).toString("base64url");
  if (b64.length > MAX_B64) {
    body = {
      listeners: d.listeners.ok ? { ok: true, listeners: d.listeners.listeners.slice(0, 32) } : d.listeners,
      services: d.services.ok ? { ok: true, services: d.services.services.slice(0, 200) } : d.services,
      truncated: true,
    };
    b64 = Buffer.from(JSON.stringify(body)).toString("base64url");
  }
  return `verify_discover:ok;result=${b64}`;
}
