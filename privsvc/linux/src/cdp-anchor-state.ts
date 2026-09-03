// privsvc/linux/src/cdp-anchor-state.ts
//
// ADR-0011 fase 0, paso 1 — en Linux la respuesta es «no aplica», y hay
// que decirlo en vez de callarse.
//
// ── Por qué aquí no hay pin que reportar ────────────────────────────
//
// El gate 1 se verificó en un Ubuntu real: en Linux el agente **no
// instala nada en el trust store del sistema**. `update-ca-trust` /
// `update-ca-certificates` no se llaman a propósito (ver la cabecera de
// `crypto-store.ts`), así que el bundle es privado del cliente gRPC de
// Tracenium. Lo peor que puede hacer un control plane comprometido por
// esa vía es cambiar en qué confía el agente para hablar con él mismo,
// que es algo que ya controla. No hay ancla del sistema que plantar y
// por tanto no hay nada que fijar.
//
// ── Por qué el método existe igualmente ─────────────────────────────
//
// Si Linux simplemente no respondiera, el control plane no podría
// distinguir «esta plataforma no lo necesita» de «este equipo no
// reporta» — y esa segunda lectura es justo la que haría creer que hay
// un hueco de cobertura donde hay una decisión de diseño. `applicable:
// false` con su motivo es la diferencia entre un dato y un silencio.

import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { success } from "./protocol";

export async function handleCdpAnchorState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  return success(req.id, {
    applicable: false,
    platform: "linux",
    reason:
      "el agente no escribe en el trust store del sistema en Linux " +
      "(update-ca-trust/update-ca-certificates no se llaman a proposito); " +
      "no hay ancla que fijar — ADR-0011 gate 1",
    mode: null,
    pinnedCount: 0,
    pinned: [],
    last: null
  });
}
