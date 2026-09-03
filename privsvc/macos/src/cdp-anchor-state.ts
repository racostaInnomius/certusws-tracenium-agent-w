// privsvc/macos/src/cdp-anchor-state.ts
//
// ADR-0011 fase 0, paso 1 — sacar la observación del equipo.
//
// ── Por qué existe este método ──────────────────────────────────────
//
// El modo `observe` del pin de anclas tiene UN propósito: generar la
// evidencia con la que decidir el paso a `enforce`. Medido el
// 2026-09-03, esa evidencia no salía del endpoint — el backend no tenía
// una sola referencia a anchor-pin y agent-core no leía el veredicto.
// Un mecanismo que funciona y no produce nada visible es el fallo que
// este repositorio ya conoce por `purge_after` y por los guards de la
// fase 1.
//
// ── Solo lectura, y aun así root ────────────────────────────────────
//
// No decide nada ni escribe nada. Pide root igual porque `CERT_DIR` es
// 0700 de root y porque el repo evita a propósito una superficie de
// privilegio parcial — el mismo argumento que ya cubre `cdp.*` entero
// en el router.
//
// ── Lo que NO se reporta ────────────────────────────────────────────
//
// Las huellas de las anclas fijadas van completas: son públicas por
// definición (un hash de un certificado que el equipo ya publica en
// cada handshake) y sin ellas no se puede distinguir «vio la CA nueva
// de la rotación» de «vio otra cosa», que es LA pregunta del paso 2.

import { CERT_DIR } from "./paths";
import { loadAnchorPins, loadAnchorState } from "./anchor-pin";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { success } from "./protocol";

export function anchorPinModeActual(): "observe" | "enforce" {
  return process.env.TRACENIUM_ANCHOR_PIN === "enforce" ? "enforce" : "observe";
}

export async function handleCdpAnchorState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const pinned = loadAnchorPins(CERT_DIR);
  const last = loadAnchorState(CERT_DIR);

  return success(req.id, {
    // `applicable` distingue las tres cosas que un panel confundiría:
    // «no aplica en esta plataforma» (Linux), «aplica y nunca ha
    // evaluado» (last: null) y «aplica y esto es lo que vio».
    applicable: true,
    platform: "macos",
    mode: anchorPinModeActual(),
    pinnedCount: pinned.length,
    pinned,
    last
  });
}
