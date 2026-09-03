// privsvc/macos/src/anchor-pin.ts
//
// Fijación (pinning) de las ANCLAS DE CONFIANZA que instala el agente.
// ADR-0011, fase 0.
//
// ── Qué problema resuelve ────────────────────────────────────────────
//
// El agente instala en el trust store DEL SISTEMA los certificados
// autofirmados que vengan en `caBundlePem`, y ese bundle sale de la
// respuesta del servidor:
//
//   crypto-store.ts (renovación) → installCaCertificatesToSystemKeychain
//                                → security add-trusted-cert -r trustRoot
//
// Al enrolar es legítimo: hay que confiar en algo para arrancar. Lo que
// convierte esa decisión puntual en RECURRENTE es que la renovación
// —periódica, con material del control plane— repite la operación sin
// condición y sin recordar en qué confió la primera vez.
//
// Consecuencia medida: un control plane comprometido puede plantar un
// ancla arbitraria en cada endpoint por la ruta rutinaria de renovación,
// sin necesidad de ninguna capacidad de escritura nueva.
//
// ── Por qué OBSERVA y no BLOQUEA por defecto ─────────────────────────
//
// Hay una rotación de CA en curso. Un pin estricto desplegado en mitad
// de una rotación legítima rechazaría el ancla nueva, y un equipo que no
// confía en la CA nueva acaba sin poder conectar — sin conexión no hay
// forma de mandarle el arreglo, así que se convierte en una visita
// presencial. Es el mismo razonamiento que ya está escrito en
// `server-pin.ts` para el pin de conexión.
//
// Por eso el modo por defecto es `observe`: registra el ancla nueva,
// la reporta, y la instala igual. El operador enciende `enforce` cuando
// tiene el dato delante y la rotación ha asentado — que es exactamente
// la secuencia de la fase 1 de ADR-0009 (expediente sin gate primero).
//
// ⚠️ Observar tiene que ser RUIDOSO. La instalación del ancla está hoy
// envuelta en `.catch(() => undefined)` en las dos rutas, así que un
// fallo —o un ancla inesperada— no deja rastro. Un veredicto que nadie
// ve no existe.

import fs from "fs";
import path from "path";

export type AnchorPinMode = "observe" | "enforce";

export type AnchorPinVerdict = {
  /** Anclas en las que este equipo ya había confiado. */
  pinned: string[];
  /** Anclas autofirmadas que trae este bundle. */
  incoming: string[];
  /** Las de `incoming` que nadie había visto antes. */
  unpinned: string[];
  /** No había fichero de pines: esta ejecución establece la línea base. */
  firstRun: boolean;
  /** En `enforce`, las que NO deben instalarse. Vacío en `observe`. */
  rejected: string[];
};

/**
 * El núcleo, puro y sin sistema de ficheros.
 *
 * Separado a propósito: es la única lógica que hay que portar a la
 * PrivSvc de Windows (C#), y una función pura se porta leyéndola. El
 * resto —dónde se guarda el fichero, cómo se lee el keychain— es
 * específico de cada plataforma y no debe mezclarse aquí.
 */
export function evaluateAnchorPins(
  pinned: string[],
  incoming: string[],
  mode: AnchorPinMode
): AnchorPinVerdict {
  const known = new Set(pinned.map((p) => p.toLowerCase()));
  const firstRun = pinned.length === 0;

  // La PRIMERA vez no hay nada contra qué comparar, y tratar todo como
  // sospechoso convertiría cada enrolamiento en una alarma. La primera
  // ejecución establece la línea base; a partir de ahí sí significa algo.
  const unpinned = firstRun
    ? []
    : incoming.filter((fp) => !known.has(fp.toLowerCase()));

  return {
    pinned,
    incoming,
    unpinned,
    firstRun,
    rejected: mode === "enforce" ? unpinned : []
  };
}

/**
 * Fichero de pines. Vive junto a los certificados porque comparte su
 * ciclo de vida: si alguien borra el directorio para re-enrolar, los
 * pines se van con él, que es el comportamiento correcto.
 */
export function anchorPinPath(certDir: string): string {
  return path.join(certDir, "anchor-pins.json");
}

export function loadAnchorPins(certDir: string): string[] {
  try {
    const raw = fs.readFileSync(anchorPinPath(certDir), "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.anchors)) return [];
    return parsed.anchors.filter((a: unknown): a is string => typeof a === "string");
  } catch {
    // Ausente o ilegible = sin línea base. Devolver [] hace que
    // `firstRun` sea true y que NO se acuse a nadie, que es el fallo
    // seguro: un fichero corrupto no puede convertirse en una alarma
    // para toda la flota.
    return [];
  }
}

/**
 * Guarda la UNIÓN de lo ya fijado y lo aceptado.
 *
 * Unión y no reemplazo: durante una rotación conviven la CA vieja y la
 * nueva, y olvidar la vieja haría que el siguiente escaneo la viera como
 * desconocida. Un pin que se reescribe entero cada vez no es un pin.
 */
export function saveAnchorPins(certDir: string, anchors: string[]): void {
  const merged = Array.from(new Set(anchors.map((a) => a.toLowerCase()))).sort();
  const tmp = `${anchorPinPath(certDir)}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, anchors: merged }, null, 2), {
    encoding: "utf8",
    mode: 0o600
  });
  fs.renameSync(tmp, anchorPinPath(certDir));
}

// ── La observación tiene que SALIR del equipo (ADR-0011 fase 0, paso 1) ──
//
// Medido 2026-09-03: el modo `observe` observaba hacia un log local. El
// backend no tenía una sola referencia a esto y agent-core no leía el
// veredicto. Un modo cuyo único propósito es generar la evidencia para
// decidir, y que no la entrega, es el mismo fallo de `purge_after`.
//
// ⚠️ Por qué un FICHERO y no la respuesta IPC: el veredicto se produce
// en enrolamiento y renovación, que son raros —la renovación se dispara
// por umbral de caducidad, no por reloj—. Si solo viajara en la
// respuesta de esas llamadas, un equipo que no renueva en meses no
// reportaría nada, y «no reporta» es indistinguible de «no ha visto
// nada». Persistirlo lo convierte en estado consultable en cualquier
// momento por el ciclo de facts.

export type AnchorPinState = {
  version: 1;
  /** Cuándo se produjo el último veredicto. */
  at: string;
  mode: AnchorPinMode;
  /** Qué ruta lo produjo: distingue la línea base de una repetición. */
  source: "enroll" | "renew";
  incoming: string[];
  unpinned: string[];
  rejected: string[];
  firstRun: boolean;
  /**
   * Cuántas veces se ha visto ALGUNA ancla no fijada, desde siempre.
   *
   * Solo crece. El resto del fichero es el último veredicto y se
   * sobrescribe, así que dos eventos entre dos ciclos de facts dejarían
   * ver solo el segundo. Este contador sobrevive a eso: aunque se pierda
   * el detalle, queda la prueba de que ocurrió — que es justo lo que el
   * criterio de salida del paso 2 necesita («cero anclas no fijadas»).
   */
  unpinnedSeenTotal: number;
};

export function anchorStatePath(certDir: string): string {
  return path.join(certDir, "anchor-pin-last.json");
}

export function loadAnchorState(certDir: string): AnchorPinState | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(anchorStatePath(certDir), "utf8"));
    if (parsed?.version !== 1) return null;
    return parsed as AnchorPinState;
  } catch {
    // Igual que los pines: ausente o ilegible no puede convertirse en
    // una alarma. `null` significa «este equipo no ha reportado», que es
    // distinto de «no ha visto nada» y así se dirá arriba.
    return null;
  }
}

export function saveAnchorState(
  certDir: string,
  verdict: AnchorPinVerdict,
  mode: AnchorPinMode,
  source: "enroll" | "renew"
): void {
  const previo = loadAnchorState(certDir);
  const state: AnchorPinState = {
    version: 1,
    at: new Date().toISOString(),
    mode,
    source,
    incoming: verdict.incoming,
    unpinned: verdict.unpinned,
    rejected: verdict.rejected,
    firstRun: verdict.firstRun,
    unpinnedSeenTotal:
      (previo?.unpinnedSeenTotal ?? 0) + (verdict.unpinned.length > 0 ? 1 : 0)
  };
  const tmp = `${anchorStatePath(certDir)}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { encoding: "utf8", mode: 0o600 });
  fs.renameSync(tmp, anchorStatePath(certDir));
}

/** Texto para el log. Se separa para que el mensaje sea probable. */
export function describeAnchorVerdict(v: AnchorPinVerdict): string {
  if (v.firstRun) {
    return `anchor-pin: linea base establecida con ${v.incoming.length} ancla(s)`;
  }
  if (v.unpinned.length === 0) {
    return `anchor-pin: ${v.incoming.length} ancla(s), todas ya fijadas`;
  }
  const verb = v.rejected.length > 0 ? "RECHAZADA(S)" : "ACEPTADA(S) en modo observe";
  return (
    `anchor-pin: ATENCION — ${v.unpinned.length} ancla(s) NO fijada(s) ${verb}: ` +
    v.unpinned.join(", ")
  );
}
