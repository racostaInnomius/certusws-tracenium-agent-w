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
