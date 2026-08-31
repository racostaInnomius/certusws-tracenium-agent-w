// src/plugins/rcp/recording-handoff.ts
//
// Entrega de la clave y ciclo de vida del fichero grabado (ADR-0012).
//
// ── La invariante que gobierna todo este módulo ──────────────────────
//
//   La clave de una grabación NUNCA se escribe en el endpoint. Vive en memoria
//   mientras dura el proceso y viaja al control plane por el mTLS que ya
//   existe. De ahí se sigue algo incómodo y correcto:
//
//     **Un .trec que sobrevive a un reinicio del agente sin que su clave haya
//     llegado es basura indescifrable, para siempre, por nadie.**
//
//   Así que al arrancar hay que barrer esos ficheros. Y para poder distinguir
//   "su clave ya está en el control plane" de "su clave se perdió con el
//   proceso anterior", cada grabación confirmada deja una marca al lado.
//
//   La marca NO contiene la clave ni nada sensible: solo dice que la otra
//   mitad está a salvo en el servidor. Es un dato de estado, no un secreto.
//
// ── Por qué se borra en vez de guardar por si acaso ──────────────────
//
//   Un fichero que nadie puede descifrar no es una grabación: es vídeo de la
//   pantalla de una persona ocupando su disco sin aportar nada a nadie. Y a
//   diferencia de casi todo lo demás, aquí "guardarlo por si acaso" no tiene
//   un caso — no hay ningún futuro en el que esa clave reaparezca.

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { recordingsDir } from "./recording-store";

/** Sufijo de la marca "la clave ya está en el control plane". */
export const CONFIRMED_SUFFIX = ".ok";

export type PendingRecording = {
  sessionId: string;
  file: string;
  bytes: number;
  frames: number;
  keyBase64: string;
  sha256: string;
  truncated: boolean;
  stopReason: string;
};

/** Marca que acompaña a un fichero cuya clave ya se entregó. */
export function confirmedMarkerPath(recordingFile: string): string {
  return recordingFile + CONFIRMED_SUFFIX;
}

/**
 * Deja constancia de que el control plane ya tiene la clave.
 *
 * Sin secreto dentro: quien lea la marca no obtiene nada útil, y sin ella el
 * barrido de arranque borraría un fichero perfectamente recuperable.
 */
export function writeConfirmedMarker(
  recordingFile: string,
  info: { sessionId: string; atUtc?: string }
): void {
  try {
    fs.writeFileSync(
      confirmedMarkerPath(recordingFile),
      JSON.stringify({
        sessionId: info.sessionId,
        keyDeliveredAtUtc: info.atUtc ?? new Date().toISOString()
      }),
      { mode: 0o600 }
    );
  } catch {
    // Si no se puede escribir la marca, el barrido de arranque se llevará el
    // fichero. Se pierde una grabación; no se filtra nada ni se rompe nada.
  }
}

export function isConfirmed(recordingFile: string): boolean {
  try {
    return fs.existsSync(confirmedMarkerPath(recordingFile));
  } catch {
    return false;
  }
}

/** Retira un fichero y su marca. Idempotente, nunca lanza. */
export function removeRecording(recordingFile: string): void {
  for (const f of [recordingFile, confirmedMarkerPath(recordingFile)]) {
    try {
      fs.unlinkSync(f);
    } catch {
      /* puede no existir */
    }
  }
}

/**
 * Barrido de arranque: borra las grabaciones cuya clave se perdió.
 *
 * Se llama UNA vez al iniciar el agente. Cualquier .trec sin marca viene de un
 * proceso anterior que murió antes de entregar la clave, así que ya no lo
 * puede leer nadie.
 *
 * Devuelve cuántas retiró, para que quede en el log: un número alto significa
 * que el agente está muriendo a mitad de sesión repetidamente, y eso es un
 * problema distinto que conviene ver.
 */
export function purgeUnconfirmed(dir = recordingsDir()): number {
  let removed = 0;
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }

  for (const name of names) {
    if (!name.endsWith(".trec")) continue;
    const file = path.join(dir, name);
    if (isConfirmed(file)) continue;
    removeRecording(file);
    removed++;
  }

  // Marcas huérfanas: su fichero ya se subió y se borró, o desapareció. No
  // hacen daño, pero acumularlas convierte el directorio en un cementerio.
  for (const name of names) {
    if (!name.endsWith(CONFIRMED_SUFFIX)) continue;
    const marker = path.join(dir, name);
    const recording = marker.slice(0, -CONFIRMED_SUFFIX.length);
    if (fs.existsSync(recording)) continue;
    try {
      fs.unlinkSync(marker);
    } catch {
      /* da igual */
    }
  }

  return removed;
}

/**
 * SHA-256 del fichero cifrado, en hex.
 *
 * Va en el mensaje de entrega para que el backend pueda comprobar que lo que
 * llegó al blob es lo que el agente dijo haber grabado. Sin esto, una subida
 * truncada o alterada produciría una grabación de auditoría en la que nadie
 * puede confiar — y una prueba en la que no se puede confiar es peor que no
 * tener prueba, porque parece que la hay.
 */
export function fileSha256(file: string): string {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(file));
  return hash.digest("hex");
}

/** Lista las grabaciones confirmadas que siguen pendientes de subir. */
export function pendingUploads(dir = recordingsDir()): string[] {
  try {
    return fs
      .readdirSync(dir)
      .filter((n) => n.endsWith(".trec"))
      .map((n) => path.join(dir, n))
      .filter((f) => isConfirmed(f));
  } catch {
    return [];
  }
}
