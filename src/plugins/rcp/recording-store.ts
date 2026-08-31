// src/plugins/rcp/recording-store.ts
//
// Búfer LOCAL de grabaciones de pantalla (ADR-0012, decisión 2).
//
// La grabación se origina en el agente y se sube DESPUÉS de la sesión, para no
// quitarle ancho de banda a la persona a la que se está dando soporte. Eso
// crea un problema que el ADR nombra explícitamente y que este módulo existe
// para resolver:
//
//   **Queda vídeo de la pantalla de alguien en su propio disco.**
//
// De ahí las tres reglas de abajo. Ninguna es una optimización; cada una
// evita un daño concreto.
//
// ── 1. Cifrado en reposo, con una clave que este equipo NO conserva ──
//
//   Cada grabación se cifra con una clave aleatoria distinta (AES-256-GCM).
//   La clave se devuelve a quien llama para que viaje al control plane por el
//   canal mTLS ya autenticado, y NO se escribe nunca junto al vídeo.
//
//   O sea: el equipo que guarda el fichero no puede leerlo. Alguien que robe
//   el portátil —o el propio usuario curioseando en el directorio— encuentra
//   ruido. Es la única postura defendible cuando lo que hay en disco es la
//   pantalla de una persona grabada para auditarla.
//
//   El precio: si la clave no llega al backend, esa grabación es basura
//   irrecuperable. Es el lado correcto por el que fallar.
//
// ── 2. Se cifra POR REGISTRO, no el fichero entero ───────────────────
//
//   Una sesión puede cortarse a media escritura: el equipo se apaga, el
//   proceso muere, el disco se llena. Con un único flujo cifrado, un final
//   truncado se lleva por delante todo lo anterior. Por registro, lo que se
//   pierde es el último fotograma y el resto sigue siendo auditable — que es
//   justo lo que se quería tener.
//
// ── 3. Topes de disco, y uno de ellos NO es nuestro ──────────────────
//
//   Hay tope por sesión y tope total del búfer, los dos obvios. El tercero es
//   el que se olvida: **espacio libre del disco**. Un tope de 200 MB en un
//   portátil al que le quedan 80 MB libres sigue siendo dañino. Grabar para
//   auditar a alguien no puede dejarle el equipo inservible, así que se mira
//   cuánto queda de verdad, no solo cuánto llevamos escrito.
//
//   Al alcanzar cualquiera de los tres se DEJA de grabar y se registra el
//   hecho. Nunca se sigue grabando a costa del disco ajeno.

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { agentDataDir } from "../../bootstrap/paths";

/** Tope por sesión. Al alcanzarlo se corta la grabación, no la sesión. */
export const MAX_SESSION_BYTES = 200 * 1024 * 1024;

/** Tope del búfer entero, sumando grabaciones pendientes de subir. */
export const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;

/**
 * Suelo de espacio libre. Por debajo no se escribe NADA, aunque los otros dos
 * topes lo permitieran.
 */
export const MIN_FREE_DISK_BYTES = 2 * 1024 * 1024 * 1024;

/**
 * Cuánto sobrevive una grabación sin subir antes de borrarse.
 *
 * La subida puede no ocurrir NUNCA: el equipo se apaga para siempre, la
 * persona deja la organización, alguien reinstala. Sin caducidad, el búfer se
 * convierte en un archivo permanente de pantallas ajenas en equipos ajenos —
 * exactamente lo contrario de lo que pretende una retención de 3 meses en un
 * blob controlado.
 */
export const BUFFER_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export type StopReason =
  | "session_ended"
  | "session_cap"
  | "total_cap"
  | "disk_low"
  | "write_error";

export type RecordingResult = {
  /** Fichero cifrado, o null si no llegó a escribirse nada. */
  path: string | null;
  bytes: number;
  frames: number;
  /**
   * Clave de esta grabación, en base64. NO se persiste: quien llama tiene que
   * mandarla al control plane o la grabación queda ilegible para siempre.
   */
  keyBase64: string;
  /** Por qué se dejó de grabar. `session_ended` es el caso sano. */
  stopReason: StopReason;
  /**
   * true si la grabación NO cubre la sesión entera. La auditoría tiene que
   * poder distinguir "no se grabó", "se grabó entera" y "se grabó a medias":
   * las tres significan cosas distintas para quien revise el incidente.
   */
  truncated: boolean;
};

export function recordingsDir(): string {
  // Dentro del directorio de datos del agente: modo 700 y ya denegado por la
  // jaula de rutas de rcp.file, así que un operador no puede sacarlo por el
  // gestor de ficheros de la propia herramienta.
  return path.join(agentDataDir(), "recordings");
}

/** Espacio libre del volumen, o null si no se puede saber. */
export function freeDiskBytes(dir: string): number | null {
  try {
    const st: any = (fs as any).statfsSync?.(dir);
    if (!st) return null;
    // bavail: bloques disponibles para procesos SIN privilegio. Se usa este y
    // no `bfree` a propósito: en muchos sistemas de ficheros hay un porcentaje
    // reservado para root, y contarlo daría por libre un espacio que el agente
    // no debería tocar aunque corra como root.
    return Number(st.bsize) * Number(st.bavail);
  } catch {
    return null;
  }
}

/** Suma de lo que ocupan las grabaciones pendientes. */
export function bufferBytes(dir = recordingsDir()): number {
  let total = 0;
  try {
    for (const name of fs.readdirSync(dir)) {
      try {
        total += fs.statSync(path.join(dir, name)).size;
      } catch {
        /* desapareció entre el readdir y el stat */
      }
    }
  } catch {
    /* aún no existe el directorio */
  }
  return total;
}

/**
 * Borra grabaciones caducadas. Devuelve cuántas quitó.
 *
 * Se llama al arrancar una grabación nueva, que es cuando importa: el búfer
 * solo crece si nadie lo limpia, y no hay ningún otro momento natural.
 */
export function purgeExpired(now = Date.now(), dir = recordingsDir()): number {
  let removed = 0;
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  for (const name of names) {
    const file = path.join(dir, name);
    try {
      const st = fs.statSync(file);
      if (now - st.mtimeMs > BUFFER_TTL_MS) {
        fs.unlinkSync(file);
        removed++;
      }
    } catch {
      /* otro proceso se nos adelantó */
    }
  }
  return removed;
}

/** Decide si se puede empezar a grabar, y por qué no si no se puede. */
export function canStart(args: {
  freeBytes: number | null;
  bufferBytes: number;
}): { ok: true } | { ok: false; reason: StopReason } {
  // Un `null` en espacio libre —statfs no disponible— NO bloquea: dejaría la
  // función inservible en cualquier plataforma donde no podamos medirlo, y el
  // tope por sesión sigue acotando el daño.
  if (args.freeBytes !== null && args.freeBytes < MIN_FREE_DISK_BYTES) {
    return { ok: false, reason: "disk_low" };
  }
  if (args.bufferBytes >= MAX_TOTAL_BYTES) {
    return { ok: false, reason: "total_cap" };
  }
  return { ok: true };
}

/** Decide si cabe un fotograma más. */
export function canWriteMore(args: {
  sessionBytes: number;
  incomingBytes: number;
  freeBytes: number | null;
}): { ok: true } | { ok: false; reason: StopReason } {
  if (args.sessionBytes + args.incomingBytes > MAX_SESSION_BYTES) {
    return { ok: false, reason: "session_cap" };
  }
  if (
    args.freeBytes !== null &&
    args.freeBytes - args.incomingBytes < MIN_FREE_DISK_BYTES
  ) {
    return { ok: false, reason: "disk_low" };
  }
  return { ok: true };
}

export type FrameMeta = {
  /** Milisegundos desde el inicio de la grabación. */
  t: number;
  /** true = fotograma completo; false = solo la región (x,y,rw,rh). */
  full: boolean;
  x: number;
  y: number;
  rw: number;
  rh: number;
  /** Tamaño del escritorio, para que el reproductor dimensione el lienzo. */
  w: number;
  h: number;
};

/**
 * Serializa un registro cifrado.
 *
 * Formato, todo big-endian:
 *   u32 longitud de cabecera | cabecera JSON | u8 12 (IV) | IV | u16 16 (tag)
 *   | tag | u32 longitud de payload | payload cifrado
 *
 * La cabecera va EN CLARO a propósito: son marcas de tiempo y coordenadas, no
 * contenido de la pantalla, y tenerlas legibles permite recorrer y reparar un
 * fichero truncado sin la clave — que es justo lo que hará falta el día que
 * alguien tenga que recuperar una grabación a medias.
 */
export function encodeRecord(
  meta: FrameMeta,
  payload: Buffer,
  key: Buffer
): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();

  const header = Buffer.from(JSON.stringify(meta), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32BE(header.length, 0);
  const plen = Buffer.alloc(4);
  plen.writeUInt32BE(enc.length, 0);

  return Buffer.concat([head, header, iv, tag, plen, enc]);
}

/** Descifra un registro. Lanza si el tag no cuadra — es lo que debe hacer. */
export function decodeRecord(
  buf: Buffer,
  offset: number,
  key: Buffer
): { meta: FrameMeta; payload: Buffer; next: number } {
  const headLen = buf.readUInt32BE(offset);
  let p = offset + 4;
  const meta = JSON.parse(buf.subarray(p, p + headLen).toString("utf8")) as FrameMeta;
  p += headLen;
  const iv = buf.subarray(p, p + 12);
  p += 12;
  const tag = buf.subarray(p, p + 16);
  p += 16;
  const plen = buf.readUInt32BE(p);
  p += 4;
  const enc = buf.subarray(p, p + plen);
  p += plen;

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const payload = Buffer.concat([decipher.update(enc), decipher.final()]);
  return { meta, payload, next: p };
}

export function newRecordingKey(): Buffer {
  return crypto.randomBytes(32);
}
