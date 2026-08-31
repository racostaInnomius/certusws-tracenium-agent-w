// src/plugins/rcp/recording-uploader.ts
//
// Subida DIFERIDA de las grabaciones (ADR-0012, decisión 2).
//
// ── Por qué diferida ────────────────────────────────────────────────
//
//   Grabar para auditar a alguien no puede costarle a esa persona el ancho de
//   banda justo mientras le estás dando soporte. Así que durante la sesión no
//   se sube nada: se escribe a disco y se sube DESPUÉS.
//
//   "Después" es literal: se espera a que la sesión haya terminado y un rato
//   más. El rato de más no es supersticion — un técnico que cierra una sesión
//   y abre otra en el mismo equipo es lo normal, y empezar a subir 80 MB en
//   ese hueco reproduce exactamente el problema que la subida diferida evita.
//
// ── Qué pasa si nunca se puede subir ────────────────────────────────
//
//   Pasa. El equipo se apaga, la persona se va de la organización, la red
//   corporativa bloquea el blob. El búfer tiene caducidad (ver
//   recording-store.ts) y aquí hay un número de intentos: una grabación que no
//   sube tras N intentos se borra en vez de quedarse reintentando para
//   siempre en el disco de alguien.
//
//   La auditoría del backend distingue "no se grabó" de "se grabó y no llegó"
//   porque la clave sí llegó en su momento: hay fila, y no hay blob. Esa
//   diferencia importa el día que alguien pregunte por una sesión concreta.
//
// ── Tras un reinicio ya no tenemos la clave ─────────────────────────
//
//   La clave nunca se persiste, así que al reiniciar no podemos volver a
//   mandarla. Pero el backend YA la tiene —eso es lo que dice la marca junto
//   al fichero—, así que se le pide un destino nuevo con la clave vacía. El
//   backend solo acepta esa petición si ya guarda una clave para esa sesión.

import fs from "fs";
import path from "path";
import https from "https";
import http from "http";
import { removeRecording } from "./recording-handoff";

/**
 * Cuánto se espera tras cerrar la sesión antes de empezar a subir.
 *
 * Dos minutos: bastante para que un técnico que encadena dos sesiones en el
 * mismo equipo no se encuentre la subida por medio, y poco para que la
 * grabación no se quede en el disco más de lo necesario.
 */
export const UPLOAD_DELAY_MS = 2 * 60 * 1000;

/**
 * Intentos antes de rendirse y borrar.
 *
 * Reintentar para siempre convierte un problema de red en vídeo de la pantalla
 * de alguien acumulándose indefinidamente en su equipo.
 */
export const MAX_ATTEMPTS = 5;

/** Espera antes del intento `attempt` (1-based), con techo. */
export function backoffMs(attempt: number): number {
  // 1 min, 4, 9, 16, 25 — cuadrático y con techo a media hora. Un fallo de red
  // corporativa dura minutos u horas, no segundos, así que reintentar cada
  // pocos segundos solo gasta batería y llena el log.
  const ms = attempt * attempt * 60_000;
  return Math.min(ms, 30 * 60_000);
}

/** ¿Merece la pena reintentar con este código HTTP? */
export function isRetryable(status: number): boolean {
  // 408 timeout, 429 rate limit y toda la familia 5xx son transitorios.
  if (status === 408 || status === 429) return true;
  if (status >= 500) return true;
  // 403 en un SAS suele ser "caducó": no se reintenta con ESTA url, pero
  // tampoco es permanente — el llamador pedirá un destino nuevo.
  return false;
}

/** ¿Un 403/404 significa que hay que pedir otra URL, no rendirse? */
export function needsFreshUrl(status: number): boolean {
  return status === 403 || status === 404;
}

export type UploadOutcome =
  | { ok: true }
  | { ok: false; retryable: boolean; freshUrl: boolean; detail: string };

/**
 * Sube el fichero a la URL con SAS, con PUT en bloque.
 *
 * `x-ms-blob-type: BlockBlob` es obligatorio en Azure Blob para un PUT
 * directo; sin esa cabecera devuelve 400 y el mensaje no dice cuál falta.
 */
export function putFile(
  urlString: string,
  file: string,
  timeoutMs = 10 * 60 * 1000
): Promise<UploadOutcome> {
  return new Promise((resolve) => {
    let size: number;
    try {
      size = fs.statSync(file).size;
    } catch (err: any) {
      resolve({ ok: false, retryable: false, freshUrl: false, detail: `stat: ${err?.message}` });
      return;
    }

    let url: URL;
    try {
      url = new URL(urlString);
    } catch {
      resolve({ ok: false, retryable: false, freshUrl: false, detail: "url inválida" });
      return;
    }

    const lib = url.protocol === "https:" ? https : http;
    const req = lib.request(
      url,
      {
        method: "PUT",
        headers: {
          "content-length": size,
          "content-type": "application/octet-stream",
          "x-ms-blob-type": "BlockBlob"
        },
        timeout: timeoutMs
      },
      (res) => {
        const status = res.statusCode ?? 0;
        res.resume(); // drenar, o el socket no se libera
        if (status >= 200 && status < 300) {
          resolve({ ok: true });
          return;
        }
        resolve({
          ok: false,
          retryable: isRetryable(status),
          freshUrl: needsFreshUrl(status),
          detail: `HTTP ${status}`
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, retryable: true, freshUrl: false, detail: "timeout" });
    });
    req.on("error", (err: any) => {
      // Fallo de red: transitorio por defecto. Rendirse a la primera
      // convertiría un corte de wifi en una grabación perdida.
      resolve({ ok: false, retryable: true, freshUrl: false, detail: err?.message || "error" });
    });

    const stream = fs.createReadStream(file);
    stream.on("error", (err: any) => {
      req.destroy();
      resolve({ ok: false, retryable: false, freshUrl: false, detail: `read: ${err?.message}` });
    });
    stream.pipe(req);
  });
}

export type UploaderDeps = {
  logger?: { info?: Function; warn?: Function };
  /** Pide al control plane un destino nuevo para esta sesión. */
  requestDestination: (sessionId: string) => void;
};

type QueueEntry = {
  sessionId: string;
  file: string;
  url: string | null;
  attempts: number;
  timer: NodeJS.Timeout | null;
};

/**
 * Cola de subidas pendientes.
 *
 * Vive en memoria; el estado duradero son los ficheros en disco con su marca.
 * Tras un reinicio se reconstruye desde ahí, que es lo correcto: la verdad
 * está en el disco, no en una estructura que se pierde con el proceso.
 */
export class RecordingUploader {
  private queue = new Map<string, QueueEntry>();

  constructor(private readonly deps: UploaderDeps) {}

  /** Encola una grabación cuyo destino ya conocemos. */
  enqueue(sessionId: string, file: string, url: string): void {
    const existing = this.queue.get(sessionId);
    if (existing?.timer) clearTimeout(existing.timer);

    const entry: QueueEntry = {
      sessionId,
      file,
      url,
      attempts: existing?.attempts ?? 0,
      timer: null
    };
    this.queue.set(sessionId, entry);
    this.schedule(entry, existing ? backoffMs(entry.attempts) : UPLOAD_DELAY_MS);
  }

  /**
   * Reconstruye la cola tras un reinicio.
   *
   * No se sube nada aquí: no tenemos URL —caducó con el proceso anterior— así
   * que se pide destino nuevo. El backend solo lo concede si ya tiene la clave
   * de esa sesión.
   */
  resume(files: string[]): void {
    for (const file of files) {
      const sessionId = path.basename(file).replace(/\.trec$/, "");
      if (this.queue.has(sessionId)) continue;
      this.queue.set(sessionId, { sessionId, file, url: null, attempts: 0, timer: null });
      this.deps.requestDestination(sessionId);
    }
  }

  /** El control plane rechazó la grabación: se retira del equipo. */
  reject(sessionId: string, reason: string): void {
    const entry = this.queue.get(sessionId);
    if (!entry) return;
    if (entry.timer) clearTimeout(entry.timer);
    this.queue.delete(sessionId);
    this.deps.logger?.info?.("[rcp.rec] grabación rechazada por el servidor; se retira", {
      sessionId,
      reason
    });
    removeRecording(entry.file);
  }

  /** Cancela los temporizadores. Para el cierre del agente. */
  stop(): void {
    for (const e of this.queue.values()) {
      if (e.timer) clearTimeout(e.timer);
    }
    this.queue.clear();
  }

  private schedule(entry: QueueEntry, delay: number): void {
    entry.timer = setTimeout(() => {
      void this.attempt(entry);
    }, delay);
    // No mantener vivo el proceso solo por una subida pendiente: si el agente
    // se está cerrando, la grabación espera al siguiente arranque.
    entry.timer.unref?.();
  }

  private async attempt(entry: QueueEntry): Promise<void> {
    entry.timer = null;
    if (!entry.url) return;

    if (!fs.existsSync(entry.file)) {
      // Se lo llevó la caducidad del búfer, o un barrido. Nada que subir.
      this.queue.delete(entry.sessionId);
      return;
    }

    entry.attempts += 1;
    const res = await putFile(entry.url, entry.file);

    if (res.ok) {
      this.deps.logger?.info?.("[rcp.rec] grabación subida", {
        sessionId: entry.sessionId,
        attempts: entry.attempts
      });
      this.queue.delete(entry.sessionId);
      removeRecording(entry.file);
      return;
    }

    this.deps.logger?.warn?.("[rcp.rec] fallo subiendo la grabación", {
      sessionId: entry.sessionId,
      attempts: entry.attempts,
      detail: res.detail
    });

    if (res.freshUrl) {
      // El SAS caducó. No cuenta como intento perdido: se pide otro destino.
      entry.url = null;
      this.deps.requestDestination(entry.sessionId);
      return;
    }

    if (!res.retryable || entry.attempts >= MAX_ATTEMPTS) {
      this.deps.logger?.warn?.(
        "[rcp.rec] se abandona la subida y se retira la grabación",
        { sessionId: entry.sessionId, attempts: entry.attempts, detail: res.detail }
      );
      this.queue.delete(entry.sessionId);
      removeRecording(entry.file);
      return;
    }

    this.schedule(entry, backoffMs(entry.attempts));
  }
}
