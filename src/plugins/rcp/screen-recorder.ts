// src/plugins/rcp/screen-recorder.ts
//
// Grabación de sesiones de pantalla (ADR-0012, decisión 2).
//
// ── El ritmo: por qué NO es "1 fps" a secas ──────────────────────────
//
//   El ADR pide ritmo reducido, 1 fps, para no guardar 4,4 GB por hora. Ese
//   número era para fotogramas COMPLETOS. Con rects sucios —lo que Windows ya
//   produce— el ahorro sale de otro sitio: no se guarda lo que no cambió.
//
//   Y aquí está la trampa. Los rects son INTERDEPENDIENTES: cada uno se pinta
//   encima del estado anterior. Quedarse con uno de cada cinco no da "la misma
//   grabación más ligera", da una grabación CORRUPTA — los rects que
//   sobreviven se pintan sobre una base que nunca existió. Y es un fallo que
//   no se ve al grabar: se descubre meses después, al reproducir la sesión que
//   alguien necesitaba como prueba.
//
//   De ahí la regla:
//
//     * El primer fotograma SIEMPRE se graba, y siempre es completo (la
//       sesión lo fuerza). Es la base sobre la que se pinta todo lo demás.
//     * Los PARCIALES se graban TODOS. Tirar uno rompe la reconstrucción.
//       Salen baratos justamente porque son pequeños.
//     * Los COMPLETOS posteriores se limitan a uno por segundo. En Windows son
//       redundantes si tenemos todos los parciales, pero se conserva uno por
//       segundo porque acota el daño de un registro corrupto y da puntos por
//       donde saltar al reproducir. En macOS y Linux, donde los helpers SOLO
//       devuelven completos, esta es la regla que de verdad implementa el
//       "1 fps" del ADR.
//
//   O sea: el ritmo reducido se aplica donde es correcto aplicarlo, y no donde
//   rompería el resultado.

import fs from "fs";
import path from "path";
import {
  canStart,
  canWriteMore,
  encodeRecord,
  newRecordingKey,
  purgeExpired,
  recordingsDir,
  bufferBytes,
  freeDiskBytes,
  type FrameMeta,
  type RecordingResult,
  type StopReason
} from "./recording-store";

/** Un fotograma completo por segundo como máximo. Ver la nota de arriba. */
const KEYFRAME_MIN_INTERVAL_MS = 1000;

/**
 * Cada cuántos fotogramas se vuelve a mirar el espacio libre del disco.
 *
 * Un statfs por fotograma serían cinco por segundo durante toda la sesión, en
 * el equipo de alguien que además está compartiendo pantalla. Cada 20 —unos
 * cuatro segundos— es de sobra: entre dos comprobaciones caben como mucho unos
 * megabytes nuestros, y el suelo de 2 GB absorbe eso con holgura.
 */
const DISK_CHECK_EVERY = 20;

export type RecorderLogger = {
  info?: (msg: string, meta?: any) => void;
  warn?: (msg: string, meta?: any) => void;
};

export class ScreenRecorder {
  private key: Buffer | null = null;
  private file: string | null = null;
  private fd: number | null = null;
  private bytes = 0;
  private frames = 0;
  private framesSinceDiskCheck = 0;
  private lastFreeBytes: number | null = null;
  private startedAt = 0;
  private lastKeyframeAt = 0;
  private stopped: StopReason | null = null;
  private wroteAnything = false;

  constructor(
    private readonly sessionId: string,
    private readonly logger?: RecorderLogger,
    private readonly dir: string = recordingsDir()
  ) {}

  /** ¿Está grabando ahora mismo? */
  get active(): boolean {
    return this.fd !== null && this.stopped === null;
  }

  /**
   * Abre la grabación. Devuelve false si no se puede empezar — y eso NO es un
   * error de la sesión: se sigue dando soporte, simplemente sin grabar, y
   * queda registrado el motivo.
   */
  start(): boolean {
    try {
      fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    } catch {
      /* puede existir ya */
    }

    // Limpiar caducadas ANTES de medir el búfer: si no, una grabación vieja
    // que ya no vale para nada podría impedir que empiece una que sí importa.
    const purged = purgeExpired(Date.now(), this.dir);
    if (purged > 0) {
      this.logger?.info?.("[rcp.rec] grabaciones caducadas retiradas", { purged });
    }

    this.lastFreeBytes = freeDiskBytes(this.dir);
    const gate = canStart({
      freeBytes: this.lastFreeBytes,
      bufferBytes: bufferBytes(this.dir)
    });
    if (!gate.ok) {
      this.stopped = gate.reason;
      this.logger?.warn?.("[rcp.rec] no se graba esta sesión", {
        sessionId: this.sessionId,
        reason: gate.reason
      });
      return false;
    }

    this.key = newRecordingKey();
    this.startedAt = Date.now();
    // El nombre lleva el sessionId para poder emparejarlo con la auditoría sin
    // abrir el fichero (que además está cifrado).
    this.file = path.join(this.dir, `${this.sessionId}.trec`);

    try {
      this.fd = fs.openSync(this.file, "w", 0o600);
    } catch (err: any) {
      this.stopped = "write_error";
      this.logger?.warn?.("[rcp.rec] no se pudo abrir el fichero de grabación", {
        sessionId: this.sessionId,
        err: err?.message
      });
      return false;
    }

    return true;
  }

  /**
   * Ofrece un fotograma. Decide solo si le toca guardarlo.
   *
   * Nunca lanza: corre dentro del bucle de captura y un fallo grabando no
   * puede tumbar la sesión de soporte que está grabando.
   */
  offer(frame: {
    payload: Buffer;
    full: boolean;
    x: number;
    y: number;
    rw: number;
    rh: number;
    w: number;
    h: number;
  }): void {
    if (!this.active || !this.key || this.fd === null) return;

    const now = Date.now();

    // Limitar SOLO los completos, y solo después del primero. Ver la nota de
    // cabecera: tirar un parcial rompe la reconstrucción.
    if (frame.full && this.wroteAnything) {
      if (now - this.lastKeyframeAt < KEYFRAME_MIN_INTERVAL_MS) return;
    }

    if (this.framesSinceDiskCheck >= DISK_CHECK_EVERY) {
      this.lastFreeBytes = freeDiskBytes(this.dir);
      this.framesSinceDiskCheck = 0;
    }

    const gate = canWriteMore({
      sessionBytes: this.bytes,
      incomingBytes: frame.payload.length,
      freeBytes: this.lastFreeBytes
    });
    if (!gate.ok) {
      // Se DEJA de grabar; la sesión sigue. Nunca se sigue grabando a costa
      // del disco de otra persona.
      this.finishWith(gate.reason);
      return;
    }

    const meta: FrameMeta = {
      t: now - this.startedAt,
      full: frame.full,
      x: frame.x,
      y: frame.y,
      rw: frame.rw,
      rh: frame.rh,
      w: frame.w,
      h: frame.h
    };

    try {
      const rec = encodeRecord(meta, frame.payload, this.key);
      fs.writeSync(this.fd, rec);
      this.bytes += rec.length;
      this.frames += 1;
      this.framesSinceDiskCheck += 1;
      this.wroteAnything = true;
      if (frame.full) this.lastKeyframeAt = now;
    } catch (err: any) {
      this.logger?.warn?.("[rcp.rec] fallo escribiendo la grabación", {
        sessionId: this.sessionId,
        err: err?.message
      });
      this.finishWith("write_error");
    }
  }

  /** Cierra la grabación y devuelve con qué se queda quien llama. */
  stop(): RecordingResult {
    const reason = this.stopped ?? "session_ended";
    this.finishWith(reason);

    return {
      path: this.wroteAnything ? this.file : null,
      bytes: this.bytes,
      frames: this.frames,
      keyBase64: this.key ? this.key.toString("base64") : "",
      stopReason: reason,
      // "Se grabó a medias" tiene que poder distinguirse de "se grabó entera"
      // y de "no se grabó". Las tres significan cosas distintas para quien
      // revise el incidente meses después.
      truncated: reason !== "session_ended"
    };
  }

  private finishWith(reason: StopReason): void {
    if (this.stopped === null) this.stopped = reason;
    if (this.fd !== null) {
      try {
        fs.closeSync(this.fd);
      } catch {
        /* ya cerrado */
      }
      this.fd = null;
    }
    // Un fichero sin un solo fotograma no es una grabación: es basura cifrada
    // ocupando el búfer de alguien.
    if (!this.wroteAnything && this.file) {
      try {
        fs.unlinkSync(this.file);
      } catch {
        /* puede no existir */
      }
    }
  }
}
