// test/plugins/rcp-recording-uploader.test.ts
//
// La cola de subida decide cuánto tiempo se queda en el disco de una persona
// el vídeo de su propia pantalla. Sus dos fallos posibles son opuestos:
//
//   rendirse pronto  ⇒ se pierde una grabación de auditoría por un corte de wifi
//   no rendirse nunca ⇒ el vídeo se acumula indefinidamente en su equipo
//
// Por eso lo que se fija aquí es dónde está la línea, no que "funcione".

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  backoffMs,
  isRetryable,
  needsFreshUrl,
  RecordingUploader,
  MAX_ATTEMPTS,
  UPLOAD_DELAY_MS
} from "../../src/plugins/rcp/recording-uploader";
import { writeConfirmedMarker, confirmedMarkerPath } from "../../src/plugins/rcp/recording-handoff";

let dir: string;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "upl-")); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); vi.useRealTimers(); });

function recording(sessionId: string): string {
  const f = path.join(dir, `${sessionId}.trec`);
  fs.writeFileSync(f, "bytes cifrados");
  writeConfirmedMarker(f, { sessionId });
  return f;
}

describe("backoff", () => {
  it("crece con los intentos", () => {
    expect(backoffMs(2)).toBeGreaterThan(backoffMs(1));
  });

  it("tiene techo", () => {
    // Sin techo, el intento 20 esperaría siete horas y la grabación caducaría
    // antes de reintentarse.
    expect(backoffMs(100)).toBe(30 * 60_000);
  });

  it("el primer reintento no es inmediato", () => {
    // Un fallo de red corporativa dura minutos, no segundos. Reintentar al
    // instante gasta batería y llena el log sin arreglar nada.
    expect(backoffMs(1)).toBeGreaterThanOrEqual(60_000);
  });
});

describe("qué respuestas HTTP se reintentan", () => {
  it("5xx, 408 y 429 son transitorios", () => {
    expect(isRetryable(500)).toBe(true);
    expect(isRetryable(503)).toBe(true);
    expect(isRetryable(408)).toBe(true);
    expect(isRetryable(429)).toBe(true);
  });

  it("un 400 no se reintenta: reintentar no lo arregla", () => {
    expect(isRetryable(400)).toBe(false);
  });

  it("403 y 404 piden URL NUEVA, no rendirse", () => {
    // En un SAS, 403 suele ser "caducó". Tratarlo como permanente tiraría una
    // grabación perfectamente subible.
    expect(needsFreshUrl(403)).toBe(true);
    expect(needsFreshUrl(404)).toBe(true);
    expect(needsFreshUrl(500)).toBe(false);
  });
});

describe("cola", () => {
  it("NO sube durante la sesión: espera el retraso completo", async () => {
    // El punto entero de la subida diferida. Empezar antes le quita ancho de
    // banda a la persona a la que se está dando soporte.
    vi.useFakeTimers();
    const up = new RecordingUploader({ requestDestination: () => {} });
    const f = recording("s1");
    up.enqueue("s1", f, "https://blob.invalid/x");

    await vi.advanceTimersByTimeAsync(UPLOAD_DELAY_MS - 1000);
    expect(fs.existsSync(f)).toBe(true); // sigue ahí, nadie lo tocó
    up.stop();
  });

  it("tras un reinicio pide destino nuevo, sin clave", () => {
    // La clave se fue con el proceso anterior; el servidor la tiene.
    const asked: string[] = [];
    const up = new RecordingUploader({ requestDestination: (s) => asked.push(s) });
    up.resume([recording("s2"), recording("s3")]);
    expect(asked.sort()).toEqual(["s2", "s3"]);
    up.stop();
  });

  it("un rechazo del servidor retira el fichero Y su marca", () => {
    // Si el servidor no la quiere, tenerla en el equipo del usuario no le
    // sirve a nadie.
    const up = new RecordingUploader({ requestDestination: () => {} });
    const f = recording("s4");
    up.enqueue("s4", f, "https://blob.invalid/x");
    up.reject("s4", "tenant disabled recording");

    expect(fs.existsSync(f)).toBe(false);
    expect(fs.existsSync(confirmedMarkerPath(f))).toBe(false);
    up.stop();
  });

  it("rechazar algo que no está en la cola no lanza", () => {
    const up = new RecordingUploader({ requestDestination: () => {} });
    expect(() => up.reject("no-existe", "x")).not.toThrow();
  });

  it("stop() cancela los temporizadores pendientes", () => {
    vi.useFakeTimers();
    const up = new RecordingUploader({ requestDestination: () => {} });
    up.enqueue("s5", recording("s5"), "https://blob.invalid/x");
    expect(() => up.stop()).not.toThrow();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("se rinde tras un número acotado de intentos", () => {
    // La constante es el contrato: reintentar para siempre convierte un
    // problema de red en vídeo acumulándose en el equipo de alguien.
    expect(MAX_ATTEMPTS).toBeGreaterThan(1);
    expect(MAX_ATTEMPTS).toBeLessThanOrEqual(10);
  });
});
