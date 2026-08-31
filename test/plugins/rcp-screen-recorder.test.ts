// test/plugins/rcp-screen-recorder.test.ts
//
// El grabador decide QUÉ fotogramas se quedan. Su fallo más caro no da error
// al grabar: da una grabación que parece bien y está corrupta, y se descubre
// meses después, al reproducir la sesión que alguien necesitaba como prueba.
//
// Ese fallo es tirar un rect sucio. Los rects son interdependientes —cada uno
// se pinta sobre el estado anterior—, así que quedarse con uno de cada cinco
// no da la misma grabación más ligera: da una base que nunca existió.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { ScreenRecorder } from "../../src/plugins/rcp/screen-recorder";
import { decodeRecord, MAX_SESSION_BYTES } from "../../src/plugins/rcp/recording-store";

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "rec-test-"));
});
afterEach(() => {
  delete process.env.TRACENIUM_RECORDINGS_DIR;
  fs.rmSync(dir, { recursive: true, force: true });
});

const frame = (over: Partial<any> = {}) => ({
  payload: Buffer.from("jpeg"),
  full: true, x: 0, y: 0, rw: 1920, rh: 1080, w: 1920, h: 1080,
  ...over
});

/** Lee todos los registros de una grabación con su clave. */
function readAll(file: string, keyBase64: string) {
  const buf = fs.readFileSync(file);
  const key = Buffer.from(keyBase64, "base64");
  const out: any[] = [];
  let off = 0;
  while (off < buf.length) {
    const r = decodeRecord(buf, off, key);
    out.push(r.meta);
    off = r.next;
  }
  return out;
}

describe("qué fotogramas se guardan", () => {
  it("NUNCA tira un fotograma parcial", () => {
    // El test que protege la corrección de toda la grabación.
    const rec = new ScreenRecorder("s1", undefined, dir);
    expect(rec.start()).toBe(true);
    rec.offer(frame());                                   // base
    for (let i = 0; i < 30; i++) {
      rec.offer(frame({ full: false, x: i, y: i, rw: 8, rh: 8 }));
    }
    const res = rec.stop();

    const metas = readAll(res.path!, res.keyBase64);
    expect(metas.filter((m) => !m.full).length).toBe(30);
  });

  it("guarda siempre el primer fotograma, que es la base", () => {
    const rec = new ScreenRecorder("s2", undefined, dir);
    rec.start();
    rec.offer(frame());
    const res = rec.stop();
    expect(readAll(res.path!, res.keyBase64)[0].full).toBe(true);
  });

  it("limita los COMPLETOS posteriores a uno por segundo", () => {
    // Aquí sí se aplica el ritmo reducido del ADR: los completos son
    // independientes, así que tirarlos no rompe nada. Es la regla que de
    // verdad implementa el "1 fps" en macOS y Linux, donde los helpers solo
    // devuelven completos.
    const rec = new ScreenRecorder("s3", undefined, dir);
    rec.start();
    for (let i = 0; i < 10; i++) rec.offer(frame());
    const res = rec.stop();

    // El primero entra; el resto cae en la misma ventana de 1 s.
    expect(readAll(res.path!, res.keyBase64).length).toBe(1);
  });

  it("las marcas de tiempo van en orden y desde cero", () => {
    const rec = new ScreenRecorder("s4", undefined, dir);
    rec.start();
    rec.offer(frame());
    rec.offer(frame({ full: false }));
    const res = rec.stop();
    const metas = readAll(res.path!, res.keyBase64);
    expect(metas[0].t).toBeGreaterThanOrEqual(0);
    expect(metas[1].t).toBeGreaterThanOrEqual(metas[0].t);
  });
});

describe("cuando hay que parar", () => {
  it("corta al llegar al tope de sesión y lo marca como truncada", () => {
    const rec = new ScreenRecorder("s5", undefined, dir);
    rec.start();
    rec.offer(frame());
    // Un payload que se pasa del tope de golpe.
    rec.offer(frame({ full: false, payload: Buffer.alloc(MAX_SESSION_BYTES + 1) }));
    const res = rec.stop();

    expect(res.stopReason).toBe("session_cap");
    expect(res.truncated).toBe(true);
  });

  it("una parada por tope NO borra lo ya grabado", () => {
    // Media grabación sigue siendo auditable. Tirarla sería castigar al que
    // revisa por un límite que decidimos nosotros.
    const rec = new ScreenRecorder("s6", undefined, dir);
    rec.start();
    rec.offer(frame());
    rec.offer(frame({ full: false, payload: Buffer.alloc(MAX_SESSION_BYTES + 1) }));
    const res = rec.stop();

    expect(res.path).not.toBeNull();
    expect(fs.existsSync(res.path!)).toBe(true);
    expect(res.frames).toBe(1);
  });

  it("tras cortar, ya no acepta más fotogramas", () => {
    const rec = new ScreenRecorder("s7", undefined, dir);
    rec.start();
    rec.offer(frame());
    rec.offer(frame({ full: false, payload: Buffer.alloc(MAX_SESSION_BYTES + 1) }));
    expect(rec.active).toBe(false);
    rec.offer(frame({ full: false }));
    expect(rec.stop().frames).toBe(1);
  });

  it("una sesión sin un solo fotograma no deja fichero", () => {
    // Un fichero vacío no es una grabación: es basura cifrada ocupando el
    // búfer de alguien.
    const rec = new ScreenRecorder("s8", undefined, dir);
    rec.start();
    const res = rec.stop();
    expect(res.path).toBeNull();
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it("el final normal NO se marca como truncado", () => {
    const rec = new ScreenRecorder("s9", undefined, dir);
    rec.start();
    rec.offer(frame());
    const res = rec.stop();
    expect(res.stopReason).toBe("session_ended");
    expect(res.truncated).toBe(false);
  });
});

describe("seguridad del fichero", () => {
  it("se escribe en modo 600", () => {
    const rec = new ScreenRecorder("s10", undefined, dir);
    rec.start();
    rec.offer(frame());
    const res = rec.stop();
    const mode = fs.statSync(res.path!).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("la clave NO queda en el disco junto al vídeo", () => {
    // El punto entero del cifrado: el equipo que guarda el fichero no puede
    // leerlo. Si la clave estuviera al lado, no habríamos cifrado nada.
    const rec = new ScreenRecorder("s11", undefined, dir);
    rec.start();
    rec.offer(frame());
    const res = rec.stop();

    for (const name of fs.readdirSync(dir)) {
      const content = fs.readFileSync(path.join(dir, name));
      expect(content.includes(Buffer.from(res.keyBase64, "base64"))).toBe(false);
    }
  });

  it("un fallo de escritura no lanza — la sesión de soporte sigue", () => {
    const rec = new ScreenRecorder("s12", undefined, dir);
    rec.start();
    rec.offer(frame());
    // Cerrar el descriptor por debajo simula un disco que falla a mitad.
    fs.closeSync((rec as any).fd);
    expect(() => rec.offer(frame({ full: false }))).not.toThrow();
    expect(rec.stop().stopReason).toBe("write_error");
  });
});

// ── Integración con la sesión ───────────────────────────────────────
//
// El acoplamiento que importa: que NO se grabe cuando el tenant no lo activó.
// Un fallo aquí no da error — deja vídeo de la pantalla de alguien en su disco
// sin que nadie lo haya decidido, que es exactamente lo que ADR-0012 descartó
// al rechazar "grabar siempre y usar el toggle solo para retener".

import { ScreenSession } from "../../src/plugins/rcp/screen-session";
import { vi } from "vitest";

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(_cb: () => void) {}
  sendMessage(text: string) { this.sent.push(text); }
}

const okFrame = () => ({
  ok: true,
  result: {
    data: Buffer.from("jpeg-simulado").toString("base64"),
    width: 1920, height: 1080, cursorX: 0, cursorY: 0,
    full: true, x: 0, y: 0, rw: 1920, rh: 1080
  }
});

function sessionWithRecording(enabled: boolean) {
  // La sesión resuelve el directorio por su cuenta, y en la máquina que corre
  // los tests ese camino es el REAL del agente. Sin el override, el grabador
  // no arrancaría (o peor: escribiría en el equipo de quien corre los tests) y
  // el verde no probaría nada.
  process.env.TRACENIUM_RECORDINGS_DIR = dir;
  const dc = new FakeDataChannel();
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    policyRuntime: { isFeatureEnabled: (f: string) => f === "remoteRecordScreen" && enabled },
    priv: { call: vi.fn(async () => okFrame()) }
  };
  const session = new ScreenSession(dc as any, {
    sessionId: "sess-rec", ctx,
    sendScreenAudit: () => {}, onTeardown: () => {}
  } as any);
  return { session, ctx };
}

describe("la sesión solo graba si el tenant lo activó", () => {
  it("con el toggle APAGADO no se crea grabador", async () => {
    const { session } = sessionWithRecording(false);
    await new Promise((r) => setTimeout(r, 60));
    expect((session as any).recorder).toBeNull();
    session.dispose("test");
  });

  it("con el toggle ENCENDIDO sí se crea", async () => {
    const { session } = sessionWithRecording(true);
    await new Promise((r) => setTimeout(r, 60));
    expect((session as any).recorder).not.toBeNull();
    session.dispose("test");
  });

  it("al cerrar la sesión se suelta el grabador", async () => {
    // Si quedara vivo, seguiría con el fichero abierto y el búfer sin cerrar.
    const { session } = sessionWithRecording(true);
    await new Promise((r) => setTimeout(r, 60));
    session.dispose("test");
    expect((session as any).recorder).toBeNull();
  });
});
