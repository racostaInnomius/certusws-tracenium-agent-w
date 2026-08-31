// test/plugins/rcp-recording-store.test.ts
//
// El búfer local guarda VÍDEO DE LA PANTALLA de una persona EN SU PROPIO
// DISCO, entre el final de la sesión y la subida. Sus modos de fallo no son
// "se pierde una grabación": son "le llenamos el disco" y "le dejamos su
// pantalla en claro". Eso es lo que se fija aquí.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import {
  canStart,
  canWriteMore,
  encodeRecord,
  decodeRecord,
  newRecordingKey,
  MAX_SESSION_BYTES,
  MAX_TOTAL_BYTES,
  MIN_FREE_DISK_BYTES,
  type FrameMeta
} from "../../src/plugins/rcp/recording-store";

const meta = (over: Partial<FrameMeta> = {}): FrameMeta => ({
  t: 1000, full: true, x: 0, y: 0, rw: 1920, rh: 1080, w: 1920, h: 1080, ...over
});

describe("topes de disco", () => {
  it("no empieza si queda poco espacio libre", () => {
    // El tope que se olvida. 200 MB de cupo en un portátil con 80 MB libres
    // sigue siendo dañino: el cupo mide lo NUESTRO, no lo que queda.
    const r = canStart({ freeBytes: 100 * 1024 * 1024, bufferBytes: 0 });
    expect(r.ok).toBe(false);
    expect((r as any).reason).toBe("disk_low");
  });

  it("no empieza si el búfer ya está lleno", () => {
    const r = canStart({ freeBytes: 500e9, bufferBytes: MAX_TOTAL_BYTES });
    expect(r.ok).toBe(false);
    expect((r as any).reason).toBe("total_cap");
  });

  it("empieza cuando hay sitio", () => {
    expect(canStart({ freeBytes: 500e9, bufferBytes: 0 }).ok).toBe(true);
  });

  it("un espacio libre desconocido NO bloquea la grabación", () => {
    // statfs puede no estar. Bloquear ahí dejaría la función inservible en esa
    // plataforma; el tope por sesión sigue acotando el daño.
    expect(canStart({ freeBytes: null, bufferBytes: 0 }).ok).toBe(true);
  });

  it("corta al llegar al tope de la sesión", () => {
    const r = canWriteMore({
      sessionBytes: MAX_SESSION_BYTES - 10,
      incomingBytes: 100,
      freeBytes: 500e9
    });
    expect(r.ok).toBe(false);
    expect((r as any).reason).toBe("session_cap");
  });

  it("corta si ESCRIBIR dejaría el disco por debajo del suelo", () => {
    // Se mira el después, no el antes: comprobar solo el estado actual dejaría
    // pasar el fotograma que cruza la línea.
    const r = canWriteMore({
      sessionBytes: 0,
      incomingBytes: 50 * 1024 * 1024,
      freeBytes: MIN_FREE_DISK_BYTES + 10 * 1024 * 1024
    });
    expect(r.ok).toBe(false);
    expect((r as any).reason).toBe("disk_low");
  });

  it("deja escribir en condiciones normales", () => {
    expect(canWriteMore({ sessionBytes: 1e6, incomingBytes: 250e3, freeBytes: 500e9 }).ok).toBe(true);
  });
});

describe("cifrado en reposo", () => {
  it("ida y vuelta con la clave correcta", () => {
    const key = newRecordingKey();
    const payload = Buffer.from("fotograma jpeg simulado");
    const rec = encodeRecord(meta(), payload, key);
    const out = decodeRecord(rec, 0, key);
    expect(out.payload.toString()).toBe("fotograma jpeg simulado");
    expect(out.meta.w).toBe(1920);
    expect(out.next).toBe(rec.length);
  });

  it("el PAYLOAD no aparece en claro en el fichero", () => {
    // Lo que este módulo existe para impedir: que el equipo que guarda el
    // fichero pueda leer la pantalla que contiene.
    const key = newRecordingKey();
    const secreto = "CONTRASEÑA-VISIBLE-EN-PANTALLA";
    const rec = encodeRecord(meta(), Buffer.from(secreto), key);
    expect(rec.toString("latin1")).not.toContain(secreto);
  });

  it("otra clave NO descifra", () => {
    const rec = encodeRecord(meta(), Buffer.from("x"), newRecordingKey());
    expect(() => decodeRecord(rec, 0, newRecordingKey())).toThrow();
  });

  it("un payload manipulado LANZA en vez de devolver basura", () => {
    // GCM autentica. Una grabación de auditoría que se puede alterar sin que
    // se note no sirve como prueba de nada.
    const key = newRecordingKey();
    const rec = encodeRecord(meta(), Buffer.from("original"), key);
    rec[rec.length - 1] ^= 0xff;
    expect(() => decodeRecord(rec, 0, key)).toThrow();
  });

  it("cada registro lleva su propio IV", () => {
    // Reutilizar IV en GCM con la misma clave rompe el cifrado por completo.
    const key = newRecordingKey();
    const a = encodeRecord(meta(), Buffer.from("mismo"), key);
    const b = encodeRecord(meta(), Buffer.from("mismo"), key);
    expect(a.equals(b)).toBe(false);
  });

  it("cada grabación estrena clave", () => {
    expect(newRecordingKey().equals(newRecordingKey())).toBe(false);
    expect(newRecordingKey().length).toBe(32);
  });
});

describe("formato del fichero", () => {
  it("se recorren varios registros seguidos", () => {
    const key = newRecordingKey();
    const buf = Buffer.concat([
      encodeRecord(meta({ t: 0 }), Buffer.from("uno"), key),
      encodeRecord(meta({ t: 1000, full: false, x: 10, y: 20 }), Buffer.from("dos"), key)
    ]);

    const r1 = decodeRecord(buf, 0, key);
    const r2 = decodeRecord(buf, r1.next, key);
    expect(r1.payload.toString()).toBe("uno");
    expect(r2.payload.toString()).toBe("dos");
    expect(r2.meta.full).toBe(false);
    expect(r2.meta.x).toBe(10);
    expect(r2.next).toBe(buf.length);
  });

  it("un fichero TRUNCADO conserva los registros anteriores", () => {
    // El motivo de cifrar por registro y no el fichero entero. Un equipo que
    // se apaga a media escritura no puede llevarse la sesión completa.
    const key = newRecordingKey();
    const completo = Buffer.concat([
      encodeRecord(meta({ t: 0 }), Buffer.from("sobrevive"), key),
      encodeRecord(meta({ t: 1000 }), Buffer.from("se pierde"), key)
    ]);
    const primero = decodeRecord(completo, 0, key);
    const truncado = completo.subarray(0, primero.next + 20);

    expect(decodeRecord(truncado, 0, key).payload.toString()).toBe("sobrevive");
    expect(() => decodeRecord(truncado, primero.next, key)).toThrow();
  });

  it("la cabecera queda LEGIBLE sin la clave", () => {
    // Deliberado: son marcas de tiempo y coordenadas, no contenido de
    // pantalla. Tenerlas en claro permite recorrer y reparar un fichero
    // truncado sin la clave, que es lo que hará falta el día que haya que
    // recuperar una grabación a medias.
    const rec = encodeRecord(meta({ t: 4242 }), Buffer.from("x"), newRecordingKey());
    const headLen = rec.readUInt32BE(0);
    const header = JSON.parse(rec.subarray(4, 4 + headLen).toString("utf8"));
    expect(header.t).toBe(4242);
    expect(header.w).toBe(1920);
  });
});
