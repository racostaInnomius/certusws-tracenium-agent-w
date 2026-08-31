// test/plugins/rcp-recording-handoff.test.ts
//
// La invariante que gobierna el ciclo de vida del fichero grabado:
//
//   la clave NUNCA se escribe en el endpoint, así que un .trec que sobrevive a
//   un reinicio sin que su clave haya llegado al control plane es basura
//   indescifrable — para siempre, por nadie.
//
// Los dos errores posibles son simétricos y los dos son malos: barrer un
// fichero que sí era recuperable pierde una grabación de auditoría; NO barrer
// uno indescifrable deja vídeo de la pantalla de alguien en su disco sin que
// aporte nada. Eso es lo que se fija aquí.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  purgeUnconfirmed,
  writeConfirmedMarker,
  isConfirmed,
  removeRecording,
  confirmedMarkerPath,
  pendingUploads,
  fileSha256
} from "../../src/plugins/rcp/recording-handoff";

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "handoff-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function recording(name: string, contents = "bytes cifrados"): string {
  const f = path.join(dir, `${name}.trec`);
  fs.writeFileSync(f, contents);
  return f;
}

describe("barrido de arranque", () => {
  it("BORRA una grabación cuya clave se perdió con el proceso", () => {
    // El caso central: el agente murió a mitad de sesión y la clave se fue con
    // él. Ese fichero ya no lo puede leer nadie.
    const f = recording("s1");
    expect(purgeUnconfirmed(dir)).toBe(1);
    expect(fs.existsSync(f)).toBe(false);
  });

  it("CONSERVA una grabación cuya clave ya está en el control plane", () => {
    // Barrerla perdería una grabación de auditoría perfectamente recuperable.
    const f = recording("s2");
    writeConfirmedMarker(f, { sessionId: "s2" });
    expect(purgeUnconfirmed(dir)).toBe(0);
    expect(fs.existsSync(f)).toBe(true);
  });

  it("distingue entre varias en el mismo directorio", () => {
    const viva = recording("confirmada");
    writeConfirmedMarker(viva, { sessionId: "confirmada" });
    const muerta = recording("huerfana");

    expect(purgeUnconfirmed(dir)).toBe(1);
    expect(fs.existsSync(viva)).toBe(true);
    expect(fs.existsSync(muerta)).toBe(false);
  });

  it("retira marcas huérfanas sin fichero", () => {
    // Su grabación ya se subió y se borró. No hacen daño, pero acumularlas
    // convierte el directorio en un cementerio.
    const marker = path.join(dir, "vieja.trec.ok");
    fs.writeFileSync(marker, "{}");
    purgeUnconfirmed(dir);
    expect(fs.existsSync(marker)).toBe(false);
  });

  it("no toca ficheros que no son grabaciones", () => {
    const otro = path.join(dir, "notas.txt");
    fs.writeFileSync(otro, "algo");
    purgeUnconfirmed(dir);
    expect(fs.existsSync(otro)).toBe(true);
  });

  it("con el directorio ausente no lanza", () => {
    expect(() => purgeUnconfirmed(path.join(dir, "no-existe"))).not.toThrow();
    expect(purgeUnconfirmed(path.join(dir, "no-existe"))).toBe(0);
  });
});

describe("la marca de confirmación", () => {
  it("NO contiene la clave", () => {
    // Si la llevara, habríamos deshecho el cifrado: el equipo volvería a tener
    // las dos mitades.
    const f = recording("s3");
    const key = "Y2xhdmUtc2VjcmV0YS1xdWUtbm8tZGViZS1lc3Rhcg==";
    writeConfirmedMarker(f, { sessionId: "s3" });
    const content = fs.readFileSync(confirmedMarkerPath(f), "utf8");
    expect(content).not.toContain(key);
    expect(content).toContain("s3");
  });

  it("se escribe en modo 600", () => {
    const f = recording("s4");
    writeConfirmedMarker(f, { sessionId: "s4" });
    expect(fs.statSync(confirmedMarkerPath(f)).mode & 0o777).toBe(0o600);
  });

  it("isConfirmed es false antes y true después", () => {
    const f = recording("s5");
    expect(isConfirmed(f)).toBe(false);
    writeConfirmedMarker(f, { sessionId: "s5" });
    expect(isConfirmed(f)).toBe(true);
  });
});

describe("retirada", () => {
  it("se lleva el fichero Y su marca", () => {
    // Dejar la marca sola haría que el siguiente barrido la contara como
    // huérfana; dejar el fichero solo lo volvería indescifrable-pero-presente.
    const f = recording("s6");
    writeConfirmedMarker(f, { sessionId: "s6" });
    removeRecording(f);
    expect(fs.existsSync(f)).toBe(false);
    expect(fs.existsSync(confirmedMarkerPath(f))).toBe(false);
  });

  it("es idempotente", () => {
    const f = recording("s7");
    removeRecording(f);
    expect(() => removeRecording(f)).not.toThrow();
  });
});

describe("cola de subida", () => {
  it("solo lista las confirmadas", () => {
    // Una sin confirmar no se puede subir: el servidor no tendría con qué
    // descifrarla.
    const lista = recording("subible");
    writeConfirmedMarker(lista, { sessionId: "subible" });
    recording("sin-confirmar");

    const pend = pendingUploads(dir);
    expect(pend.length).toBe(1);
    expect(pend[0]).toBe(lista);
  });
});

describe("hash de integridad", () => {
  it("cambia si el fichero cambia", () => {
    // Sin esto, una subida truncada daría una grabación de auditoría en la que
    // nadie puede confiar — y eso es peor que no tenerla, porque parece que la
    // hay.
    const a = recording("h1", "contenido A");
    const b = recording("h2", "contenido B");
    expect(fileSha256(a)).not.toBe(fileSha256(b));
    expect(fileSha256(a)).toBe(fileSha256(recording("h3", "contenido A")));
    expect(fileSha256(a)).toMatch(/^[0-9a-f]{64}$/);
  });
});
