// test/status/remote-session-revoke.test.ts
//
// El canal de revocación es el control que le permite a una persona cortar una
// sesión en la que están viendo su pantalla (ADR-0012). Sus modos de fallo son
// silenciosos por naturaleza —un fichero que no se lee, uno que se lee de más—
// así que van fijados aquí.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

import { consumeRevokeRequest } from "../../src/status/remote-session-revoke";

// El módulo busca en los perfiles de usuario reales. En el runner apuntamos
// HOME a un directorio temporal y ejercitamos el camino de Linux, que es el que
// incluye os.homedir() entre sus candidatos.
let tmp: string;
let prevHome: string | undefined;
let prevPlatform: PropertyDescriptor | undefined;

function revokeFile(): string {
  return path.join(tmp, ".config", "tracenium", "remote-session-revoke.json");
}

function write(contents: unknown): void {
  const f = revokeFile();
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, typeof contents === "string" ? contents : JSON.stringify(contents));
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "revoke-test-"));
  prevHome = process.env.HOME;
  process.env.HOME = tmp;
  prevPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "linux" });
});

afterEach(() => {
  if (prevHome === undefined) delete process.env.HOME;
  else process.env.HOME = prevHome;
  if (prevPlatform) Object.defineProperty(process, "platform", prevPlatform);
  fs.rmSync(tmp, { recursive: true, force: true });
  vi.useRealTimers();
});

describe("consumeRevokeRequest", () => {
  it("devuelve la petición cuando el sessionId coincide", () => {
    write({ sessionId: "abc", atUtc: new Date().toISOString(), by: "usuario" });
    const req = consumeRevokeRequest("abc");
    expect(req?.sessionId).toBe("abc");
    expect(req?.by).toBe("usuario");
  });

  it("consume el fichero aunque sea de OTRA sesión", () => {
    // Si se dejara, mataría la siguiente sesión nada más abrirse y el operador
    // vería una desconexión sin causa aparente.
    write({ sessionId: "vieja", atUtc: new Date().toISOString() });
    expect(consumeRevokeRequest("nueva")).toBeNull();
    expect(fs.existsSync(revokeFile())).toBe(false);
  });

  it("ignora una petición caducada, y la consume igual", () => {
    // Una petición de corte de hace una hora se refiere a una sesión que ya
    // terminó. Actuar sobre ella solo puede equivocarse.
    const old = new Date(Date.now() - 10 * 60_000).toISOString();
    write({ sessionId: "abc", atUtc: old });
    expect(consumeRevokeRequest("abc")).toBeNull();
    expect(fs.existsSync(revokeFile())).toBe(false);
  });

  it("no lanza con un fichero corrupto, y lo retira", () => {
    // Corre dentro del bucle de captura: si lanzara, tumbaría la sesión que
    // intenta proteger.
    write("{ esto no es json");
    expect(() => consumeRevokeRequest("abc")).not.toThrow();
    expect(fs.existsSync(revokeFile())).toBe(false);
  });

  it("devuelve null cuando no hay fichero, que es el caso normal", () => {
    // Se sondea dos veces por segundo durante toda la sesión: el camino sin
    // fichero es el que más se recorre con diferencia.
    expect(consumeRevokeRequest("abc")).toBeNull();
  });

  it("una petición sin sessionId no corta nada", () => {
    write({ atUtc: new Date().toISOString() });
    expect(consumeRevokeRequest("abc")).toBeNull();
  });
});
