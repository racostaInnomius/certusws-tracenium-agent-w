// test/plugins/rcp-consent-tray-channel.test.ts
//
// El canal de respuesta de la bandeja. Misma clase de código —ficheros entre
// procesos con dueños distintos— donde ya se coló un bug silencioso en
// remote-session-revoke.ts: un readdir fallido descartaba el homedir propio y
// la revocación no habría funcionado NUNCA, sin un solo error en el log.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

import {
  consumeConsentResponse,
  consentResponseCandidates
} from "../../src/plugins/rcp/consent-prompter-tray";

let tmp: string;
let prevHome: string | undefined;
let prevPlatform: PropertyDescriptor | undefined;

function responseFile(): string {
  return path.join(tmp, "Library", "Application Support", "Tracenium", "consent-response.json");
}

function write(contents: unknown): void {
  const f = responseFile();
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, typeof contents === "string" ? contents : JSON.stringify(contents));
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "consent-test-"));
  prevHome = process.env.HOME;
  process.env.HOME = tmp;
  prevPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "darwin" });
});

afterEach(() => {
  if (prevHome === undefined) delete process.env.HOME;
  else process.env.HOME = prevHome;
  if (prevPlatform) Object.defineProperty(process, "platform", prevPlatform);
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("consentResponseCandidates", () => {
  it("incluye el homedir propio aunque /Users no se pueda listar", () => {
    // El bug exacto que ya nos pasó una vez en el canal de revocación.
    const cands = consentResponseCandidates();
    expect(cands.some((c) => c.startsWith(tmp))).toBe(true);
  });
});

describe("consumeConsentResponse", () => {
  it("devuelve la decisión cuando el requestId coincide", () => {
    write({ requestId: "r1", decision: "approved", atUtc: new Date().toISOString() });
    expect(consumeConsentResponse("r1")).toBe("approved");
  });

  it("consume el fichero aunque sea de OTRA petición", () => {
    // Dejarlo sería una mina: la siguiente petición se resolvería sola con una
    // decisión que nadie tomó para ella.
    write({ requestId: "vieja", decision: "approved", atUtc: new Date().toISOString() });
    expect(consumeConsentResponse("nueva")).toBeNull();
    expect(fs.existsSync(responseFile())).toBe(false);
  });

  it("un fichero corrupto no lanza, y se retira", () => {
    write("{ no es json");
    expect(() => consumeConsentResponse("r1")).not.toThrow();
    expect(fs.existsSync(responseFile())).toBe(false);
  });

  it("sin fichero devuelve null — el caso más recorrido", () => {
    // Se sondea cada 300 ms mientras el diálogo está abierto.
    expect(consumeConsentResponse("r1")).toBeNull();
  });

  it("cualquier decisión que no sea 'approved' es denegar", () => {
    // Un valor inesperado no puede conceder acceso al equipo de nadie.
    write({ requestId: "r1", decision: "quizá", atUtc: new Date().toISOString() });
    expect(consumeConsentResponse("r1")).toBe("denied");
  });
});
