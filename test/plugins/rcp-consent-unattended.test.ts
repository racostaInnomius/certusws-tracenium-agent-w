// test/plugins/rcp-consent-unattended.test.ts
//
// 🔴 Un equipo SIN nadie delante decía «no te contestaron».
//
// TNS-OPER-SNOC04 (T1, Windows Server 2022, 25-sep-2026): cuatro intentos de
// `rcp.screen`, los cuatro muertos exactamente a los 61 s con
// `consent_timeout`. En el portal:
//
//   «Nobody answered the request on the device.
//    The prompt appeared and expired with no answer.
//    They may be away from the machine.»
//
// Las dos frases afirman cosas que no sabíamos. Ese servidor no tiene usuario
// de consola —`last_logon_user` vacío en `host_current_status`, mientras los
// otros cuatro Windows del tenant sí lo reportan— y la bandeja vive en la
// sesión del usuario: sin usuario no hay bandeja, y sin bandeja el aviso no
// aparece en ningún sitio. No se fue nadie; no había nadie.
//
// El coste no fue solo el minuto de espera: el mensaje mandó a buscar el
// fallo en la política de aprobación, que no tenía nada que ver — la sesión
// llegaba con su access_request y moría en la puerta siguiente.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const interactiveUser = vi.fn();
vi.mock("../../src/domain/device-facts-builder", () => ({
  getInteractiveUserFromOs: () => interactiveUser()
}));

import { createTrayConsentPrompter } from "../../src/plugins/rcp/consent-prompter-tray";
import { consentCloseReason } from "../../src/plugins/rcp/consent-prompt";

import fs from "fs";
import os from "os";
import path from "path";

let tmp: string;
let prevEnv: string | undefined;
let prevPlatform: PropertyDescriptor | undefined;

const ctx: any = { logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } };

const req = {
  sessionId: "s-1",
  capability: "rcp.screen",
  operator: "Javier Pacheco",
  timeoutSeconds: 60
};

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "consent-unattended-"));
  prevEnv = process.env.TRACENIUM_AGENT_DATA_DIR;
  process.env.TRACENIUM_AGENT_DATA_DIR = path.join(tmp, "Agent");
  prevPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "darwin" });
  // El directorio de estado lo crea el agente al arrancar; aquí se replica
  // para no probar contra una carpeta que en el equipo siempre existe.
  fs.mkdirSync(path.join(tmp, "status"), { recursive: true });
  interactiveUser.mockReset();
});

afterEach(() => {
  if (prevEnv === undefined) delete process.env.TRACENIUM_AGENT_DATA_DIR;
  else process.env.TRACENIUM_AGENT_DATA_DIR = prevEnv;
  if (prevPlatform) Object.defineProperty(process, "platform", prevPlatform);
  fs.rmSync(tmp, { recursive: true, force: true });
});

function requestFile(): string {
  // status/ es hermano de Agent/ en macOS y Linux (Agent/ es 700 y la bandeja
  // no puede atravesarlo).
  return path.join(tmp, "status", "consent-request.json");
}

describe("consentimiento en un equipo sin nadie delante", () => {
  it("responde 'unavailable' en el acto, sin esperar el plazo", async () => {
    interactiveUser.mockResolvedValue(null); // servidor sin sesión interactiva

    const started = Date.now();
    const decision = await createTrayConsentPrompter(ctx).request(req);
    const elapsed = Date.now() - started;

    expect(decision).toBe("unavailable");
    // La invariante que importa: NO se esperan los 60 s del plazo. El umbral
    // es generoso a propósito; lo que se descarta es el minuto entero.
    expect(elapsed).toBeLessThan(2000);
  });

  it("y no deja una petición huérfana que la bandeja enseñe más tarde", async () => {
    interactiveUser.mockResolvedValue(null);
    await createTrayConsentPrompter(ctx).request(req);
    expect(
      fs.existsSync(requestFile()),
      "escribir una petición que nadie va a leer deja un aviso que saldría "
      + "cuando alguien entre, pidiendo permiso para una sesión ya muerta"
    ).toBe(false);
  });

  it("el operador lee «este equipo no puede preguntar», no «no te contestaron»", () => {
    expect(consentCloseReason("unavailable")).toBe("consent_required");
    // Y sigue siendo distinto de los otros dos, que sí significan que alguien
    // decidió: uno diciendo que no, el otro dejándolo vencer.
    expect(consentCloseReason("denied")).toBe("consent_denied");
    expect(consentCloseReason("timeout")).toBe("consent_timeout");
    expect(consentCloseReason("approved")).toBeNull();
  });

  it("con alguien delante sí escribe la petición y espera", async () => {
    interactiveUser.mockResolvedValue({ user: "irosales" });

    const prompter = createTrayConsentPrompter(ctx);
    const pending = prompter.request({ ...req, timeoutSeconds: 1 });

    // Se le da un respiro al escritor antes de mirar.
    await new Promise((r) => setTimeout(r, 150));
    expect(
      fs.existsSync(requestFile()),
      "con usuario de consola la petición TIENE que escribirse; si esto se "
      + "rompe, el consentimiento deja de funcionar en los equipos normales"
    ).toBe(true);

    // Nadie contesta: el plazo vence y eso sí es un timeout de verdad.
    await expect(pending).resolves.toBe("timeout");
  });
});
