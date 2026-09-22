// Qué hace el agente cuando SÍ hay token pero el servidor lo rechaza.
//
// ⚠️ El caso real (2026-09-22, un equipo de T111): el MSI no reescribió
// `HKLM\Software\CertusWS\Tracenium\ENROLLMENT_TOKEN` al reinstalar, así que
// el agente seguía mandando el token de agosto —42/42 usos— y el backend
// contestaba `403 Token exhausted` una y otra vez. El 403 sólo se trataba como
// terminal si el texto decía `Token expired`, de modo que "agotado" caía en el
// reintento genérico y no paraba nunca.
//
// Dos cosas se fijan aquí:
//   1. Un rechazo DEL TOKEN no se reintenta: se espera otro.
//   2. El log dice de qué fuente salió el token y cuál es (por huella, nunca
//      el valor), que es lo único que permitió diagnosticar aquel equipo.

import { describe, it, expect, vi } from "vitest";
import crypto from "crypto";

// `config` lee env/registro y LANZA al importarse si falta GRPC_ENDPOINT, así
// que importar enroll.ts sin esto rompe el fichero entero antes del primer
// test. Mismo doble que enroll-retry.test.ts.
vi.mock("../../src/bootstrap/config", () => ({
  config: {
    serverBaseUrl: "https://api.test.local",
    agentVersion: "9.9.9-test",
  },
}));

import { motivoDeRechazoDeToken } from "../../src/bootstrap/enroll";
import { waitForReplacementToken } from "../../src/bootstrap/token-wait";
import {
  describeTokenSource,
  tokenFingerprint,
  type TokenLookup,
} from "../../src/bootstrap/token-source";

const VIEJO = "gxq5jnXcoZkAZaUIoEgPCU5yNiZot6fy_bCYNj7PvjY";
const NUEVO = "N0rEpLaCeMeNtToKeNfOrThIsDeViCe_0000000000";

const lookup = (token: string | null): TokenLookup => ({
  token,
  source: token ? "registry:64" : null,
  location: token
    ? "HKLM\\Software\\CertusWS\\Tracenium\\ENROLLMENT_TOKEN (64-bit view)"
    : null,
  attempts: [
    {
      source: "registry:64",
      location: "HKLM\\Software\\CertusWS\\Tracenium\\ENROLLMENT_TOKEN (64-bit view)",
      found: !!token,
    },
  ],
});

const mudo = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() });

describe("motivoDeRechazoDeToken", () => {
  it("un token agotado es un rechazo del token — el caso que faltaba", () => {
    expect(motivoDeRechazoDeToken(403, '{"error":"Token exhausted"}')).toBe(
      "all of its uses are spent"
    );
  });

  it("también caducado, revocado y desconocido", () => {
    expect(motivoDeRechazoDeToken(403, '{"error":"Token expired"}')).toBe("it expired");
    expect(motivoDeRechazoDeToken(403, '{"error":"Token not active"}')).toBe(
      "it was revoked or disabled"
    );
    expect(motivoDeRechazoDeToken(401, '{"error":"Invalid bootstrap token"}')).toBe(
      "the server does not recognise it"
    );
  });

  it("NO se lleva lo que no arregla un token nuevo", () => {
    // Licencias agotadas y equipo dado de baja son definitivos para este
    // intento, pero el remedio es otro y merecen su propio aviso. Si se
    // colaran aquí, el agente esperaría para siempre un token que nadie
    // tiene por qué cambiar.
    expect(motivoDeRechazoDeToken(403, '{"error":"LICENSE_LIMIT_REACHED"}')).toBeNull();
    expect(motivoDeRechazoDeToken(410, '{"error":"DEVICE_LIFECYCLE_HIDDEN"}')).toBeNull();
  });

  it("ni los fallos pasajeros, que sí deben reintentarse", () => {
    expect(motivoDeRechazoDeToken(500, "boom")).toBeNull();
    expect(motivoDeRechazoDeToken(502, "")).toBeNull();
    expect(motivoDeRechazoDeToken(429, "slow down")).toBeNull();
  });
});

describe("waitForReplacementToken", () => {
  it("el MISMO token no vale por muchas vueltas que dé", async () => {
    const sleep = vi.fn(async () => {});
    const out = await waitForReplacementToken(VIEJO, "all of its uses are spent", {
      read: () => lookup(VIEJO),
      sleep,
      logger: mudo(),
      maxAttempts: 4,
    });

    // Sin esto el agente volvería al POST con el token agotado y el backend
    // volvería a contestar 403: el bucle que motivó este cambio.
    expect(out).toBeNull();
    // 3 y no 4: la última comprobación sale sin dormir. `maxAttempts` sólo
    // existe para las pruebas — en producción no hay salida sin token usable.
    expect(sleep).toHaveBeenCalledTimes(3);
  });

  it("continúa en cuanto aparece uno distinto, sin reiniciar nada", async () => {
    let vuelta = 0;
    const out = await waitForReplacementToken(VIEJO, "all of its uses are spent", {
      read: () => lookup(++vuelta < 3 ? VIEJO : NUEVO),
      sleep: async () => {},
      logger: mudo(),
      maxAttempts: 10,
    });

    expect(out).toBe(NUEVO);
  });

  it("deja escrito en la máquina que hay que REEMPLAZAR el token, no ponerlo", async () => {
    const blocked: string[] = [];
    const log = mudo();
    await waitForReplacementToken(VIEJO, "all of its uses are spent", {
      read: () => lookup(VIEJO),
      sleep: async () => {},
      logger: log,
      onBlocked: (d) => blocked.push(d),
      maxAttempts: 1,
    });

    expect(blocked).toHaveLength(1);
    const aviso = log.error.mock.calls[0][0] as string;
    expect(aviso).toContain("all of its uses are spent");
    expect(aviso).toContain("REPLACE");
    // Quien lee esto no debe reiniciar el servicio: no arregla nada y en campo
    // produjo miles de arranques inútiles.
    expect(aviso).toContain("restarting the service will NOT help");
  });

  it("⚠️ nombra el token por su huella, nunca por su valor", async () => {
    const log = mudo();
    await waitForReplacementToken(VIEJO, "all of its uses are spent", {
      read: () => lookup(VIEJO),
      sleep: async () => {},
      logger: log,
      maxAttempts: 1,
    });

    const aviso = log.error.mock.calls[0][0] as string;
    expect(aviso).not.toContain(VIEJO);
    expect(aviso).toContain(`sha256:${tokenFingerprint(VIEJO)}`);
  });

  it("raciona el log: no repite el aviso largo en cada vuelta", async () => {
    const log = mudo();
    await waitForReplacementToken(VIEJO, "all of its uses are spent", {
      read: () => lookup(VIEJO),
      sleep: async () => {},
      logger: log,
      maxAttempts: 7,
    });

    expect(log.error).toHaveBeenCalledTimes(1);
    // Vueltas 2 y 3 avisan; de ahí una de cada ocho.
    expect(log.warn).toHaveBeenCalledTimes(2);
  });
});

describe("de qué fuente salió el token", () => {
  it("la huella es el MISMO sha256 que guarda el backend", () => {
    // Es la propiedad que hace útil la huella: se compara de un vistazo con
    // `left(enrollment_tokens.token_hash, 12)` en la base de control. Si se
    // cambiara el algoritmo aquí, dejaría de servir para diagnosticar.
    const esperado = crypto.createHash("sha256").update(VIEJO).digest("hex").slice(0, 12);
    expect(tokenFingerprint(VIEJO)).toBe(esperado);
    expect(tokenFingerprint(`  ${VIEJO}\r\n`)).toBe(esperado);
  });

  it("dice la fuente y el sitio exacto, sin el valor", () => {
    const txt = describeTokenSource(lookup(VIEJO));
    expect(txt).toContain("registry:64");
    expect(txt).toContain("64-bit view");
    expect(txt).toContain(`sha256:${tokenFingerprint(VIEJO)}`);
    expect(txt).not.toContain(VIEJO);
  });

  it("se registra desde el PRIMER intento, no sólo tras una espera", async () => {
    // El fallo de campo tenía el token a la primera: si la fuente sólo se
    // dijera cuando hubo que esperar, este caso seguiría siendo invisible.
    const log = mudo();
    await waitForReplacementToken(VIEJO, "spent", {
      read: () => lookup(NUEVO),
      sleep: async () => {},
      logger: log,
      maxAttempts: 1,
    });

    expect(log.info.mock.calls[0][0]).toContain("Enrollment token read from registry:64");
  });
});
