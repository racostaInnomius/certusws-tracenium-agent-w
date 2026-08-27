// Lectura del token de enrollment: qué se encontró y, sobre todo, por qué no.
//
// El caso que originó esto: un equipo con el token VISIBLE en regedit cuyo
// agente reportaba "not found in env/file/registry" 3722 veces. La lectura no
// mentía —desde ese proceso el valor no estaba— pero tampoco decía nada útil,
// y sin el motivo no se puede distinguir una clave ausente de una vista de 32
// bits o de un reg.exe que ni siquiera llegó a correr.

import { describe, it, expect } from "vitest";
import {
  describeRegFailure,
  describeTokenLookup,
  parseRegQueryValue,
  type TokenLookup,
} from "../../src/bootstrap/token-source";

const REG_OUTPUT = [
  "",
  "HKEY_LOCAL_MACHINE\\Software\\CertusWS\\Tracenium",
  "    ENROLLMENT_TOKEN    REG_SZ    gxq5jnXcoZkAZaUIoEgPCU5yNiZot6fy_bCYNj7PvjY",
  "",
].join("\r\n");

describe("parseRegQueryValue", () => {
  it("saca el dato de una salida real de reg query", () => {
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", REG_OUTPUT)).toBe(
      "gxq5jnXcoZkAZaUIoEgPCU5yNiZot6fy_bCYNj7PvjY"
    );
  });

  it("⚠️ devuelve null cuando el valor pedido NO está en la salida", () => {
    // Ésta es la regresión. La versión anterior hacía split("REG_SZ") y se
    // quedaba con lo que viniera después, sin comprobar de qué valor era: ante
    // una salida de otra forma devolvía basura en vez de null, y basura en el
    // lugar de un token es un enrollment que falla más adelante, más lejos de
    // la causa.
    const otro = [
      "HKEY_LOCAL_MACHINE\\Software\\CertusWS\\Tracenium",
      "    ServerBaseUrl    REG_SZ    https://api.tracenium.com",
    ].join("\r\n");

    expect(parseRegQueryValue("ENROLLMENT_TOKEN", otro)).toBeNull();
  });

  it("acepta REG_EXPAND_SZ, que también es texto", () => {
    const out = "    ENROLLMENT_TOKEN    REG_EXPAND_SZ    abc123";
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", out)).toBe("abc123");
  });

  it("conserva un valor con espacios: el dato es el resto del renglón", () => {
    const out = "    ServerBaseUrl    REG_SZ    C:\\Program Files\\Tracenium";
    expect(parseRegQueryValue("ServerBaseUrl", out)).toBe("C:\\Program Files\\Tracenium");
  });

  it("un valor vacío es ausencia, no cadena vacía", () => {
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", "    ENROLLMENT_TOKEN    REG_SZ    ")).toBeNull();
  });

  it("aguanta entradas que no son salida de reg query", () => {
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", "")).toBeNull();
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", null)).toBeNull();
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", undefined)).toBeNull();
    expect(parseRegQueryValue("ENROLLMENT_TOKEN", 42)).toBeNull();
    expect(
      parseRegQueryValue("ENROLLMENT_TOKEN", "ERROR: The system was unable to find the key.")
    ).toBeNull();
  });
});

describe("describeRegFailure", () => {
  it("distingue 'reg.exe nunca corrió' de 'reg.exe contestó que no'", () => {
    // Sin status no hubo proceso: reg.exe ausente, o el spawn bloqueado por un
    // EDR. Manda a revisar la máquina, no la clave.
    const spawn = describeRegFailure({ code: "ENOENT", message: "spawn reg.exe ENOENT" });
    expect(spawn).toMatch(/could not run reg\.exe/i);

    const salida = describeRegFailure({
      status: 1,
      stderr: "ERROR: The system was unable to find the specified registry key or value.\r\n",
    });
    expect(salida).toMatch(/exited 1/);
    expect(salida).toMatch(/unable to find/i);
  });

  it("⚠️ no clasifica por el texto de stderr, que viene traducido", () => {
    // reg.exe escribe en el idioma del sistema. Emparejar contra cadenas en
    // inglés funciona en el laboratorio y falla en el equipo del cliente, así
    // que el texto se transporta pero no se interpreta.
    const es = describeRegFailure({
      status: 1,
      stderr: "ERROR: El sistema no puede encontrar la clave o el valor del Registro especificado.",
    });
    expect(es).toMatch(/exited 1/);
    expect(es).toMatch(/El sistema no puede encontrar/);
  });

  it("nombra el timeout como lo que es", () => {
    expect(describeRegFailure({ killed: true })).toMatch(/did not answer/i);
    expect(describeRegFailure({ code: "ETIMEDOUT" })).toMatch(/did not answer/i);
  });

  it("no explota con un error sin forma", () => {
    expect(describeRegFailure(null)).toBe("unknown failure");
    expect(describeRegFailure({ status: 1 })).toBe("reg.exe exited 1");
  });
});

describe("describeTokenLookup", () => {
  const lookup: TokenLookup = {
    token: null,
    attempts: [
      { source: "env", location: "ENROLLMENT_TOKEN", found: false, detail: "not set" },
      {
        source: "registry:64",
        location: "HKLM\\Software\\CertusWS\\Tracenium\\ENROLLMENT_TOKEN (64-bit view)",
        found: false,
        detail: "reg.exe exited 1: ERROR: unable to find",
      },
    ],
  };

  it("nombra cada fuente, dónde se buscó y qué contestó", () => {
    const txt = describeTokenLookup(lookup);
    expect(txt).toMatch(/env/);
    expect(txt).toMatch(/not set/);
    expect(txt).toMatch(/64-bit view/);
    expect(txt).toMatch(/exited 1/);
  });

  it("⚠️ nunca imprime el token, que es una credencial al portador", () => {
    // Estos logs se copian por correo para pedir ayuda. Un token filtrado ahí
    // sirve para registrar un equipo falso contra el tenant hasta que alguien
    // lo revoque.
    const conToken: TokenLookup = {
      token: "gxq5jnXcoZkAZaUIoEgPCU5yNiZot6fy_bCYNj7PvjY",
      attempts: [
        { source: "file", location: "C:\\ProgramData\\x\\enrollment.token", found: true },
      ],
    };
    expect(describeTokenLookup(conToken)).not.toContain("gxq5jn");
  });
});
