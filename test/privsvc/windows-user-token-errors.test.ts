// test/privsvc/windows-user-token-errors.test.ts
//
// 🔴 «The PrivSvc must run as LocalSystem to hold SE_TCB_NAME» sobre un
// servicio que corría como LocalSystem perfectamente.
//
// TNS-OPER-SNOC04 (Windows Server 2022, 26-sep-2026). Tras quitar de en medio
// el consentimiento, la sesión de pantalla llegó por fin a la captura y murió
// con ese mensaje. El operador se fue a revisar la cuenta del servicio, que
// estaba bien. El código de Windows era **1008**:
//
//   1008 ERROR_NO_TOKEN           → la sesión EXISTE pero no hay nadie dentro.
//                                   Es la pantalla de inicio de sesión de un
//                                   servidor sin monitor. No es configuración.
//   1314 ERROR_PRIVILEGE_NOT_HELD → ESE sí es el caso del mensaje original.
//
// El mensaje afirmaba una causa en vez de leer el código, que es la tercera
// vez en este mismo incidente: primero «nobody answered» sobre un equipo donde
// no había nadie a quien preguntar, luego la política de aprobación, y ahora
// la cuenta del servicio. Cada uno mandó a buscar el fallo donde no estaba.
//
// Y no era sólo el texto: `screen_capture_failed` NO está en
// `TERMINAL_CAPTURE_CODES`, así que se trataba como un fallo transitorio y se
// reintentaba — el operador se quedaba en «Waiting for first frame…» para
// siempre. Mapearlo a `no_interactive_desktop`, que sí es terminal y ya tiene
// texto correcto en el portal, cierra la sesión y explica por qué.
//
// Se comprueba por escáner de fuentes porque el proyecto del PrivSvc no
// compila en este Mac: `grpc.tools` trae un `protoc` x86_64 y aquí es ARM.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

const SRC = path.resolve(
  __dirname,
  "../../privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SessionScreenCapture.cs"
);

const text = readFileSync(SRC, "utf8");

/**
 * Quita las líneas de comentario.
 *
 * ⚠️ Hace falta: el comentario que explica ESTE fallo cita `SE_TCB_NAME` y
 * `1008`, y la primera versión de la prueba encontró la explicación en vez del
 * código. Segunda vez en esta misma sesión que me pasa — un escáner de fuentes
 * tiene que mirar código, no prosa.
 */
function codeOnly(s: string): string {
  return s
    .split("\n")
    .filter((l) => {
      const x = l.trimStart();
      return !x.startsWith("//") && !x.startsWith("*") && !x.startsWith("/*");
    })
    .join("\n");
}

/** El bloque que atiende el fallo de WTSQueryUserToken, sin comentarios. */
function tokenFailureBlock(): string {
  const start = text.indexOf("if (!NativeMethods.WTSQueryUserToken(session");
  expect(start, "ya no existe la llamada a WTSQueryUserToken").toBeGreaterThan(-1);
  const end = text.indexOf("IntPtr primaryToken", start);
  return codeOnly(text.slice(start, end > start ? end : start + 4000));
}

describe("WTSQueryUserToken: el código de error decide el mensaje", () => {
  const block = tokenFailureBlock();

  it("distingue «no hay nadie» de «falta el privilegio»", () => {
    expect(block).toContain("ERROR_NO_TOKEN = 1008");
    expect(block).toContain("ERROR_PRIVILEGE_NOT_HELD = 1314");
  });

  it("⚠️ la culpa a LocalSystem SÓLO se dice con 1314", () => {
    const seTcb = block.indexOf("SE_TCB_NAME");
    expect(seTcb, "desapareció el mensaje de privilegio").toBeGreaterThan(-1);

    // El texto de SE_TCB_NAME tiene que caer DENTRO de la rama de 1314, o sea
    // después de esa comprobación y antes de la siguiente sentencia throw.
    const priv = block.indexOf("err == ERROR_PRIVILEGE_NOT_HELD");
    expect(priv, "el mensaje de privilegio ya no está condicionado").toBeGreaterThan(-1);
    expect(
      seTcb,
      "el mensaje de LocalSystem se emite fuera de la rama de 1314: vuelve a "
        + "culpar a la cuenta del servicio por cualquier error",
    ).toBeGreaterThan(priv);
  });

  it("1008 se reporta como «no hay nadie conectado», no como fallo genérico", () => {
    const noToken = block.indexOf("err == ERROR_NO_TOKEN");
    expect(noToken).toBeGreaterThan(-1);
    const branch = block.slice(noToken, block.indexOf("err == ERROR_PRIVILEGE_NOT_HELD"));
    expect(branch).toContain("NoInteractiveUserException");
    expect(branch.toLowerCase()).toContain("signed in");
    expect(
      branch,
      "1008 no puede mencionar SE_TCB_NAME: no es un problema de privilegios",
    ).not.toContain("SE_TCB_NAME");
  });

  /**
   * Lo que convierte el mensaje en comportamiento: `screen_capture_failed` se
   * trata como transitorio y se reintenta; `no_interactive_desktop` es
   * terminal. Sin este mapeo, el operador ve el spinner para siempre.
   */
  it("la excepción se traduce a un código TERMINAL", () => {
    expect(text).toContain("catch (NoInteractiveUserException");
    const handler = codeOnly(text.slice(text.indexOf("catch (NoInteractiveUserException")));
    expect(handler.slice(0, 600)).toContain('"no_interactive_desktop"');
  });

  /**
   * El agente tiene que seguir considerándolo terminal. Si alguien lo saca de
   * esa lista, el mapeo de arriba deja de servir para nada.
   */
  it("y el agente lo tiene en la lista de códigos terminales", () => {
    const agent = readFileSync(
      path.resolve(__dirname, "../../src/plugins/rcp/screen-session.ts"),
      "utf8"
    );
    const set = agent.slice(
      agent.indexOf("const TERMINAL_CAPTURE_CODES"),
      agent.indexOf("]", agent.indexOf("const TERMINAL_CAPTURE_CODES"))
    );
    expect(set).toContain('"no_interactive_desktop"');
  });
});

/**
 * 🔴 EN UN SERVIDOR, LA CONSOLA CASI NUNCA ES LA SESIÓN BUENA.
 *
 * Windows Server es multiusuario por definición: quien administra entra por
 * RDP, y RDP crea una sesión NUEVA. La consola se queda en la pantalla de
 * inicio de sesión, vacía. Mirando sólo `WTSGetActiveConsoleSessionId()`,
 * con un administrador trabajando DENTRO del servidor devolvíamos Win32 1008
 * — «no hay nadie» cuando sí lo había.
 */
describe("elección de sesión: consola, y si no, RDP", () => {
  /**
   * ⚠️ Perezoso a propósito, y con el `expect` DENTRO de cada prueba.
   *
   * La primera versión calculaba esto al recolectar el fichero, con un
   * `expect` suelto. Contra el código anterior el fichero reventaba antes de
   * registrar ninguna prueba y vitest decía «no tests» — un fallo que no
   * aparece en el recuento es un fallo que se pasa por alto en CI.
   */
  function picker(): string {
    const i = text.indexOf("private static uint? PickInteractiveSession()");
    if (i < 0) return "";
    return codeOnly(text.slice(i, text.indexOf("private static bool HasUserToken", i)));
  }

  it("ya no se usa la consola a secas", () => {
    const exchange = codeOnly(
      text.slice(text.indexOf("private static (string? line,"), text.indexOf("StartHelperLocked(session)"))
    );
    expect(
      exchange,
      "volver a coger la consola sin comprobar usuario reabre el 1008 en cada servidor con RDP",
    ).toContain("PickInteractiveSession()");
    expect(exchange).not.toContain("WTSGetActiveConsoleSessionId()");
  });

  it("prefiere la consola SÓLO si tiene usuario", () => {
    const p = picker();
    expect(p, "ya no existe el selector de sesión").not.toBe("");
    expect(p).toContain("WTSGetActiveConsoleSessionId()");
    expect(p).toContain("HasUserToken(console)");
  });

  it("y si no, enumera sesiones activas", () => {
    expect(picker()).toContain("WTSEnumerateSessions");
    expect(picker()).toContain("WTSActive");
  });

  it("⚠️ nunca la sesión 0 — es la de servicios, sin escritorio", () => {
    expect(picker()).toContain("info.SessionId <= 0");
  });

  it("⚠️ nunca una sesión DESCONECTADA: daría un fotograma congelado", () => {
    // Tienen token y tientan, pero su escritorio no se compone. Capturarlas
    // se diagnosticaría como «la captura está rota», que es peor que decir
    // que no hay nadie.
    expect(picker()).not.toContain("WTSDisconnected");
  });

  it("orden estable: dos peticiones seguidas ven lo mismo", () => {
    // Elegir «la más reciente» haría saltar al operador de escritorio a mitad
    // de una intervención cada vez que alguien se conecta.
    expect(picker()).toContain("actives.Sort()");
  });

  it("libera el buffer de WTS y el token que sondea", () => {
    expect(picker()).toContain("WTSFreeMemory");
    const has = codeOnly(
      text.slice(text.indexOf("private static bool HasUserToken"), text.indexOf("private static void StartHelperLocked"))
    );
    expect(has, "sondear sin cerrar el token filtra un handle por intento").toContain("CloseHandle");
  });
});
