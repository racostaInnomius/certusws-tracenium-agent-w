// test/plugins/rcp-recording-input.test.ts
//
// ⚠️ La grabación decía qué se VIO y no qué se HIZO — y arreglarlo tiene una
// forma obvia y equivocada.
//
// Registrar cada tecla convierte la grabación de una sesión de soporte en un
// registrador de pulsaciones. Con el acceso desatendido de la fase 4, donde el
// técnico teclea sus credenciales de dominio a través de la inyección de
// entrada, sería un fichero cifrado que guarda la contraseña de administrador
// del cliente durante los 90 días que dice la retención.
//
// Un expediente que no se puede enseñar sin filtrar un secreto no es un
// expediente: es un pasivo.
//
// La regla que fijan estas pruebas: se guarda lo que responde "qué hizo esta
// persona", no lo que responde "qué escribió".

import { describe, it, expect } from "vitest";
import {
  redactInputEvent,
  isPrintableKey,
  REDACTED_KEY
} from "../../src/plugins/rcp/recording-store";

describe("las teclas que escriben", () => {
  it("⚠️ NO se guardan literales", () => {
    // El caso que importa: alguien tecleando una contraseña.
    for (const code of ["KeyA", "KeyZ", "Digit4", "Numpad7", "Space", "Minus"]) {
      const out = redactInputEvent("keyDown", { code });
      expect(out.code).toBe(REDACTED_KEY);
      expect(out.code).not.toBe(code);
    }
  });

  it("pero se conserva QUE hubo escritura, y cuándo", () => {
    // Sin esto se perdería la capacidad de enseñar que alguien estuvo
    // tecleando, que es justo lo que este cambio existe para dar.
    const out = redactInputEvent("keyDown", { code: "KeyP" });
    expect(out.op).toBe("keyDown");
    expect(out.code).toBe(REDACTED_KEY);
  });
});

describe("las teclas de mando", () => {
  it("⚠️ van tal cual, porque son acciones y no contenido", () => {
    // Pulsar Enter o Ctrl+Alt+Supr es exactamente lo que hay que poder
    // auditar. Redactarlas dejaría la grabación sin decir nada.
    for (const code of [
      "Enter", "Tab", "Escape", "ArrowUp", "F5",
      "ControlLeft", "AltLeft", "ShiftLeft", "MetaLeft",
      "Delete", "Backspace", "Home", "End", "PageDown"
    ]) {
      expect(isPrintableKey(code)).toBe(false);
      expect(redactInputEvent("keyDown", { code }).code).toBe(code);
    }
  });
});

describe("el ratón", () => {
  it("va entero: sus coordenadas ya están en el vídeo", () => {
    expect(redactInputEvent("mouseDown", { x: 100, y: 200, button: 2 })).toEqual({
      op: "mouseDown", x: 100, y: 200, button: 2
    });
    expect(redactInputEvent("wheel", { x: 1, y: 2, deltaX: 0, deltaY: -120 })).toEqual({
      op: "wheel", x: 1, y: 2, deltaX: 0, deltaY: -120
    });
  });

  it("releaseAll no lleva nada más que su nombre", () => {
    expect(redactInputEvent("releaseAll", {})).toEqual({ op: "releaseAll" });
  });
});

describe("lo que NO puede colarse", () => {
  it("⚠️ un evento de tecla no arrastra campos inesperados", () => {
    // Si alguien añadiera un campo al mensaje del navegador —pongamos el
    // carácter ya resuelto— no puede acabar en la grabación por defecto. La
    // lista es cerrada a propósito.
    const out = redactInputEvent("keyDown", {
      code: "KeyA",
      key: "a",
      secreto: "hunter2"
    });
    expect(Object.keys(out).sort()).toEqual(["code", "op"]);
  });

  it("una tecla desconocida se trata como de mando, no como texto", () => {
    // Fallar hacia "es un mando" guarda un nombre de tecla que no significa
    // nada; fallar al revés perdería una acción auditable.
    expect(isPrintableKey("LaunchMail")).toBe(false);
    expect(redactInputEvent("keyDown", { code: "LaunchMail" }).code).toBe("LaunchMail");
  });
});
