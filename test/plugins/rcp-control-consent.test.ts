// test/plugins/rcp-control-consent.test.ts
//
// La segunda puerta de ADR-0012: CONTROLAR se consiente aparte de VER.
//
// Lo que se fija aquí es sobre todo qué NO hace la puerta. Es fácil escribir
// una que bloquee; lo difícil es que bloquee sin castigar el "no":
//
//   - denegar el control NO cierra la sesión de ver, que ya se consintió
//   - el aviso se lanza UNA vez, no con cada uno de los ~60 eventos/segundo
//     que manda un ratón moviéndose
//   - al operador se le dice una vez por qué sus clics no hacen nada, no cien

import { describe, it, expect } from "vitest";
import {
  controlGate,
  stateAfterDecision,
  shouldNotifyOperator
} from "../../src/plugins/rcp/control-consent";

describe("controlGate", () => {
  it("con la política apagada no se interpone", () => {
    // Sesiones desatendidas: servidores, quioscos. El ADR las mantiene a
    // propósito como decisión consciente del tenant, no como silencio.
    expect(controlGate(false, "not_asked").kind).toBe("forward");
    expect(controlGate(false, "denied").kind).toBe("forward");
  });

  it("el primer evento lanza el aviso y NO se reenvía", () => {
    // Reenviarlo "solo este" sería regalar el primer clic, que es justo el que
    // puede pulsar Aceptar en un diálogo del sistema.
    expect(controlGate(true, "not_asked").kind).toBe("ask");
  });

  it("mientras se espera respuesta, los eventos se tiran en silencio", () => {
    // Sin este estado, los ~60 eventos por segundo de un ratón lanzarían 60
    // avisos y la persona vería su pantalla sepultada en diálogos.
    expect(controlGate(true, "pending").kind).toBe("drop");
  });

  it("tras un sí, se reenvía", () => {
    expect(controlGate(true, "granted").kind).toBe("forward");
  });

  it("tras un no, se sigue tirando — y no se vuelve a preguntar", () => {
    // Volver a preguntar convertiría el "no" en un acoso: cada vez que el
    // operador moviera el ratón, otro diálogo.
    expect(controlGate(true, "denied").kind).toBe("drop");
  });
});

describe("stateAfterDecision", () => {
  it("aprobado ⇒ granted", () => {
    expect(stateAfterDecision("approved")).toBe("granted");
  });

  it("denegado ⇒ denied", () => {
    expect(stateAfterDecision("denied")).toBe("denied");
  });

  it("TIMEOUT cuenta como negativa, no como permiso", () => {
    // Si nadie contestó, la persona no está delante. Actuar en el equipo de
    // alguien que no está es exactamente lo que la puerta existe para
    // impedir: el silencio no es un sí.
    expect(stateAfterDecision("timeout")).toBe("denied");
  });
});

describe("shouldNotifyOperator", () => {
  it("avisa al pasar a denegado", () => {
    // El operador tiene que saber por qué sus clics no hacen nada. Sin esto
    // vería la pantalla moverse sola —la persona sigue trabajando— y sus
    // eventos sin efecto, que se diagnostica como "el control está roto".
    expect(shouldNotifyOperator("pending", "denied")).toBe(true);
  });

  it("no repite el aviso si ya estaba denegado", () => {
    expect(shouldNotifyOperator("denied", "denied")).toBe(false);
  });

  it("no avisa cuando se concede", () => {
    expect(shouldNotifyOperator("pending", "granted")).toBe(false);
  });
});
