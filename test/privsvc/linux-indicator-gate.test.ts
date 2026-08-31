// test/privsvc/linux-indicator-gate.test.ts
//
// La puerta que impide capturar pantalla mientras el aviso al usuario está
// caído (ADR-0012).
//
// La puerta de arranque —esperar a que el helper confirme la ventana— cubre
// "el aviso nunca salió". Esta cubre "salió y se cayó a los dos minutos", que
// deja la pantalla saliendo del equipo con el indicador apagado.
//
// Lo que se fija aquí es la ASIMETRÍA entre los tres estados. Confundir dos de
// ellos rompe la función en una de dos direcciones, y ambas son malas:
//   - tratar el cierre limpio como muerte ⇒ la siguiente sesión no arranca
//   - tratar la muerte como cierre limpio ⇒ vuelve el agujero que cierra esto

import { describe, it, expect } from "vitest";
import {
  indicatorGate,
  indicatorState,
  hideIndicator,
  nextStateOnChildExit,
  __resetIndicatorStateForTests
} from "../../privsvc/linux/src/remote-indicator";

describe("indicatorGate", () => {
  it("deja capturar con el indicador vivo", () => {
    expect(indicatorGate("live").allowed).toBe(true);
  });

  it("BLOQUEA cuando el indicador se murió solo", () => {
    const g = indicatorGate("died");
    expect(g.allowed).toBe(false);
    expect(g.code).toBe("indicator_gone");
  });

  it("deja pasar cuando nunca se mostró ninguno", () => {
    // Fallar cerrado aquí sería fallar cerrado en el sitio equivocado: la
    // puerta de verdad es showIndicator, que corre ANTES del primer fotograma.
    // Una sesión de pantalla siempre pasa por ella, así que bloquear también
    // "aún no se ha pedido ninguno" no añadiría garantía y sí rompería
    // cualquier captura que llegue por otro camino.
    expect(indicatorGate("never_shown").allowed).toBe(true);
  });

  it("da un código estable, no un booleano suelto", () => {
    // El agente lo tiene en TERMINAL_CAPTURE_CODES para parar la sesión en vez
    // de reintentar cada 200 ms, y la UI del operador lo usa para explicar qué
    // pasó. Si el código cambia, esos dos sitios dejan de reconocerlo en
    // silencio: la sesión se quedaría reintentando y el operador vería un
    // error genérico.
    expect(indicatorGate("died").code).toBe("indicator_gone");
    expect(indicatorGate("live").code).toBe("");
  });
});

describe("nextStateOnChildExit", () => {
  it("el indicador que estábamos mostrando muere ⇒ died", () => {
    expect(nextStateOnChildExit(true, "live")).toBe("died");
  });

  it("un indicador VIEJO que muere NO cierra la puerta", () => {
    // Este es el caso que hay que proteger. Al abrir una sesión nueva se
    // retira la anterior —o sea, se la mata— y ese exit llega después, ya con
    // el indicador nuevo en pantalla. Contarlo como muerte cerraría la puerta
    // sobre una sesión perfectamente anunciada, y el síntoma sería que la
    // SEGUNDA sesión de pantalla del día nunca funciona.
    expect(nextStateOnChildExit(false, "live")).toBe("live");
  });

  it("no resucita un estado ya muerto", () => {
    expect(nextStateOnChildExit(false, "died")).toBe("died");
  });

  it("un exit ajeno no altera el estado inicial", () => {
    expect(nextStateOnChildExit(false, "never_shown")).toBe("never_shown");
  });
});

describe("hideIndicator", () => {
  it("la retirada DELIBERADA vuelve a never_shown, no a died", () => {
    // Si el cierre limpio dejara "died", la puerta bloquearía la siguiente
    // sesión por el final ordenado de la anterior — la función se rompería
    // sola después del primer uso.
    __resetIndicatorStateForTests();
    hideIndicator();
    expect(indicatorState()).toBe("never_shown");
    expect(indicatorGate(indicatorState()).allowed).toBe(true);
  });
});
