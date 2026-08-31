// test/plugins/rcp-consent-text.test.ts
//
// El texto del aviso no es presentación: es la ÚNICA información con la que
// una persona decide si deja que otra vea —o use— su equipo. Si dice menos de
// lo que va a pasar, el "sí" que da no vale, porque consintió otra cosa. Y el
// registro de auditoría quedaría diciendo que aceptó algo que nunca le
// explicaron.
//
// Por eso va con tests: es la clase de fichero que alguien "limpia" un martes
// sin darse cuenta de lo que sostiene.

import { describe, it, expect } from "vitest";
import {
  consentLines,
  consentButtons,
  kindForCapability
} from "../../src/plugins/rcp/consent-text";

describe("consentLines", () => {
  it("la puerta de VER dice que verán la pantalla", () => {
    const t = consentLines({ kind: "view", operator: "Javier Pacheco" }).join(" ");
    expect(t).toContain("Javier Pacheco");
    expect(t).toContain("VIEW");
  });

  it("la puerta de CONTROLAR dice que podrán usar ratón y teclado", () => {
    // "Va a ver tu pantalla" y "va a poder usar tu equipo" no son la misma
    // frase. Enseñar la primera cuando ocurre la segunda es obtener el permiso
    // por una descripción falsa.
    const t = consentLines({ kind: "control", operator: "Javier Pacheco" }).join(" ");
    expect(t).toContain("CONTROL");
    expect(t).toContain("mouse and keyboard");
  });

  it("el aviso de control recuerda que YA le están viendo", () => {
    // Sin esto alguien puede conceder el control creyendo que le vuelven a
    // pedir el primer permiso.
    const t = consentLines({ kind: "control" }).join(" ");
    expect(t).toContain("already see your screen");
  });

  it("sin nombre dice 'A remote operator', no una cadena vacía", () => {
    const t = consentLines({ kind: "view", operator: "" }).join(" ");
    expect(t).toContain("A remote operator");
    expect(t).not.toContain("  is requesting");
  });

  it("un nombre con solo espacios cuenta como ausente", () => {
    const t = consentLines({ kind: "view", operator: "   " }).join(" ");
    expect(t).toContain("A remote operator");
  });

  it("SI HAY GRABACIÓN, el diálogo lo dice", () => {
    // No es redacción: grabar a alguien sin avisarle es ilegal en varias
    // jurisdicciones y, en todas, la vía rápida a perder un cliente.
    const t = consentLines({ kind: "view", recording: true }).join(" ");
    expect(t).toContain("recorded");
  });

  it("sin grabación NO menciona grabación", () => {
    // Decir que se graba cuando no se graba es mentir en la otra dirección, y
    // enseña a la gente que el aviso no describe la realidad.
    const t = consentLines({ kind: "view", recording: false }).join(" ");
    expect(t).not.toContain("recorded");
  });

  it("devuelve líneas ya partidas, no un párrafo", () => {
    // El helper de X11 no envuelve texto: Xlib sin métricas decentes corta
    // peor de lo que puede elegir quien redacta.
    const lines = consentLines({ kind: "control", recording: true });
    expect(lines.length).toBeGreaterThan(1);
    expect(lines.every((l) => !l.includes("\n"))).toBe(true);
  });
});

describe("consentButtons", () => {
  it("los botones dicen QUÉ se concede, no 'Sí'/'No'", () => {
    // Quien llega al diálogo a mitad de otra cosa lee el botón antes que el
    // texto.
    expect(consentButtons("view").allow).toBe("Allow viewing");
    expect(consentButtons("control").allow).toBe("Allow control");
    expect(consentButtons("view").deny).toBe("Don't allow");
  });
});

describe("kindForCapability", () => {
  it("rcp.screen.control es la puerta de control", () => {
    expect(kindForCapability("rcp.screen.control")).toBe("control");
  });

  it("todo lo demás es la puerta de ver", () => {
    // rcp.shell y rcp.file pasan por la primera puerta, en session-manager.
    expect(kindForCapability("rcp.screen")).toBe("view");
    expect(kindForCapability("rcp.shell")).toBe("view");
    expect(kindForCapability("rcp.file")).toBe("view");
  });
});
