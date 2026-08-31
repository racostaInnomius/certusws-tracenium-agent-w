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
  consentTitle,
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

describe("procedencia del aviso", () => {
  // Lo encontró el usuario probando el diálogo real: aceptó sin saber qué se
  // lo estaba pidiendo. Un aviso que sale de la nada diciendo que alguien
  // quiere controlar tu equipo, sin decir QUÉ software lo muestra, es
  // indistinguible de una estafa — y la reacción sana ante eso es pulsar
  // cualquier cosa para que desaparezca.

  it("el título nombra el producto", () => {
    expect(consentTitle("view")).toContain("Tracenium");
    expect(consentTitle("control")).toContain("Tracenium");
  });

  it("el CUERPO también lo nombra, no solo el título", () => {
    // El MessageBox de Windows manda el título a la barra de la ventana, donde
    // se lee menos. La línea que no se puede perder va en el cuerpo.
    expect(consentLines({ kind: "view" }).join(" ")).toContain("Tracenium");
    expect(consentLines({ kind: "control" }).join(" ")).toContain("Tracenium");
  });

  it("dice qué ES el producto, no solo su nombre", () => {
    // "Tracenium" a secas no ayuda a quien no sepa que lo tiene instalado.
    expect(consentLines({ kind: "view" }).join(" ")).toContain("IT management software");
  });

  it("la procedencia va DESPUÉS de qué se pide", () => {
    // Lo primero que la persona necesita saber es qué le están pidiendo; de
    // dónde viene el aviso es la verificación, no el titular.
    const lines = consentLines({ kind: "control" });
    const askIdx = lines.findIndex((l) => l.includes("CONTROL"));
    const srcIdx = lines.findIndex((l) => l.includes("Tracenium"));
    expect(askIdx).toBeLessThan(srcIdx);
  });
});
